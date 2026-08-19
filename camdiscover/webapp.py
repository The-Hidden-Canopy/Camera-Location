"""Flask web server + SSE API for Hidden Canopy Network Discovery"""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional

import ipaddress
import re
import urllib.request
import urllib.error

from flask import Flask, render_template, jsonify, request, Response, send_file

from .security import get_token_from_env, register_health, require_backend_token, set_token
from .api.routes import register_routes
from .api.change_routes import register_change_routes
from .persistence.db import get_database
from .services.discovery_service import DiscoveryService
from .orchestrator import DiscoveryOrchestrator
from .models import (
    DiscoveredDevice, SubnetZone, CapturePosition, CAPTURE_POSITIONS,
    DPI_STAGES, DPI_STAGE_LABELS, SENSOR_QUALITY,
)
from .network import NetworkInterface, get_interfaces, install_signal_handlers, cleanup_temp_ips
from .report import export_to_csv, export_to_json, export_to_html, generate_summary


def expand_subnet_range(entry: str) -> List[str]:
    """
    Expand a subnet range string into a list of CIDR strings.

    Supported formats:
      '172.16.1-22.0/24'  -> ['172.16.1.0/24', '172.16.2.0/24', ..., '172.16.22.0/24']
      '192.168.1.0/24'    -> ['192.168.1.0/24']
      '192.168.1.100'     -> ['192.168.1.0/24']  (bare IP -> /24)
      '10.0.0-3.0/24'     -> ['10.0.0.0/24', '10.0.1.0/24', '10.0.2.0/24', '10.0.3.0/24']
    """
    entry = entry.strip()
    if not entry:
        return []

    # Range pattern: A.B.X-Y.D/P  (third octet is a numeric range)
    m = re.match(r'^(\d+)\.(\d+)\.(\d+)-(\d+)\.(\d+)(?:/(\d+))?$', entry)
    if m:
        a, b, start, end, d, prefix = m.groups()
        prefix = int(prefix) if prefix else 24
        results = []
        for c in range(int(start), int(end) + 1):
            try:
                net = ipaddress.IPv4Network(f"{a}.{b}.{c}.{d}/{prefix}", strict=False)
                results.append(str(net))
            except Exception:
                pass
        return results

    # Plain CIDR
    if '/' in entry:
        try:
            return [str(ipaddress.IPv4Network(entry, strict=False))]
        except Exception:
            return []

    # Bare IP -> /24
    try:
        addr = ipaddress.IPv4Address(entry)
        parts = str(addr).split('.')
        return [f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"]
    except Exception:
        pass

    return []


def create_app(
    db_path: str | None = None,
    site_id: str | None = None,
    backend_token: str | None = None,
    backend_nonce: str | None = None,
) -> Flask:
    # create_app() is the universal main-thread chokepoint for every web
    # launch path (python -m camdiscover web, cli run_web, Electron). Install
    # the netsh-cleanup signal handlers here so the desktop app window closing
    # or Ctrl+C always tears down temporary IPs. Idempotent.
    try:
        install_signal_handlers()
    except Exception:
        pass

    app = Flask(
        __name__,
        template_folder="web/templates",
        static_folder="web/static",
    )

    db = get_database(db_path)

    # Backend security channel
    if backend_token and backend_nonce:
        set_token(backend_token, backend_nonce)

    register_health(app)

    @app.before_request
    def token_gate():
        """Require the backend launch token on /api routes when one is configured.

        /health is exempt so the launcher can verify the nonce before the token is
        distributed. Static files and the SPA index are also exempt.
        """
        path = request.path
        if path == "/health" or not path.startswith("/api"):
            return None
        expected = get_token_from_env()
        if not expected:
            return None
        supplied = request.headers.get("X-Backend-Token") or request.args.get("backend_token")
        if not supplied:
            return jsonify({"error": "unauthorized"}), 401
        import secrets
        if not secrets.compare_digest(supplied, expected):
            return jsonify({"error": "unauthorized"}), 401
        return None

    # Global state
    orchestrator = DiscoveryOrchestrator()
    devices_lock = threading.Lock()
    scan_state_lock = threading.Lock()
    scan_thread: threading.Thread | None = None
    scan_running = False
    scan_progress = {"phase": "idle", "current": 0, "total": 0, "message": "Ready"}
    event_subscribers: list = []

    def emit_event(event_type: str, data: dict):
        """Push an event to all SSE subscribers."""
        payload = json.dumps({"type": event_type, "data": data, "timestamp": datetime.now(timezone.utc).isoformat()})
        dead = []
        for i, queue in enumerate(event_subscribers):
            try:
                queue.put_nowait(payload)
            except Exception:
                dead.append(i)
        for i in reversed(dead):
            event_subscribers.pop(i)

    def on_progress(p):
        nonlocal scan_progress
        scan_progress = {"phase": p.phase, "current": p.current, "total": p.total, "message": p.message}
        emit_event("progress", scan_progress)

    def on_device(device: DiscoveredDevice):
        emit_event("device_found", device.to_dict())

    def on_device_updated(device: DiscoveredDevice):
        emit_event("device_updated", device.to_dict())

    def on_subnet_found(sniffed):
        emit_event("subnet_sniffed", {
            "subnet": sniffed.subnet,
            "first_seen_ip": sniffed.first_seen_ip,
            "source": sniffed.source,
        })

    orchestrator.on_progress = on_progress
    orchestrator.on_device_found = on_device
    orchestrator.on_device_updated = on_device_updated
    orchestrator.on_subnet_found = on_subnet_found

    # ─── Routes ───────────────────────────────────────────────────────

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/favicon.ico")
    def favicon():
        return Response(status=204)

    @app.route("/api/capabilities")
    def api_capabilities():
        """Return sensor-health status for every passive arm.

        Each arm reports its state so the UI can surface coverage gaps rather
        than silently showing absent evidence.  A missing arm is never hidden —
        the operator needs to know if IGMP capture is unavailable because that
        means multicast evidence cannot be collected from the current position.

        States: starting | active | waiting | port_conflict | permission_denied
                | failed | unsupported | unknown
        """
        dpi = orchestrator._dpi
        arms = dpi.get_capabilities() if dpi else {}

        # Annotate with overall assessment so the UI can show a single indicator
        degraded = [arm for arm, info in arms.items()
                    if info["state"] not in ("active", "waiting", "starting")]
        coverage = (
            "full"     if not degraded else
            "partial"  if len(degraded) < len(arms) // 2 else
            "degraded"
        )

        return jsonify({
            "coverage":        coverage,
            "degraded_arms":   degraded,
            "capture_position": orchestrator.capture_position.to_dict(),
            "interface": {
                "name":   orchestrator.selected_interface.name  if orchestrator.selected_interface else "",
                "ip":     orchestrator.selected_interface.ip    if orchestrator.selected_interface else "",
                "type":   orchestrator.selected_interface.iface_type if orchestrator.selected_interface else "",
            },
            "arms": arms,
        })

    @app.route("/api/interfaces")
    def api_interfaces():
        interfaces = get_interfaces()
        return jsonify([{
            "name": i.name,
            "ip": i.ip,
            "netmask": i.netmask,
            "mac": i.mac,
            "iface_type": i.iface_type,
            "gateway": i.gateway,
            "subnet": i.subnet,
        } for i in interfaces])

    @app.route("/api/scan", methods=["POST"])
    def api_scan():
        nonlocal scan_thread, scan_running
        with scan_state_lock:
            if scan_running:
                return jsonify({"error": "Scan already running"}), 409

            body = request.json or {}
            mode = body.get("mode", "listen")
            interface_name = body.get("interface", "")
            raw_subnets = body.get("subnets", None)
            # Default: always start fresh.  The frontend can pass "clear": false
            # to append results from a second scan onto an existing session instead.
            clear_devices = body.get("clear", True)

            # Expand subnet ranges (e.g. "172.16.1-22.0/24" -> 22 individual CIDRs)
            subnets = None
            if raw_subnets:
                raw_list = raw_subnets if isinstance(raw_subnets, list) else [raw_subnets]
                expanded: List[str] = []
                for entry in raw_list:
                    for part in str(entry).split(','):
                        expanded.extend(expand_subnet_range(part.strip()))
                subnets = expanded if expanded else None

            # Select interface — select_interface already sets selected_interface
            # internally; we call set_interface only to trigger capture-position
            # auto-detection, but ONLY if the operator hasn't manually overridden it.
            interfaces = orchestrator.select_interface(interface_name)
            if interface_name:
                match = next((i for i in interfaces if i.name == interface_name), None)
                if match:
                    orchestrator.set_interface(match)
            elif interfaces:
                best = next((i for i in interfaces if i.iface_type == "ethernet"), interfaces[0])
                orchestrator.set_interface(best)

            scan_running = True

            def run_scan():
                nonlocal scan_running, scan_thread
                try:
                    orchestrator.run(mode, subnets, clear=clear_devices)
                except Exception as e:
                    emit_event("error", {"message": str(e)})
                finally:
                    with scan_state_lock:
                        scan_running = False
                        scan_thread = None
                    emit_event("scan_complete", {"device_count": len(orchestrator.discovered_devices)})

            scan_thread = threading.Thread(target=run_scan, daemon=True)
            scan_thread.start()

        return jsonify({"status": "started", "mode": mode})

    @app.route("/api/scan/stop", methods=["POST"])
    def api_scan_stop():
        nonlocal scan_thread, scan_running
        orchestrator.stop()
        thread = scan_thread
        still_running = False
        if thread and thread.is_alive():
            thread.join(timeout=1.5)
            still_running = thread.is_alive()
        with scan_state_lock:
            if not still_running:
                scan_running = False
                scan_thread = None
        return jsonify({"status": "stopping" if still_running else "stopped", "running": still_running})

    @app.route("/api/devices/clear", methods=["POST"])
    def api_devices_clear():
        """Full session reset — wipes devices and all triage state.
        Preserves operator config (credentials, subnet zones, interface).
        Only available when no scan is running."""
        if scan_running:
            return jsonify({"error": "Cannot clear while scan is running"}), 409
        orchestrator._full_reset()
        emit_event("devices_cleared", {})
        return jsonify({"status": "cleared"})

    @app.route("/api/devices")
    def api_devices():
        with devices_lock:
            return jsonify([d.to_dict() for d in orchestrator.discovered_devices])

    @app.route("/api/triage")
    def api_triage():
        """Live triage-engine state: current task + the four priority queues.
        The UI polls this so the operator can see exactly what the single
        sequential probe worker is doing and what is queued next."""
        return jsonify(orchestrator.triage_state())

    @app.route("/api/triage/ingest", methods=["POST"])
    def api_triage_ingest():
        """Ingest out-of-band evidence for silent/orphaned devices:
        a switch MAC/port table, DHCP leases, LLDP/SNMP neighbor detail,
        DNS name exports, a router ARP dump, or an NVR channel list. Accepts JSON {kind,text} or a multipart file upload
        (form fields: kind, file). Everything becomes evidence — never a guess."""
        kind, text = "", ""
        if request.files.get("file"):
            kind = request.form.get("kind", "")
            try:
                text = request.files["file"].read().decode("utf-8", errors="replace")
            except Exception:
                text = ""
        else:
            body = request.json or {}
            kind = body.get("kind", "")
            text = body.get("text", "")
        if not kind or not text.strip():
            return jsonify({"error": "kind and text (or file) are required"}), 400
        summary = orchestrator.ingest_external_evidence(kind, text)
        emit_event("triage_ingested", {"kind": kind, **summary})
        return jsonify({"status": "ingested", "kind": kind, "summary": summary})

    @app.route("/api/status")
    def api_status():
        return jsonify({
            "scanning": scan_running,
            "progress": scan_progress,
            "device_count": len(orchestrator.discovered_devices),
            "interface": orchestrator.selected_interface.name if orchestrator.selected_interface else None,
        })

    @app.route("/api/export/csv")
    def api_export_csv():
        import io
        output = io.StringIO()
        # Keep the response in memory; export_to_csv expects a filesystem path.
        import csv
        writer = csv.writer(output)
        writer.writerow([
            "IP", "MAC", "Vendor", "Device Type", "Model", "Hostname", "Ports",
            "ONVIF", "RTSP", "Web URL", "RTSP URL", "ONVIF URL",
            "Subnet", "Subnet Zone", "Confidence", "DPI Score",
            "DPI Summary", "Discovery Methods", "Last Seen",
            "Device Class", "Classification Rationale", "Reset Risk", "Notes",
        ])
        for d in orchestrator.discovered_devices:
            writer.writerow([
                d.ip, d.mac, d.vendor, d.device_type, d.model, d.hostname,
                ";".join(str(p) for p in d.open_ports),
                d.onvif_status, d.rtsp_status,
                d.web_url, d.rtsp_url, d.onvif_url,
                d.subnet, d.subnet_zone, d.camera_confidence, d.dpi_score,
                d.dpi_summary,
                ";".join(d.discovery_methods),
                d.last_seen.isoformat(),
                d.device_class,
                d.classification_rationale,
                d.effective_reset_risk,
                d.notes,
            ])
        return Response(output.getvalue(), mimetype="text/csv", headers={
            "Content-Disposition": "attachment; filename=network-discovery.csv"
        })

    @app.route("/api/export/json")
    def api_export_json():
        import json as _json, io
        data = [d.to_dict() for d in orchestrator.discovered_devices]
        output = io.BytesIO(_json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8"))
        return send_file(output, as_attachment=True, download_name="network-discovery.json",
                         mimetype="application/json")

    @app.route("/api/export/html")
    def api_export_html():
        import tempfile, os
        with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False, encoding="utf-8") as f:
            tmp_path = f.name
        export_to_html(orchestrator.discovered_devices, tmp_path)
        return send_file(tmp_path, as_attachment=True, download_name="network-discovery.html",
                         mimetype="text/html")

    @app.route("/api/events")
    def api_events():
        """Server-Sent Events endpoint for live updates."""
        import queue
        q = queue.Queue(maxsize=100)
        event_subscribers.append(q)

        def generate():
            try:
                while True:
                    try:
                        data = q.get(timeout=30)
                        yield f"data: {data}\n\n"
                    except queue.Empty:
                        yield ": heartbeat\n\n"
            except GeneratorExit:
                if q in event_subscribers:
                    event_subscribers.remove(q)

        return Response(generate(), mimetype="text/event-stream", headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        })

    # ─── Subnet Zone APIs ─────────────────────────────────────────────

    @app.route("/api/subnets", methods=["GET"])
    def api_subnets_list():
        return jsonify([z.to_dict() for z in orchestrator.subnet_zones.values()])

    @app.route("/api/subnets", methods=["POST"])
    def api_subnets_add():
        body = request.json or {}
        zone = SubnetZone(
            subnet=body.get("subnet", ""),
            label=body.get("label", ""),
            gateway=body.get("gateway", ""),
            vlan_id=body.get("vlan_id", 0),
            method=body.get("method", "auto"),
            discoverable=body.get("discoverable", True),
            dhcp_mode=body.get("dhcp_mode", "unknown"),
            nvr_access=body.get("nvr_access", True),
            internet_blocked=body.get("internet_blocked", True),
            credential_profile=body.get("credential_profile", ""),
            notes=body.get("notes", ""),
        )
        if not zone.subnet:
            return jsonify({"error": "subnet is required"}), 400
        success = orchestrator.add_subnet_zone(zone)
        emit_event("subnet_added", zone.to_dict())
        return jsonify({"success": success, "zone": zone.to_dict()})

    @app.route("/api/subnets/<path:subnet>", methods=["DELETE"])
    def api_subnets_delete(subnet):
        success = orchestrator.remove_subnet_zone(subnet)
        emit_event("subnet_removed", {"subnet": subnet})
        return jsonify({"success": success})

    @app.route("/api/subnets/<path:subnet>/probe", methods=["POST"])
    def api_subnets_probe(subnet):
        result = orchestrator.probe_subnet_zone(subnet)
        return jsonify(result)

    @app.route("/api/routes")
    def api_routes():
        from .network import get_routes as _get_routes
        return jsonify(_get_routes())

    # ─── Capture Position APIs ────────────────────────────────────────

    @app.route("/api/capture-position", methods=["GET"])
    def api_capture_position_get():
        return jsonify(orchestrator.capture_position.to_dict())

    @app.route("/api/capture-position", methods=["POST"])
    def api_capture_position_set():
        body = request.json or {}
        position = body.get("position", "unknown")
        orchestrator.set_capture_position(position)
        emit_event("capture_position_changed", orchestrator.capture_position.to_dict())
        return jsonify(orchestrator.capture_position.to_dict())

    @app.route("/api/capture-positions")
    def api_capture_positions_list():
        return jsonify([{"id": k, "label": v} for k, v in CAPTURE_POSITIONS.items()])

    # ─── DPI APIs ─────────────────────────────────────────────────────

    @app.route("/api/dpi/stages")
    def api_dpi_stages():
        return jsonify([{"id": s, "label": DPI_STAGE_LABELS.get(s, s)} for s in DPI_STAGES])

    @app.route("/api/dpi/validate/<ip>")
    def api_dpi_validate(ip):
        if ip not in orchestrator.devices:
            return jsonify({"error": "Device not found"}), 404
        orchestrator._validate_dpi_stages(ip)
        device = orchestrator.devices[ip]
        return jsonify({
            "ip": ip,
            "dpi_stages": {k: v.to_dict() for k, v in device.dpi_stages.items()},
            "dpi_score": device.dpi_score,
            "dpi_summary": device.dpi_summary,
        })

    # ─── Subnet Watch ────────────────────────────────────────────────

    @app.route("/api/subnet-watch/start", methods=["POST"])
    def api_subnet_watch_start():
        interfaces = orchestrator.select_interface()
        if interfaces and not orchestrator.selected_interface:
            best = next((i for i in interfaces if i.iface_type == "ethernet"), interfaces[0])
            orchestrator.set_interface(best)
        orchestrator.start_subnet_watch()
        return jsonify({"status": "watching"})

    @app.route("/api/subnet-watch/stop", methods=["POST"])
    def api_subnet_watch_stop():
        orchestrator.stop_subnet_watch()
        return jsonify({"status": "stopped"})

    @app.route("/api/subnet-watch/status")
    def api_subnet_watch_status():
        return jsonify({
            "active": orchestrator._watch_active,
            "known_subnets": list(orchestrator._sniffer._known) if orchestrator._sniffer else [],
        })

    # ─── ONVIF Device Info ────────────────────────────────────────────

    @app.route("/api/devices/<ip>/onvif-info")
    def api_onvif_info(ip):
        device = orchestrator.devices.get(ip)
        username = request.args.get("user", "admin")
        password = request.args.get("pass", "")
        # If no stored URL, try each open HTTP port in preference order.
        # Port 8899 is a proprietary default; most cameras use 80 or 8080.
        onvif_url = (device.onvif_url if device else "") or ""
        if not onvif_url:
            open_ports = list(device.open_ports if device else [])
            for port in [p for p in (80, 8080, 8899, 443) if not open_ports or p in open_ports]:
                onvif_url = f"http://{ip}:{port}/onvif/device_service"
                break
            else:
                onvif_url = f"http://{ip}:80/onvif/device_service"
        from .discovery import query_onvif_device_audit
        audit = query_onvif_device_audit(ip, onvif_url, username, password)
        return jsonify({
            "manufacturer": audit.manufacturer,
            "model": audit.model,
            "firmware": audit.firmware,
            "serial": audit.serial,
            "hardware_id": audit.hardware_id,
            "stream_uris": audit.stream_uris,
            "snapshot_uris": audit.snapshot_uris,
            "scopes": audit.scopes,
            "services": audit.services,
            "capabilities": audit.capabilities,
            "media_profile_tokens": audit.media_profile_tokens,
            "service_urls": audit.service_urls,
            "reported_ipv4_addresses": audit.reported_ipv4_addresses,
            "default_gateways": audit.default_gateways,
            "dns_servers": audit.dns_servers,
            "ntp_servers": audit.ntp_servers,
            "system_datetime": audit.system_datetime,
            "user_count": audit.user_count,
            "supports_device": audit.supports_device,
            "supports_media": audit.supports_media,
            "supports_events": audit.supports_events,
            "supports_imaging": audit.supports_imaging,
            "supports_ptz": audit.supports_ptz,
            "supports_analytics": audit.supports_analytics,
            "checks": audit.checks,
            "error": audit.error,
        })

    # ─── Snapshot Proxy ───────────────────────────────────────────────

    @app.route("/api/devices/<ip>/snapshot")
    def api_snapshot(ip):
        """Proxy a JPEG snapshot from the camera, trying vendor-specific URLs."""
        import ssl as _ssl
        device = orchestrator.devices.get(ip)
        vendor = (device.vendor if device else "").lower()
        open_ports = list(device.open_ports if device else [])
        username = request.args.get("user", "admin")
        password = request.args.get("pass", "")

        # Build an SSL context that accepts self-signed camera certs.
        # Almost every camera uses a self-signed cert — strict verification
        # would reject all of them.
        _ssl_ctx = _ssl.create_default_context()
        _ssl_ctx.check_hostname = False
        _ssl_ctx.verify_mode = _ssl.CERT_NONE

        def _make_opener(url: str):
            mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
            # Always register credentials — even blank password — so the
            # auth handler can respond to a 401 Digest/Basic challenge.
            mgr.add_password(None, url, username, password)
            return urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=_ssl_ctx),
                urllib.request.HTTPDigestAuthHandler(mgr),
                urllib.request.HTTPBasicAuthHandler(mgr),
            )

        # Try every HTTP port the device has open, in preference order.
        # Fall back to 80 only if no port scan has run yet.
        http_ports = [p for p in (80, 8080, 443, 8443) if p in open_ports] or [80]

        for http_port in http_ports:
            scheme = "https" if http_port in (443, 8443) else "http"
            base = f"{scheme}://{ip}:{http_port}"

            candidate_paths = []
            if "hikvision" in vendor:
                candidate_paths = [
                    "/ISAPI/Streaming/channels/101/picture",
                    "/Streaming/channels/1/picture",
                    "/onvif-http/snapshot?Profile_1",
                ]
            elif "dahua" in vendor or "amcrest" in vendor:
                candidate_paths = [
                    "/cgi-bin/snapshot.cgi",
                    "/cgi-bin/snapshot.cgi?channel=1",
                    "/cgi-bin/mjpg/video.cgi?channel=0&subtype=1",
                ]
            elif "axis" in vendor:
                candidate_paths = ["/axis-cgi/jpg/image.cgi"]
            elif "reolink" in vendor:
                candidate_paths = ["/cgi-bin/api.cgi?cmd=Snap&channel=0&rs=abc"]
            elif "hanwha" in vendor or "wisenet" in vendor:
                candidate_paths = ["/cgi-bin/viewer/video.jpg"]
            elif "twenty20" in vendor or "petrocloud" in vendor:
                # Twenty20/PetroCloud — form-based login, no HTTP snapshot endpoint
                candidate_paths = []

            candidate_paths += [
                "/snapshot.jpg", "/snap.jpg", "/image.jpg",
                "/jpg/image.jpg", "/tmpfs/auto.jpg",
                "/cgi-bin/snapshot.cgi", "/onvif/snapshot",
            ]

            for path in candidate_paths:
                url = base + path
                try:
                    opener = _make_opener(url)
                    req = urllib.request.Request(
                        url,
                        headers={"User-Agent": "CamDiscover/1.0",
                                 "Accept": "image/jpeg,image/*,*/*"},
                    )
                    with opener.open(req, timeout=5) as resp:
                        ct = resp.headers.get_content_type() or ""
                        data = resp.read(2_000_000)
                        if data[:2] == b"\xff\xd8" or "image" in ct:
                            return Response(data, mimetype="image/jpeg", headers={
                                "X-Snapshot-URL": url,
                                "Cache-Control": "no-store",
                            })
                except Exception:
                    continue

        return jsonify({"error": "No snapshot available — try the Web UI link or check credentials"}), 404

    # ─── MJPEG Stream Proxy ───────────────────────────────────────────
    # Transcodes RTSP → MJPEG via FFmpeg so the browser can show a live feed.

    @app.route("/api/devices/<ip>/stream")
    def api_stream(ip):
        """Live MJPEG stream from a camera via FFmpeg RTSP transcoding."""
        import subprocess as _sp
        device  = orchestrator.devices.get(ip)
        user    = request.args.get("user", "admin")
        passwd  = request.args.get("pass", "")
        rtsp    = request.args.get("url", "")

        # Pick best RTSP URL: explicit > stored > guessed
        if not rtsp:
            rtsp = (device.rtsp_url if device else "") or ""
        if not rtsp:
            rtsp = f"rtsp://{ip}:554/"
        # Embed credentials into the URL — include username even if password is
        # blank (rtsp://admin:@ip/...) so cameras with no password still auth.
        # URL-encode both fields so special chars (@ / : in passwords) don't
        # corrupt the URL structure and cause FFmpeg to reject it.
        if user and "@" not in rtsp:
            from urllib.parse import quote as _urlq
            rtsp = rtsp.replace(
                "rtsp://",
                f"rtsp://{_urlq(user, safe='')}:{_urlq(passwd, safe='')}@",
                1,
            )

        cmd = [
            "ffmpeg", "-loglevel", "error",
            "-rtsp_transport", "tcp",
            "-i", rtsp,
            "-f", "mjpeg",
            "-q:v", "5",      # quality 1-31, lower = better
            "-r", "10",       # 10 fps
            "-vf", "scale=iw:ih",
            "pipe:1",
        ]

        def generate():
            proc = None   # must be initialised before try so finally can reference it
            try:
                proc = _sp.Popen(cmd, stdout=_sp.PIPE, stderr=_sp.DEVNULL)
                boundary = b"--frame\r\nContent-Type: image/jpeg\r\n\r\n"
                buf = b""
                while True:
                    chunk = proc.stdout.read(4096)
                    if not chunk:
                        break
                    buf += chunk
                    while True:
                        start = buf.find(b"\xff\xd8")
                        end   = buf.find(b"\xff\xd9", start + 2) if start != -1 else -1
                        if start == -1 or end == -1:
                            break
                        frame = buf[start:end + 2]
                        buf   = buf[end + 2:]
                        yield boundary + frame + b"\r\n"
            except GeneratorExit:
                pass
            finally:
                if proc is not None:
                    try:
                        proc.kill()
                    except Exception:
                        pass

        return Response(
            generate(),
            mimetype="multipart/x-mixed-replace; boundary=frame",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    # ─── Credential store (in-memory, per session) ────────────────────

    _creds: dict = {}   # ip -> {username, password}
    # Gap 7: _creds and orchestrator.credentials are kept in sync.
    # orchestrator.credentials is the live reference used by scan workers;
    # _creds is the local copy that survives across multiple scan starts.

    @app.route("/api/devices/<ip>/credentials", methods=["GET"])
    def api_creds_get(ip):
        c = _creds.get(ip, {})
        return jsonify({"username": c.get("username", "admin"),
                        "has_password": bool(c.get("password"))})

    @app.route("/api/devices/<ip>/credentials", methods=["POST"])
    def api_creds_set(ip):
        body = request.json or {}
        entry = {"username": body.get("username", "admin"),
                 "password": body.get("password", "")}
        _creds[ip] = entry
        # Gap 7: mirror into orchestrator so active probes (ONVIF, RTSP)
        # can use saved credentials without the user having to re-run a scan.
        orchestrator.credentials[ip] = entry
        return jsonify({"saved": True})

    # ─── Set IP ───────────────────────────────────────────────────────

    @app.route("/api/devices/<ip>/set-ip", methods=["POST"])
    def api_set_ip(ip):
        """Block legacy direct mutation outside the governed change-plan flow."""
        return jsonify({
            "error": "direct device mutation is disabled",
            "required_flow": "/api/change-plans",
            "detail": (
                "Use the governed change-plan workflow to propose, approve, ",
                "and execute network changes with durable scope and audit.",
            ),
        }), 410


    @app.route("/api/dpi/checklist")
    def api_dpi_checklist():
        """DPI checklist reference for the UI."""
        return jsonify([
            {"layer": "DHCP", "what": "Cameras requesting IPs, DHCP offers, lease renewals",
             "missing": "Static cameras, wrong VLAN, DHCP not reaching camera subnet",
             "filter": "bootp or udp.port == 67 or udp.port == 68"},
            {"layer": "ARP", "what": "Camera MACs asking for gateway/NVR/camera peers",
             "missing": "Devices online but not visible in app, duplicate IPs, wrong gateway",
             "filter": "arp"},
            {"layer": "ONVIF Discovery", "what": "WS-Discovery probes/responses for cameras",
             "missing": "App/NVR can't auto-discover cameras",
             "filter": "udp.port == 3702"},
            {"layer": "RTSP Video", "what": "NVR pulling video streams from cameras",
             "missing": "Camera added but no video, wrong credentials, blocked stream",
             "filter": "tcp.port == 554 or udp.port == 554"},
            {"layer": "HTTP/HTTPS Admin", "what": "Web login, config pages, ISAPI/API calls",
             "missing": "Camera reachable by ping but not configurable",
             "filter": "tcp.port == 80 or tcp.port == 443 or tcp.port == 8080"},
            {"layer": "Vendor SDK Ports", "what": "Hikvision/Dahua proprietary control channels",
             "missing": "App works only with vendor tool, not ONVIF",
             "filter": "tcp.port == 8000 or tcp.port == 37777 or tcp.port == 5000"},
            {"layer": "Time Sync", "what": "Cameras/NVR syncing to NTP",
             "missing": "Wrong timestamps, evidence unusable, recording mismatch",
             "filter": "udp.port == 123"},
            {"layer": "DNS", "what": "NVR/cloud lookup, DDNS, update checks",
             "missing": "Remote app fails, cloud/P2P fails, suspicious callouts",
             "filter": "udp.port == 53 or tcp.port == 53"},
            {"layer": "Cloud/P2P", "what": "Outbound connections from NVR/cameras",
             "missing": "Unknown vendor cloud dependency or unwanted egress",
             "filter": "ip.addr == <camera_ip> and !(ip.addr == <nvr_ip>)"},
            {"layer": "Storage/Export", "what": "NAS, SMB, FTP, email alerts",
             "missing": "Recordings not saving/exporting",
             "filter": "tcp.port == 445 or tcp.port == 21 or tcp.port == 25 or tcp.port == 587"},
            {"layer": "UPnP/Port Mapping", "what": "Router/NVR trying to open external ports",
             "missing": "Hidden exposure to internet",
             "filter": "udp.port == 1900"},
        ])

    # ─── Next Safe Action (Arm 8 — the explainer) ────────────────────

    @app.route("/api/devices/<ip>/next-action")
    def api_next_action(ip):
        """Return the single safest next operator action for this device."""
        action = orchestrator.next_safe_action(ip)
        device = orchestrator.devices.get(ip)
        val_entry = None
        with orchestrator._triage_lock:
            ve = orchestrator._camera_validation_q.get(ip)
            val_entry = ve.to_dict() if ve else None
        return jsonify({
            "ip":           ip,
            "action":       action,
            "confidence":   device.camera_confidence if device else 0,
            "device_class": device.device_class if device else "unknown",
            "warn_reset":   device.warn_reset if device else False,
            "validation":   val_entry,
        })

    # ─── Camera Validation Queue ──────────────────────────────────────

    @app.route("/api/camera-validation")
    def api_camera_validation():
        with orchestrator._triage_lock:
            items = [v.to_dict() for v in orchestrator._camera_validation_q.values()]
        # Enrich with device data
        for item in items:
            dev = orchestrator.devices.get(item["ip"])
            if dev:
                item["vendor"] = dev.vendor
                item["model"]  = dev.model
                item["confidence"] = dev.camera_confidence
        return jsonify(items)

    # ─── Gateway Mismatch Queue ───────────────────────────────────────

    @app.route("/api/gateway-mismatches")
    def api_gateway_mismatches():
        with orchestrator._triage_lock:
            items = [g.to_dict() for g in orchestrator._gateway_mismatch_q.values()]
        return jsonify(items)

    # ─── Multicast Groups ─────────────────────────────────────────────

    @app.route("/api/multicast-groups")
    def api_multicast_groups():
        with orchestrator._triage_lock:
            groups = [g.to_dict() for g in orchestrator._multicast_groups.values()]
        return jsonify(groups)

    # ─── Interface Profile ────────────────────────────────────────────

    @app.route("/api/interface-profile")
    def api_interface_profile():
        """Return current adapter state including DHCP / temp-IP warnings."""
        from .network import get_interfaces
        iface = orchestrator.selected_interface
        if not iface:
            return jsonify({"error": "No interface selected"}), 404

        # Detect temporary / manually-assigned IPs on the adapter
        try:
            import subprocess
            r = subprocess.run(
                ["netsh", "interface", "ipv4", "show", "addresses", iface.name],
                capture_output=True, text=True, timeout=5,
            )
            raw = r.stdout
        except Exception:
            raw = ""

        dhcp_enabled = "dhcp" in raw.lower() or "yes" in raw.lower()
        from .network import _TEMP_IPS
        temp_ips = [ip for (ifn, ip) in list(_TEMP_IPS) if ifn == iface.name]

        warnings = []
        if temp_ips:
            warnings.append(
                f"This adapter has {len(temp_ips)} temporary IP(s) added by the scanner: "
                + ", ".join(temp_ips) +
                ". Discovery results may reflect a service/repair configuration."
            )
        if not dhcp_enabled and iface.ip:
            warnings.append(
                "This adapter appears to be using a static/manual IP. "
                "Verify this is the correct network before trusting scan results."
            )

        cp = orchestrator.capture_position
        sq = SENSOR_QUALITY.get(cp.position, SENSOR_QUALITY.get("unknown"))
        return jsonify({
            "name":         iface.name,
            "ip":           iface.ip,
            "mac":          iface.mac,
            "iface_type":   iface.iface_type,
            "dhcp_enabled": dhcp_enabled,
            "temp_ips":     temp_ips,
            "warnings":     warnings,
            "sensor": {
                "position":  cp.position,
                "label":     CAPTURE_POSITIONS.get(cp.position, cp.position),
                "quality":   sq["label"],
                "colour":    sq["colour"],
                "note":      sq["note"],
                "can_see_unicast":    cp.can_see_unicast,
                "can_see_broadcast":  cp.can_see_broadcast,
                "can_see_multicast":  cp.can_see_multicast,
            },
        })

    # ─── Infrastructure warnings (device-class labels only) ──────────────

    @app.route("/api/seeds")
    def api_seeds():
        from .seeds import INFRASTRUCTURE_WARNINGS
        return jsonify({
            "infrastructure_warnings": INFRASTRUCTURE_WARNINGS,
        })

    # ─── APIPA Devices ────────────────────────────────────────────────

    @app.route("/api/apipa-devices")
    def api_apipa_devices():
        """Return all devices observed with a 169.254.x.x address."""
        from .seeds import is_apipa
        devices = [d.to_dict() for d in orchestrator.discovered_devices
                   if d.apipa_seen or is_apipa(d.ip)]
        return jsonify(devices)

    # ─── Lost / Mismatched Devices ────────────────────────────────────

    @app.route("/api/lost-devices")
    def api_lost_devices():
        """Consolidated view: mismatch + gateway-mismatch + orphan queues."""
        with orchestrator._triage_lock:
            mismatches = [m.to_dict() for m in orchestrator._mismatch_q.values()]
            gw_mismatches = [g.to_dict() for g in orchestrator._gateway_mismatch_q.values()]
            orphans = [o.to_dict() for o in orchestrator._orphan_q.values()]

        # Enrich mismatch entries with device data where available
        for item in mismatches + gw_mismatches:
            dev = orchestrator.devices.get(item.get("ip", ""))
            if dev:
                item["device_class"] = dev.device_class
                item["vendor"] = dev.vendor
                item["warn_reset"] = dev.warn_reset
                item["last_seen"] = dev.last_seen.isoformat()
                item["confidence"] = dev.camera_confidence
                item["open_ports"] = list(dev.open_ports)  # snapshot — triage thread mutates this list

        return jsonify({
            "mismatches":        mismatches,
            "gateway_mismatches": gw_mismatches,
            "orphans":           orphans,
            "total":             len(mismatches) + len(gw_mismatches) + len(orphans),
        })

    @app.route("/api/sites/current", methods=["GET", "POST"])
    def api_set_current_site():
        """Bind the active discovery session to a site."""
        if request.method == "GET":
            return jsonify({"site_id": discovery_svc._site_id})
        body = request.json or {}
        site_id = body.get("site_id")
        try:
            discovery_svc.set_site(site_id)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 404
        return jsonify({"site_id": discovery_svc._site_id})

    # Persist discovery events to durable asset/endpoint records.
    discovery_svc = DiscoveryService(orchestrator, db=db)
    if site_id:
        try:
            discovery_svc.set_site(site_id)
        except ValueError:
            pass

    app.config["CAMDISCOVER_DB"] = db
    app.config["CAMDISCOVER_DB_PATH"] = str(db.db_path)
    app.config["DISCOVERY_ORCHESTRATOR"] = orchestrator
    app.config["DISCOVERY_SERVICE"] = discovery_svc

    register_routes(app)
    register_change_routes(app)

    return app


# ─── IP Change Helpers ────────────────────────────────────────────────────

def _onvif_request(url: str, username: str, password: str, body_xml: str) -> str:
    """Send a SOAP request to an ONVIF endpoint using WS-Security PasswordDigest."""
    from .discovery import _ws_security_header
    security_header = _ws_security_header(username, password) if (username or password) else ""
    envelope = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
        ' xmlns:tds="http://www.onvif.org/ver10/device/wsdl"'
        ' xmlns:tt="http://www.onvif.org/ver10/schema">'
        f'{security_header}'
        f'<s:Body>{body_xml}</s:Body>'
        '</s:Envelope>'
    )
    data = envelope.encode("utf-8")
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/soap+xml; charset=utf-8", "User-Agent": "CamDiscover/1.0"},
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.read(65536).decode("utf-8", errors="replace")


def _set_ip_onvif(onvif_url: str, username: str, password: str,
                  new_ip: str, prefix_len: int, gateway: str) -> tuple:
    body = (
        '<tds:SetNetworkInterfaces>'
        '  <tds:InterfaceToken>eth0</tds:InterfaceToken>'
        '  <tds:NetworkInterface>'
        '    <tt:IPv4><tt:Enabled>true</tt:Enabled>'
        f'   <tt:Manual><tt:Address>{new_ip}</tt:Address>'
        f'   <tt:PrefixLength>{prefix_len}</tt:PrefixLength></tt:Manual>'
        '    <tt:DHCP>false</tt:DHCP>'
        '    </tt:IPv4>'
        '  </tds:NetworkInterface>'
        '</tds:SetNetworkInterfaces>'
    )
    resp = _onvif_request(onvif_url, username, password, body)
    if "SetNetworkInterfacesResponse" in resp or "RebootNeeded" in resp:
        return True, f"ONVIF accepted — camera may reboot and reappear at {new_ip}"
    if "fault" in resp.lower() or "Fault" in resp:
        import re
        reason = re.search(r"<[^>]*[Tt]ext[^>]*>([^<]+)<", resp)
        return False, f"ONVIF fault: {reason.group(1) if reason else resp[:200]}"
    return False, "ONVIF: unexpected response"


def _set_ip_hikvision(ip: str, username: str, password: str,
                      new_ip: str, netmask: str, gateway: str) -> tuple:
    xml = (
        f'<?xml version="1.0" encoding="UTF-8"?>'
        f'<NetworkInterface version="2.0">'
        f'<id>1</id>'
        f'<IPAddress><ipVersion>v4</ipVersion><addressingType>static</addressingType>'
        f'<ipAddress>{new_ip}</ipAddress><subnetMask>{netmask}</subnetMask>'
        f'<DefaultGateway><ipAddress>{gateway}</ipAddress></DefaultGateway>'
        f'</IPAddress></NetworkInterface>'
    )
    url = f"http://{ip}/ISAPI/System/Network/interfaces/1"
    mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    mgr.add_password(None, url, username, password)
    opener = urllib.request.build_opener(
        urllib.request.HTTPDigestAuthHandler(mgr),
        urllib.request.HTTPBasicAuthHandler(mgr),
    )
    req = urllib.request.Request(url, data=xml.encode(), method="PUT",
                                 headers={"Content-Type": "application/xml", "User-Agent": "CamDiscover/1.0"})
    with opener.open(req, timeout=5) as resp:
        body = resp.read(4096).decode("utf-8", errors="replace")
        if resp.status in (200, 201) or "OK" in body or "statusCode>200" in body:
            return True, f"Hikvision ISAPI accepted — camera will use {new_ip}"
        return False, f"Hikvision returned {resp.status}: {body[:200]}"


def _set_ip_dahua(ip: str, username: str, password: str,
                  new_ip: str, netmask: str, gateway: str) -> tuple:
    url = (
        f"http://{ip}/cgi-bin/configManager.cgi?action=setConfig"
        f"&Network.Interface[0].IPAddress={new_ip}"
        f"&Network.Interface[0].SubnetMask={netmask}"
        f"&Network.Interface[0].DefaultGateway={gateway}"
        f"&Network.Interface[0].DhcpEnable=false"
    )
    mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    mgr.add_password(None, url, username, password)
    opener = urllib.request.build_opener(
        urllib.request.HTTPDigestAuthHandler(mgr),
        urllib.request.HTTPBasicAuthHandler(mgr),
    )
    req = urllib.request.Request(url, headers={"User-Agent": "CamDiscover/1.0"})
    with opener.open(req, timeout=5) as resp:
        body = resp.read(4096).decode("utf-8", errors="replace")
        if "OK" in body or resp.status == 200:
            return True, f"Dahua CGI accepted — camera will use {new_ip}"
        return False, f"Dahua returned {resp.status}: {body[:200]}"
