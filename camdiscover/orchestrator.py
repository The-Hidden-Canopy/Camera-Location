"""Discovery orchestrator — coordinates all discovery modes including DPI validation"""

from __future__ import annotations

import datetime as _dt
import ipaddress
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse

from . import ALL_CAMERA_PORTS, CAMERA_SUBNETS, DISCOVERY_MODES
from .discovery import (
    OnvifDevice, SsdpDevice, RtspResult, MdnsDevice,
    send_onvif_probe, send_ssdp_search, send_mdns_probe,
    scan_ports, grab_http_banner, probe_rtsp, reverse_dns_name,
    PassiveListener, query_onvif_device_info,
    send_dahua_probe,
)
from .models import (
    DiscoveredDevice, Evidence, DPIStageResult, DPI_STAGES,
    SubnetZone, CapturePosition, CAPTURE_POSITIONS,
    ScopeCursor, MismatchEntry, CandidateSubnet, OrphanEntry,
    GatewayMismatch, MulticastGroup, CameraValidationEntry,
)
from .seeds import (
    INFRASTRUCTURE_WARNINGS, WARN_RESET_CLASSES,
    is_apipa, APIPA_WARNING, POE_STATES,
)
from .dpi import DPICollector
from .dpi.evidence import EVIDENCE_WEIGHTS, CAMERA_VENDOR_KEYWORDS
from .network import (
    NetworkInterface, get_interfaces, get_arp_table,
    ping_host, add_temp_ip, remove_temp_ip, ip_to_subnet,
    add_static_route, remove_static_route,
    add_secondary_ip, remove_secondary_ip, cleanup_temp_ips,
    test_tcp_port, probe_subnet_connectivity, get_routes,
    discover_local_subnets, SubnetSniffer, SniffedSubnet,
)
from .vendor import lookup_vendor, fingerprint_device, classify_device_type


@dataclass
class DiscoveryProgress:
    phase: str
    current: int
    total: int
    message: str


class DiscoveryOrchestrator:
    """Coordinates camera discovery across multiple modes and protocols."""

    def __init__(self):
        self.devices: Dict[str, DiscoveredDevice] = {}
        self.selected_interface: Optional[NetworkInterface] = None
        self._stopping = False
        self._passive_listener: Optional[PassiveListener] = None
        self.on_progress: Optional[Callable[[DiscoveryProgress], None]] = None
        self.on_device_found: Optional[Callable[[DiscoveredDevice], None]] = None
        self.on_device_updated: Optional[Callable[[DiscoveredDevice], None]] = None
        self.on_subnet_found: Optional[Callable[[SniffedSubnet], None]] = None

        # Subnet zone management
        self.subnet_zones: Dict[str, SubnetZone] = {}
        self.capture_position: CapturePosition = CapturePosition()

        # Subnet sniffer (Wireshark-inspired: detect from traffic, not config)
        self._sniffer: Optional[SubnetSniffer] = None
        self._watch_active = False

        # Passive DPI evidence collector — runs alongside every scan mode
        self._dpi: Optional[DPICollector] = None

        # Serialises netsh add/remove calls so Windows never gets two
        # interface-modification commands at the same time
        self._netsh_lock = threading.Lock()

        # Guards self.devices against the TOCTOU race between the triage
        # worker thread and the DPICollector background thread. Both call
        # _get_or_create; without a lock, both can pass the "ip not in dict"
        # check simultaneously and the second write silently overwrites the
        # first, dropping whatever evidence was already attached.
        self._devices_lock = threading.Lock()

        # ── Triage engine state ─────────────────────────────────────────
        # Passive listening runs continuously; ONE sequential probe worker
        # drains these queues in strict priority order. No fan-out.
        self._known_scopes: List[ScopeCursor] = []
        self._mismatch_q: Dict[str, MismatchEntry] = {}
        self._candidate_q: Dict[str, CandidateSubnet] = {}
        self._orphan_q: Dict[str, OrphanEntry] = {}
        # Gateway mismatch: devices whose traffic targets a gateway from a
        # different subnet (old static config, camera moved, split segment).
        self._gateway_mismatch_q: Dict[str, GatewayMismatch] = {}
        # Multicast groups observed — tracked, never scanned wholesale.
        self._multicast_groups: Dict[str, MulticastGroup] = {}
        # P5 Camera validation queue: alive devices queued for deep Arm-7
        # validation (ONVIF/RTSP/HTTP/NVR).  Only runs when P1-P4 are idle.
        self._camera_validation_q: Dict[str, CameraValidationEntry] = {}
        self._triage_lock = threading.Lock()
        # ip/cidr -> (failure_count, earliest_next_attempt_epoch)
        self._backoff: Dict[str, tuple] = {}
        self._triage_task = ""          # human-readable "current task" line
        self._triage_running = False
        # cidr -> temporary secondary IP added so an OFF-LINK known scope
        # (a promoted/manual foreign subnet) is actually reachable while it
        # is being walked. Exactly one at a time; removed when the scope
        # completes. cleanup_temp_ips() is the crash/stop safety net.
        self._scope_temp_ip: Dict[str, str] = {}

        # ── Rate limiting / concurrency guard ───────────────────────────────
        # Inter-host delay (seconds) between sequential probes so the scanner
        # never overwhelms the local machine or the target network.
        self._probe_delay: float = 0.05          # 50 ms default
        # Maximum hosts to probe in a single scan session (safety cap).
        self._probe_budget: int = 5000
        self._probes_consumed: int = 0
        # Minimum prefix length for auto-scanned subnets (/20 = 4094 hosts).
        # Anything larger is rejected unless explicitly provided by the operator.
        self._max_subnet_prefix: int = 20

        # ── Credential store (Gap 7) ────────────────────────────────────────
        # ip -> {username, password} — populated by webapp.py when the operator
        # saves credentials via the UI.  Used by ONVIF/RTSP probes so saved
        # passwords are actually tried, not just stored in a dead dict.
        self.credentials: Dict[str, dict] = {}

        # ── NVR channel cache ────────────────────────────────────────────────
        # nvr_ip -> frozenset of camera IPs returned by that NVR's channel API.
        # Populated lazily by _get_nvr_camera_ips(); cleared at the start of
        # every scan run so each run fetches fresh data at most once per NVR
        # instead of once per camera × NVR (O(cameras × nvrs × endpoints × 4s)).
        self._nvr_channel_cache: Dict[str, set] = {}

        # ── Secondary identity indexes ───────────────────────────────────────
        # These allow _get_or_create to find an existing device by MAC address
        # before falling back to IP lookup.  This prevents a device that moved
        # from one IP to another from appearing as two separate records.
        # Both maps are kept in sync whenever a device is added or its MAC set.
        self._devices_by_mac: Dict[str, str] = {}   # normalised MAC → device_id
        self._devices_by_id:  Dict[str, str] = {}   # device_id → current IP key

        # Auto-detect capture position from interface type
        self._capture_position_manual = False   # True once operator sets it explicitly
        self._auto_detect_capture_position()

    @property
    def discovered_devices(self) -> List[DiscoveredDevice]:
        return list(self.devices.values())

    def _emit_progress(self, phase: str, current: int, total: int, message: str):
        # A failing UI/SSE callback must NEVER abort discovery.
        if self.on_progress:
            try:
                self.on_progress(DiscoveryProgress(phase, current, total, message))
            except Exception:
                pass

    def _emit_device(self, device: DiscoveredDevice):
        if self.on_device_found:
            try:
                self.on_device_found(device)
            except Exception:
                pass

    def _emit_device_updated(self, device: DiscoveredDevice):
        if self.on_device_updated:
            try:
                self.on_device_updated(device)
            except Exception:
                pass

    @staticmethod
    def _normalise_mac(mac: str) -> str:
        """Canonical lowercase colon-separated MAC for index keys."""
        return mac.lower().replace("-", ":").strip() if mac else ""

    def _register_device(self, device: DiscoveredDevice):
        """Add or refresh both secondary indexes for a device."""
        self._devices_by_id[device.device_id] = device.ip
        if device.mac:
            nm = self._normalise_mac(device.mac)
            if nm:
                self._devices_by_mac[nm] = device.device_id

    def _get_or_create(self, ip: str, method: str = "",
                       mac: str = "") -> DiscoveredDevice:
        """Return an existing device for this IP (or MAC), creating one if needed.

        Identity resolution order:
          1. Same IP already in the dict → return it (fast path).
          2. MAC provided and known → IP may have changed; update current IP
             on the existing record and re-key it.
          3. Neither found → create a fresh device.

        This prevents a camera that moved from 192.168.88.34 to 10.32.57.118
        from appearing as two unrelated records simply because the IP changed.
        """
        new_device = None
        with self._devices_lock:
            # ── Fast path: IP already present ────────────────────────────
            if ip in self.devices:
                dev = self.devices[ip]
                if method and method not in dev.discovery_methods:
                    dev.discovery_methods.append(method)
                if mac:
                    nm = self._normalise_mac(mac)
                    if nm and not dev.mac:
                        dev.mac = mac
                        self._devices_by_mac[nm] = dev.device_id
                return dev

            # ── MAC lookup: device moved to a new IP ──────────────────────
            if mac:
                nm = self._normalise_mac(mac)
                dev_id = self._devices_by_mac.get(nm)
                if dev_id:
                    old_ip = self._devices_by_id.get(dev_id)
                    dev = self.devices.get(old_ip) if old_ip else None
                    if dev:
                        # Re-key under the new IP; record old IP in history
                        self.devices.pop(old_ip, None)
                        dev.record_ip(ip)
                        self.devices[ip] = dev
                        self._devices_by_id[dev_id] = ip
                        if method and method not in dev.discovery_methods:
                            dev.discovery_methods.append(method)
                        return dev

            # ── Create new device ─────────────────────────────────────────
            device = DiscoveredDevice(ip=ip)
            if method:
                device.discovery_methods.append(method)
            if mac:
                device.mac = mac
            self.devices[ip] = device
            self._register_device(device)
            new_device = device

        # Emit outside the lock to avoid re-entrant deadlocks.
        if new_device is not None:
            self._emit_device(new_device)
        return self.devices[ip]

    def select_interface(self, name: str = "") -> List[NetworkInterface]:
        interfaces = get_interfaces()
        usable = [i for i in interfaces if i.iface_type not in ("virtual", "loopback")]
        if not usable:
            usable = interfaces

        if name:
            match = next((i for i in usable if i.name == name), None)
            if match:
                self.selected_interface = match
        elif usable:
            self.selected_interface = usable[0]

        return usable

    def set_interface(self, iface: NetworkInterface):
        self.selected_interface = iface
        # Update capture position to match the selected adapter type so the
        # sensor-quality banner reflects what is actually in use.
        self._update_capture_for_iface(iface)

    def _update_capture_for_iface(self, iface: NetworkInterface):
        """Set capture position based on the interface's type.
        Skipped if the operator has manually overridden it via set_capture_position."""
        if self._capture_position_manual:
            return
        t = iface.iface_type
        if t == "wi-fi":
            self.capture_position = CapturePosition(
                position="wifi",
                can_see_unicast=False,
                can_see_broadcast=True,
                can_see_multicast=True,
                can_see_rtsp=False,
                notes="Wi-Fi — wired camera unicast traffic not visible",
            )
        elif t in ("ethernet", "unknown"):
            # "unknown" is almost always a wired adapter whose description
            # didn't match any of the wi-fi/virtual keywords.
            self.capture_position = CapturePosition(
                position="ethernet_same",
                can_see_unicast=True,
                can_see_broadcast=True,
                can_see_multicast=True,
                can_see_rtsp=True,
            )
        # virtual/loopback → leave position unchanged (user should pick manually)

    def stop(self):
        self._stopping = True
        if self._passive_listener:
            self._passive_listener.stop()
        if self._dpi:
            self._dpi.stop()
            self._dpi = None
        # Stopping a scan must immediately undo every netsh change so the
        # interface is left exactly as we found it.
        try:
            cleanup_temp_ips()
        except Exception:
            pass

    # ─── Full state reset ─────────────────────────────────────────────

    def _full_reset(self):
        """Wipe all discovered-device and triage state so the next scan starts
        completely clean.

        Deliberately preserved across resets (operator config, not scan results):
          • self.credentials          — saved camera passwords
          • self.subnet_zones         — zone/VLAN definitions
          • self.capture_position     — operator-chosen network position
          • self.selected_interface   — chosen NIC
        """
        with self._devices_lock:
            self.devices.clear()
            self._devices_by_mac.clear()
            self._devices_by_id.clear()

        with self._triage_lock:
            self._known_scopes.clear()
            self._mismatch_q.clear()
            self._candidate_q.clear()
            self._orphan_q.clear()
            self._gateway_mismatch_q.clear()
            self._multicast_groups.clear()
            self._camera_validation_q.clear()

        self._backoff.clear()
        self._nvr_channel_cache.clear()
        self._scope_temp_ip.clear()
        self._triage_running = False
        self._probes_consumed = 0

    # ─── Mode dispatch ────────────────────────────────────────────────

    def run(self, mode: str, subnets: List[str] = None, clear: bool = True) -> List[DiscoveredDevice]:
        """Every mode now runs through the single sequential triage engine.

        Passive listening (DPICollector) runs continuously and feeds the
        evidence-driven queues.  One probe worker drains them in strict
        priority order: known scope → mismatch → candidate subnet → orphan.

        `mode` only tunes depth/dwell, never parallelism:
          report      — export only, no probing
          listen      — P1+P2 only, longer passive dwell, no candidate scans
          dhcp-trap   — like listen, even longer passive dwell
          sweep       — full cascade incl. candidate promotion + scan
          fingerprint — full cascade then deep camera validation
          dpi         — full cascade then deep DPI validation

        `clear` (default True): wipe all state from the previous run so every
        scan starts clean.  Pass clear=False only when intentionally appending
        results from a second scan onto an existing session.
        """
        self._stopping = False
        if clear:
            self._full_reset()

        if mode == "report":
            return self.discovered_devices

        self._emit_progress("init", 0, 1, f"Starting {mode} triage...")
        self._start_dpi_collector()           # continuous passive listening
        try:
            self._run_triage(mode, subnets)
            if mode in ("fingerprint", "dpi") and not self._stopping:
                ips = list(self.devices.keys())
                if mode == "fingerprint":
                    self._emit_progress("fingerprint", 0, len(ips),
                                        f"Deep fingerprint on {len(ips)} device(s)...")
                    self._fingerprint_all_serial(ips, phase="fingerprint")
                else:
                    self._emit_progress("dpi", 0, len(ips),
                                        f"DPI validation on {len(ips)} device(s)...")
                    self._validate_dpi_all_serial(ips, phase="dpi")
        finally:
            self._stop_dpi_collector()
            # Done with this network — clear every temporary IP we added so
            # no stale on-link routes survive into the next scan/session.
            try:
                cleanup_temp_ips()
            except Exception:
                pass

        return self.discovered_devices

    # ══════════════════════════════════════════════════════════════════
    #  TRIAGE ENGINE — one sequential probe worker, evidence-fed queues
    # ══════════════════════════════════════════════════════════════════

    def triage_state(self) -> dict:
        """Snapshot of the engine for the UI (current task + all queues)."""
        with self._triage_lock:
            return {
                "running":            self._triage_running,
                "current_task":       self._triage_task,
                "known_scopes":       [s.to_dict() for s in self._known_scopes],
                "mismatch":           [m.to_dict() for m in self._mismatch_q.values()],
                "candidates":         [c.to_dict() for c in self._candidate_q.values()],
                "orphans":            [o.to_dict() for o in self._orphan_q.values()],
                "gateway_mismatch":   [g.to_dict() for g in self._gateway_mismatch_q.values()],
                "multicast_groups":   [g.to_dict() for g in self._multicast_groups.values()],
                "camera_validation":  [v.to_dict() for v in self._camera_validation_q.values()],
            }

    def _set_task(self, text: str, phase: str, cur: int = 0, total: int = 0):
        self._triage_task = text
        self._emit_progress(phase, cur, total, text)

    # ── Backoff ─────────────────────────────────────────────────────────
    # 1st fail → retry in 5 min, 2nd → 30 min, 3rd+ → stale (skip).

    def _backoff_due(self, key: str) -> bool:
        rec = self._backoff.get(key)
        return True if not rec else time.time() >= rec[1]

    def _backoff_fail(self, key: str) -> int:
        fails = self._backoff.get(key, (0, 0.0))[0] + 1
        delay = {1: 300, 2: 1800}.get(fails, 86400)   # 5m, 30m, then "stale"
        self._backoff[key] = (fails, time.time() + delay)
        return fails

    def _backoff_clear(self, key: str):
        self._backoff.pop(key, None)

    # ── Known-scope seeding ─────────────────────────────────────────────

    def _seed_known_scopes(self, custom_subnets: Optional[List[str]]):
        """Phase-1 source. Explicit subnets win; otherwise ONLY the subnets
        the interface actually has an IP on (never the routing table — its
        stale on-link routes caused spurious multi-subnet pulls)."""
        seeds: List[tuple] = []   # (cidr, source)
        if custom_subnets:
            seeds = [(s, "manual") for s in custom_subnets]
        elif self.selected_interface:
            for s in self.selected_interface.all_subnets():
                seeds.append((s, "interface"))
            if not seeds and self.selected_interface.ip:
                seeds.append((ip_to_subnet(self.selected_interface.ip), "interface"))
        with self._triage_lock:
            have = {s.cidr for s in self._known_scopes}
            for cidr, src in seeds:
                if cidr not in have:
                    self._known_scopes.append(ScopeCursor(cidr=cidr, source=src))
                    have.add(cidr)

    def _add_gateway_mismatch(self, ip: str, observed_gateway: str,
                              reason: str = "", evidence_type: str = "observed",
                              next_action: str = ""):
        """Record a device that appears to be configured for a wrong gateway."""
        with self._triage_lock:
            if ip in self._gateway_mismatch_q:
                gm = self._gateway_mismatch_q[ip]
                gm.last_seen = _dt.datetime.now()
                if observed_gateway and not gm.observed_target_gateway:
                    gm.observed_target_gateway = observed_gateway
                return
            iface_gw = ""
            if self.selected_interface and hasattr(self.selected_interface, "gateway"):
                iface_gw = self.selected_interface.gateway or ""
            gm = GatewayMismatch(
                ip=ip,
                observed_target_gateway=observed_gateway,
                current_gateway=iface_gw,
                suspected_old_subnet=ip_to_subnet(observed_gateway) if observed_gateway else "",
                reason=reason,
                evidence_type=evidence_type,
                next_action=next_action or "Verify device; validate suspected old subnet",
            )
            self._gateway_mismatch_q[ip] = gm
        # Also add to regular mismatch P2 queue for active verification
        self._add_mismatch(ip, f"Gateway mismatch: targeting {observed_gateway}",
                           priority=20)

    def _observe_multicast(self, group: str, source_ip: str = "",
                           protocol_hint: str = ""):
        """Record a multicast group observation — never triggers a scan."""
        with self._triage_lock:
            if group not in self._multicast_groups:
                self._multicast_groups[group] = MulticastGroup(
                    group=group, protocol_hint=protocol_hint)
            mg = self._multicast_groups[group]
            mg.last_seen = _dt.datetime.now()
            mg.packet_count += 1
            if source_ip and source_ip not in mg.sources:
                mg.sources.append(source_ip)
            if protocol_hint and not mg.protocol_hint:
                mg.protocol_hint = protocol_hint

    # ── P5: camera validation queue ─────────────────────────────────────

    # Camera-candidate port set: if any are open on an alive host, it's
    # worth queuing for deep ONVIF/RTSP validation.
    _CAMERA_PORTS = frozenset({80, 443, 554, 8080, 8443, 8554, 8899, 37777, 5000})

    # Classes that are never camera-validated (infrastructure / no stream).
    _NO_VALIDATE_CLASSES = frozenset({"bridge", "router", "switch", "server"})

    def _add_camera_validation(self, ip: str, reason: str = "",
                               priority: int = 50):
        """Queue a device for Arm-7 deep validation (P5 — runs when P1-P4 idle).

        Auto-skips devices whose class is infrastructure (bridge, router, etc.)
        and devices already in the queue.
        """
        dev = self.devices.get(ip)
        if dev and dev.device_class in self._NO_VALIDATE_CLASSES:
            return
        with self._triage_lock:
            if ip in self._camera_validation_q:
                return
            self._camera_validation_q[ip] = CameraValidationEntry(
                ip=ip, reason=reason, priority=priority)

    # ── Gap 1: NVR channel list query ───────────────────────────────────
    #
    # Query known NVRs (Hikvision ISAPI / Dahua HTTP CGI) for their camera
    # channel lists and return the set of IP addresses they report.  Used by
    # _tick_camera_validation to set entry.nvr_match.
    #
    # Hikvision ISAPI:  GET /ISAPI/ContentMgmt/InputProxy/channels
    # Dahua CGI:        GET /cgi-bin/devManager.cgi?action=getDeviceChannels
    #
    # Both endpoints return XML with camera IP addresses.  We extract all
    # dotted-quad strings and return the unique set.

    def _get_nvr_camera_ips(self, nvr_ip: str) -> set:
        """Return the set of camera IPs known to this NVR, or empty set.

        Results are cached for the lifetime of the current scan session so
        N cameras being validated in P5 do not each trigger a fresh HTTP
        round-trip to every NVR (was O(cameras × nvrs × 3 endpoints × 4 s)).
        """
        # ── Cache hit ────────────────────────────────────────────────────────
        if nvr_ip in self._nvr_channel_cache:
            return self._nvr_channel_cache[nvr_ip]

        # ── Cache miss — query the NVR ────────────────────────────────────────
        import base64, urllib.request as _req
        cred = self.credentials.get(nvr_ip, {})
        user = cred.get("username", "admin")
        pwd  = cred.get("password", "")
        auth = base64.b64encode(f"{user}:{pwd}".encode()).decode()

        endpoints = [
            f"http://{nvr_ip}/ISAPI/ContentMgmt/InputProxy/channels",
            f"http://{nvr_ip}/ISAPI/System/Video/inputs/channels",
            f"http://{nvr_ip}/cgi-bin/devManager.cgi?action=getDeviceChannels",
        ]
        import re as _re
        ip_re = _re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
        result: set = set()
        for url in endpoints:
            try:
                r = _req.Request(url,
                                 headers={"Authorization": f"Basic {auth}",
                                          "User-Agent": "CamDiscover/1.0"})
                with _req.urlopen(r, timeout=4.0) as resp:
                    body = resp.read(131072).decode("utf-8", errors="replace")
                ips = {m for m in ip_re.findall(body)
                       if not m.startswith(("0.", "127.", "255."))}
                if ips:
                    result = ips
                    break
            except Exception:
                continue

        # Store even an empty result so we don't retry an unreachable NVR
        # for every camera in the queue.
        self._nvr_channel_cache[nvr_ip] = result
        return result

    def _tick_camera_validation(self) -> bool:
        """Arm 7 — deep-validate one pending camera.  Only called when P1-P4
        are all idle so it never interrupts higher-priority work."""
        with self._triage_lock:
            entry = next(
                (e for e in sorted(self._camera_validation_q.values(),
                                   key=lambda x: x.priority)
                 if e.status == "pending"),
                None)
        if not entry:
            return False

        entry.status = "validating"
        entry.last_checked = _dt.datetime.now()
        ip = entry.ip
        dev = self.devices.get(ip)
        self._set_task(f"P5 camera validation — {ip}", "triage")

        try:
            # Port scan if not already done
            if dev and not dev.open_ports:
                self._scan_and_fingerprint(ip)
                dev = self.devices.get(ip)

            # ONVIF — imports already at module level
            if dev and (8899 in (dev.open_ports or []) or dev.onvif_url):
                try:
                    url = dev.onvif_url or f"http://{ip}:8899/onvif/device_service"
                    # Gap 7: use saved credentials if available
                    _cred = self.credentials.get(ip, {})
                    _user = _cred.get("username", "admin")
                    _pass = _cred.get("password", "")
                    info = query_onvif_device_info(ip, url, _user, _pass)
                    if not info.error:
                        entry.onvif_ok = True
                        if info.model and not dev.model:
                            dev.model = info.model
                        self._record_evidence(dev, "onvif_device_info",
                                              f"Model: {info.model}",
                                              "active_onvif_p5")
                except Exception:
                    pass

            # RTSP — probe 554 first, then 8554 if also open.
            # BUG FIX: was passing a URL string as the `port` arg and
            # checking result.success (non-existent attr) — both silently
            # swallowed by the except, so rtsp_ok was never set True.
            _rtsp_ports = [p for p in (554, 8554) if p in (dev.open_ports or [])] if dev else []
            if _rtsp_ports:
                try:
                    result = probe_rtsp(ip, _rtsp_ports[0])
                    if result and result.found:
                        entry.rtsp_ok = True
                        if result.described:
                            entry.stream_ok = True
                        detail = "RTSP DESCRIBE succeeded" if result.described else "RTSP port responded"
                        self._record_evidence(dev, "rtsp_describe_response",
                                              detail, "active_rtsp_p5")
                except Exception:
                    pass

            # HTTP banner — imports already at module level
            if dev and any(p in (dev.open_ports or []) for p in (80, 8080, 443)):
                try:
                    port = next(p for p in (80, 8080, 443) if p in (dev.open_ports or []))
                    banner = grab_http_banner(ip, port)
                    if banner:
                        entry.http_ok = True
                except Exception:
                    pass

            # Gap 1: nvr_match — check if this IP is in any known NVR's channel list
            if not entry.nvr_match:
                nvr_devices = [d for d in self.devices.values()
                               if d.device_class in ("nvr",)
                               or any(kw in (d.model or "").lower()
                                      for kw in ("nvr", "dvr", "recorder"))]
                for nvr_dev in nvr_devices:
                    try:
                        channel_ips = self._get_nvr_camera_ips(nvr_dev.ip)
                        if ip in channel_ips:
                            entry.nvr_match = True
                            self._record_evidence(dev, "nvr_channel_match",
                                                  f"Device listed in NVR {nvr_dev.ip} channel list",
                                                  "active_nvr_p5")
                            break
                    except Exception:
                        pass

            entry.status = "pass" if (entry.onvif_ok or entry.rtsp_ok or entry.http_ok
                                      or entry.nvr_match) else "fail"
        except Exception:
            entry.status = "fail"

        entry.attempts += 1
        if dev:
            # Gap 6: Mirror P5 results into device.validation dict so API
            # consumers (webapp, report, CLI) can read validation outcomes
            # without importing the CameraValidationEntry model.
            dev.validation["onvif"] = "pass" if entry.onvif_ok else "fail"
            dev.validation["rtsp"]  = "pass" if entry.rtsp_ok  else "fail"
            dev.validation["http"]  = "pass" if entry.http_ok  else "fail"
            dev.validation["nvr_match"] = "pass" if entry.nvr_match else "unknown"
            dev.validation["stream"] = "pass" if entry.stream_ok else "fail"
            dev.validation["p5_status"] = entry.status
            self._refresh_dpi_stages(dev)
            self._emit_device_updated(dev)
        return True

    # ── Next safe action (Arm 8 — the explainer) ────────────────────────

    def next_safe_action(self, ip: str) -> str:
        """Return a short, operator-readable statement of the single safest
        next check for this device given its current evidence state.

        This is Arm 8: the UI explainer.  Never suggests mass scanning or
        destructive actions — always the minimal, reversible next step.
        """
        dev = self.devices.get(ip)
        if not dev:
            # In a queue but not yet visited
            with self._triage_lock:
                if ip in self._gateway_mismatch_q:
                    gm = self._gateway_mismatch_q[ip]
                    return (f"Verify {ip} is reachable. "
                            f"It may still have a static gateway pointing at "
                            f"{gm.observed_target_gateway or 'an old subnet'}.")
                if ip in self._mismatch_q:
                    return f"Ping {ip} once. If alive, check its subnet config."
                if ip in self._orphan_q:
                    return f"Check switch/NVR for {ip}. May be powered but unreachable by IP."
            return f"No data yet for {ip}. Start with a single ping."

        conf = dev.camera_confidence
        cls  = dev.device_class or "unknown"

        # Infrastructure — never probe aggressively
        if dev.warn_reset:
            return (f"{ip} is classified as {cls}. "
                    f"Do not reset. Verify connectivity only — check both ends first.")

        if dev.apipa_seen:
            return (f"{ip} has an APIPA address (169.254.x.x). "
                    f"Check: DHCP server reachable? Correct VLAN? "
                    f"Device may need a static IP or DHCP fix.")

        if dev.suspected_old_gateway:
            return (f"{ip} may be configured to use {dev.suspected_old_gateway} "
                    f"as its gateway. Log into the camera and update its static "
                    f"IP settings to match the current subnet.")

        if dev.subnet_mismatch:
            return (f"{ip}: {dev.subnet_mismatch}. "
                    f"Verify device first; only expand to its subnet after confirmation.")

        if not dev.open_ports:
            return f"Port scan {ip} to confirm which services are active."

        if conf < 20:
            return (f"{ip} responded to ping with {len(dev.open_ports)} open port(s). "
                    f"Check MAC OUI and HTTP banner to classify it.")

        if conf < 50:
            if 554 in dev.open_ports and not dev.rtsp_url:
                return f"Probe RTSP on {ip}:554 — likely a camera stream endpoint."
            if not dev.onvif_url and any(p in dev.open_ports for p in (80, 8080, 8899)):
                return f"Try ONVIF discovery on {ip}. HTTP and/or ONVIF port are open."
            return (f"{ip} has moderate camera evidence ({conf}%). "
                    f"Try ONVIF or HTTP login to confirm.")

        if conf >= 50 and not dev.onvif_status == "found":
            return (f"{ip} looks strongly like a camera (confidence {conf}%). "
                    f"Run ONVIF GetDeviceInformation to confirm model and assign to NVR.")

        if conf >= 50 and dev.onvif_status == "found":
            if not dev.rtsp_url:
                return f"{ip} confirmed via ONVIF. Pull RTSP stream URI via GetStreamUri."
            return (f"{ip} is a confirmed camera. "
                    f"Verify it appears in the NVR channel list and is recording.")

        return f"Monitor {ip} — no specific action needed right now."

    # ── The scheduler loop ──────────────────────────────────────────────

    def _run_triage(self, mode: str, custom_subnets: Optional[List[str]]):
        self._triage_running = True

        # ── Reset scan-progress state without wiping the evidence ledger ──
        # When clear=False (the default for normal scan starts) _full_reset()
        # is not called, so completed scopes stay completed and mismatch entries
        # stay in terminal states from the prior run.  We reset scope completion
        # and stale mismatch statuses here so every scan re-walks the known
        # scope and re-checks previously unreachable devices — but we deliberately
        # do NOT touch self.devices or its evidence.  The ledger is durable.
        with self._triage_lock:
            for s in self._known_scopes:
                if s.completed:
                    s.completed    = False
                    s.next_host    = 1
                    s.started_at   = None
                    s.completed_at = None
            for m in self._mismatch_q.values():
                if m.status in ("dead_or_stale", "route_missing_retry_pending",
                                "alive_wrong_subnet"):
                    m.status   = "observed"
                    m.attempts = 0
        # Backoff state is intentionally preserved when clear=False so that
        # devices with 2 prior failures are not given a fresh 3-attempt budget
        # on every mode switch.  Only clear the ephemeral caches.
        self._nvr_channel_cache.clear()
        self._probes_consumed = 0

        self._seed_known_scopes(custom_subnets)

        # ONE bounded active discovery burst before the sequential walk.
        # The DPICollector listens passively and actively probes only SADP;
        # ONVIF/SSDP cameras need an active WS-Discovery / M-SEARCH. This is a
        # single multicast/broadcast burst from the interface IP(s) — NOT a
        # per-subnet fan-out — so it stays within the "one active task" rule.
        if not self._stopping:
            iface_ip = self.selected_interface.ip if self.selected_interface else ""
            burst_ips = [ip for ip in
                         (self.selected_interface.all_ips if self.selected_interface else [iface_ip])
                         if ip and not ip.startswith("169.254")] or ([iface_ip] if iface_ip else [])
            if burst_ips:
                self._set_task("Active discovery burst (ONVIF/SSDP/Dahua)...", "triage")
                try:
                    self._probe_all_protocols(burst_ips)
                except Exception:
                    pass

        allow_promote = mode in ("sweep", "fingerprint", "dpi")
        # Passive dwell: how long to keep cycling after active work drains so
        # late ONVIF/SADP/ARP announcements still get triaged.
        dwell = {"listen": 12, "dhcp-trap": 30}.get(mode, 6)
        idle_started: Optional[float] = None

        last_arp = 0.0
        consecutive_errors = 0
        try:
            while not self._stopping:
                # The worker MUST survive any single bad host/device/ARP-line
                # /callback. One exception used to abort the whole scan at a
                # random point ("inconsistent results, breaks halfway"). Now
                # each iteration is isolated: log, brief pause, keep going.
                try:
                    # ARP table refresh is a subprocess — throttle to every 4s
                    # so a 254-host walk doesn't spawn 254 `arp -a` calls.
                    now = time.time()
                    if now - last_arp >= 4.0:
                        last_arp = now
                        self._collect_arp_entries()

                    if self._tick_known_scope():
                        idle_started = None
                        consecutive_errors = 0
                        continue
                    if self._tick_mismatch():
                        idle_started = None
                        consecutive_errors = 0
                        continue
                    if allow_promote and self._tick_candidate():
                        idle_started = None
                        consecutive_errors = 0
                        continue
                    if self._tick_orphan():
                        idle_started = None
                        consecutive_errors = 0
                        continue

                    # P5: Deep camera validation — only when P1-P4 are idle.
                    # The octopus validates cameras one at a time with its
                    # most careful arm only after all anchor/mismatch/candidate
                    # work is done.
                    if self._tick_camera_validation():
                        idle_started = None
                        consecutive_errors = 0
                        continue

                    # Nothing active to do — keep passively listening for
                    # `dwell` seconds in case a device announces itself late.
                    now = time.time()
                    if idle_started is None:
                        idle_started = now
                        self._set_task(
                            "Idle — passively listening for new evidence...",
                            "triage")
                    if now - idle_started >= dwell:
                        break
                    time.sleep(1.0)
                    consecutive_errors = 0
                except Exception as e:
                    # Never fatal. Pause briefly so a persistently-throwing
                    # path can't tight-spin, and surface it without stopping.
                    consecutive_errors += 1
                    try:
                        self._set_task(
                            f"Recovered from error (continuing): "
                            f"{type(e).__name__}: {e}", "triage")
                    except Exception:
                        pass
                    # If something is wedged (200+ straight failures), end the
                    # scan cleanly rather than spin forever.
                    if consecutive_errors >= 200:
                        break
                    time.sleep(0.2)
        finally:
            self._triage_running = False
            # Make sure no scope's temporary IP is left behind if the loop
            # exited between add and the per-scope removal.
            try:
                cleanup_temp_ips()
            except Exception:
                pass
            self._scope_temp_ip.clear()
            self._set_task("Triage complete", "triage", 1, 1)

    # ── P1: known scope walk, ONE host at a time ────────────────────────

    def _consume_probe_budget(self, count: int = 1) -> bool:
        """Return True if the budget still allows `count` probes."""
        if self._probes_consumed + count > self._probe_budget:
            return False
        self._probes_consumed += count
        return True

    def _tick_known_scope(self) -> bool:
        with self._triage_lock:
            cursor = next((s for s in self._known_scopes if not s.completed), None)
        if not cursor:
            return False

        # ── Subnet-size guardrail ─────────────────────────────────────────
        # Reject auto-scanning subnets larger than the configured maximum
        # (/20 = 4094 hosts).  The operator can still add them manually.
        try:
            net = ipaddress.IPv4Network(cursor.cidr, strict=False)
            if net.prefixlen < self._max_subnet_prefix:
                self._set_task(
                    f"P1 SKIP {cursor.cidr}: too large for auto-scan "
                    f"(/{net.prefixlen} > /{self._max_subnet_prefix})", "triage")
                cursor.completed = True
                cursor.completed_at = _dt.datetime.now()
                return True
        except Exception:
            pass

        # ── Budget guard ──────────────────────────────────────────────────
        if not self._consume_probe_budget(1):
            self._set_task(
                f"P1 PAUSE {cursor.cidr}: probe budget exhausted "
                f"({self._probes_consumed}/{self._probe_budget})", "triage")
            cursor.completed = True
            cursor.completed_at = _dt.datetime.now()
            return True

        # ── Rate-limiting pause between hosts ─────────────────────────────
        if self._probe_delay > 0:
            time.sleep(self._probe_delay)

        # ── Arbitrary-CIDR scope walk ─────────────────────────────────────
        # Instead of hardcoding /24 and host octet 1..254, parse the real CIDR
        # and walk its host addresses sequentially.
        try:
            net = ipaddress.IPv4Network(cursor.cidr, strict=False)
            hosts = list(net.hosts())
        except Exception:
            # Fallback to legacy /24 behaviour if the CIDR is malformed
            net = None
            hosts = []

        if net and hosts:
            host_idx = cursor.next_host - 1
            if host_idx < 0 or host_idx >= len(hosts):
                cursor.completed = True
                cursor.completed_at = _dt.datetime.now()
                temp = self._scope_temp_ip.pop(cursor.cidr, None)
                if temp and self.selected_interface:
                    try:
                        remove_secondary_ip(self.selected_interface.name, temp)
                    except Exception:
                        pass
                return True
            ip = str(hosts[host_idx])
            cursor.next_host = host_idx + 2
            if cursor.next_host > len(hosts):
                cursor.completed = True
                cursor.completed_at = _dt.datetime.now()
                temp = self._scope_temp_ip.pop(cursor.cidr, None)
                if temp and self.selected_interface:
                    try:
                        remove_secondary_ip(self.selected_interface.name, temp)
                    except Exception:
                        pass
        else:
            base = ".".join(cursor.cidr.split(".")[:3])
            if cursor.started_at is None:
                cursor.started_at = _dt.datetime.now()
                iface_name = (self.selected_interface.name
                              if self.selected_interface else "")
                if (iface_name and cursor.cidr not in self._scope_temp_ip
                        and not self._has_local_ip_for_subnet(cursor.cidr)):
                    cand = f"{base}.200"
                    self._set_task(
                        f"P1 {cursor.cidr} is off-link — adding {cand}...",
                        "triage")
                    try:
                        if add_secondary_ip(iface_name, cand):
                            self._scope_temp_ip[cursor.cidr] = cand
                            time.sleep(0.5)
                    except Exception:
                        pass
            host = cursor.next_host
            ip = f"{base}.{host}"
            cursor.next_host = host + 1
            if cursor.next_host > 254:
                cursor.completed = True
                cursor.completed_at = _dt.datetime.now()
                temp = self._scope_temp_ip.pop(cursor.cidr, None)
                if temp and self.selected_interface:
                    try:
                        remove_secondary_ip(self.selected_interface.name, temp)
                    except Exception:
                        pass

        idx = next((i for i, s in enumerate(self._known_scopes)
                    if s.cidr == cursor.cidr), 0) + 1
        total_hosts = len(hosts) if hosts else 254
        cur_host = cursor.next_host - 1 if hosts else (cursor.next_host - 1)
        self._set_task(
            f"P1 known {cursor.cidr} — checking {ip} ({cur_host}/{total_hosts})",
            "triage", cur_host, total_hosts)

        # Budget: 1 ping (≤0.5s). Alive → basic fingerprint, then queue for P5.
        try:
            if ping_host(ip, 500):
                dev = self._get_or_create(ip, "Ping")
                if not dev.open_ports:
                    self._scan_and_fingerprint(ip)
                else:
                    dev.last_seen = _dt.datetime.now()
                    self._emit_device_updated(dev)
                # After basic fingerprint, promote to P5 for deep validation
                # if the device looks camera-capable.  Infrastructure classes
                # are excluded inside _add_camera_validation.
                dev = self.devices.get(ip)
                if dev and (
                    dev.camera_confidence >= 15
                    or bool(self._CAMERA_PORTS & set(dev.open_ports or []))
                ):
                    self._add_camera_validation(
                        ip,
                        reason=f"Alive in P1 scan of {cursor.cidr}, {dev.camera_confidence}% confidence",
                        priority=40,
                    )
        except Exception:
            pass
        return True

    # ── P2: mismatched IPs, ONE at a time ───────────────────────────────

    def _tick_mismatch(self) -> bool:
        with self._triage_lock:
            pend = [m for m in self._mismatch_q.values()
                    if m.status not in ("dead_or_stale", "alive_wrong_subnet")
                    and self._backoff_due(f"mm:{m.ip}")]
            pend.sort(key=lambda m: (m.priority, m.first_seen))
            entry = pend[0] if pend else None
        if not entry:
            return False

        # Budget + rate-limit
        if not self._consume_probe_budget(1):
            return False
        if self._probe_delay > 0:
            time.sleep(self._probe_delay)

        entry.attempts += 1
        entry.last_checked = _dt.datetime.now()
        self._set_task(
            f"P2 mismatch {entry.ip} — {entry.reason} (try {entry.attempts})",
            "triage")

        alive = False
        try:
            # Same-L2 ARP first (cheapest), then one ICMP, then one TCP port.
            if ping_host(entry.ip, 800):
                alive = True
            else:
                for p in (80, 554, 8899):
                    if self._stopping:
                        break
                    if test_tcp_port(entry.ip, p, 1.0):
                        alive = True
                        break
        except Exception:
            pass

        if alive:
            entry.status = "alive_wrong_subnet"
            self._backoff_clear(f"mm:{entry.ip}")
            dev = self._get_or_create(entry.ip, "Mismatch")
            try:
                self._scan_and_fingerprint(entry.ip)
            except Exception:
                pass
            if not dev.subnet_mismatch:
                dev.subnet_mismatch = entry.reason or "Alive on L2, wrong subnet"
            self._emit_device_updated(dev)

            # Gap 8: A reachable mismatch device confirms any gateway-mismatch
            # entry we already have for it.  Advance status "observed" → "confirmed"
            # so the operator knows the device is definitely alive and misconfigured.
            with self._triage_lock:
                gm = self._gateway_mismatch_q.get(entry.ip)
                if gm and gm.status == "observed":
                    gm.status = "confirmed"
                    gm.last_checked = _dt.datetime.now()

            # Queue for P5 deep validation — mismatch devices are often cameras
            # with old static configs and are high-value targets.
            self._add_camera_validation(
                entry.ip,
                reason=f"Alive mismatch device — {entry.reason}",
                priority=25,
            )
            # A reachable mismatch is hard evidence its subnet exists.
            if entry.suspected_cidr:
                self._add_candidate(entry.suspected_cidr, "mismatch_alive",
                                    confidence=70, observed_ip=entry.ip,
                                    gateway=entry.suspected_gateway)
        else:
            fails = self._backoff_fail(f"mm:{entry.ip}")
            # Use "route_missing_retry_pending" as a non-terminal retry state.
            # "alive_unreachable_by_route" was previously used here but was
            # excluded by the scheduler filter, giving the device only one real
            # attempt.  Now the scheduler retries until the backoff limit (3
            # failures) then marks the entry dead_or_stale.
            entry.status = ("dead_or_stale" if fails >= 3
                            else "route_missing_retry_pending")
        return True

    # ── P3: candidate subnet validation (NEVER a full scan) ─────────────

    def _tick_candidate(self) -> bool:
        with self._triage_lock:
            cand = next((c for c in self._candidate_q.values()
                         if not c.promoted
                         and c.status not in ("rejected", "monitor_only", "promoted")
                         and self._backoff_due(f"cs:{c.cidr}")), None)
        if not cand:
            return False

        # Budget + rate-limit (each target counts as one probe)
        targets = list(dict.fromkeys(cand.observed_ips))[:3]
        if cand.suspected_gateway and cand.suspected_gateway not in targets:
            targets.append(cand.suspected_gateway)
        if not self._consume_probe_budget(len(targets)):
            return False
        if self._probe_delay > 0:
            time.sleep(self._probe_delay)

        cand.attempts += 1
        cand.status = "validating"
        self._set_task(
            f"P3 validate {cand.cidr} — {len(targets)} evidence IP(s), no full scan",
            "triage")

        # An off-link candidate (SADP/NVR/DHCP-derived foreign subnet) is
        # unreachable by plain ping — we'd wrongly mark every foreign net as
        # Lost. Add ONE short-lived temporary secondary IP just for this
        # bounded validation (≤4 probes), then remove it. Sequential — only
        # the candidate being validated ever holds a temp IP.
        iface_name = (self.selected_interface.name
                      if self.selected_interface else "")
        val_temp = None
        if (iface_name and not self._has_local_ip_for_subnet(cand.cidr)):
            vbase = ".".join(cand.cidr.split(".")[:3])
            vcand = f"{vbase}.201"
            try:
                if add_secondary_ip(iface_name, vcand):
                    val_temp = vcand
                    time.sleep(0.5)
            except Exception:
                pass

        alive_any = False
        try:
            for t in targets:
                if self._stopping:
                    break
                try:
                    if ping_host(t, 800) or test_tcp_port(t, 80, 1.0) \
                            or test_tcp_port(t, 554, 1.0):
                        alive_any = True
                        dev = self._get_or_create(t, "Candidate")
                        try:
                            self._scan_and_fingerprint(t)
                        except Exception:
                            pass
                        break
                except Exception:
                    pass
        finally:
            # Drop the validation temp IP immediately. If the candidate is
            # promoted, _tick_known_scope re-adds a temp IP for the full walk.
            if val_temp and iface_name:
                try:
                    remove_secondary_ip(iface_name, val_temp)
                except Exception:
                    pass

        if alive_any:
            cand.status = "promoted"
            cand.promoted = True
            self._backoff_clear(f"cs:{cand.cidr}")
            # Promote: append AFTER current scopes so it scans sequentially,
            # never preempting the known network.
            with self._triage_lock:
                if cand.cidr not in {s.cidr for s in self._known_scopes}:
                    self._known_scopes.append(
                        ScopeCursor(cidr=cand.cidr, source="promoted"))
            self._set_task(f"Promoted {cand.cidr} → queued after current scope",
                           "triage")
        else:
            fails = self._backoff_fail(f"cs:{cand.cidr}")
            cand.status = "monitor_only" if fails >= 3 else "route_missing"
        return True

    # ── P4: orphan investigation (passive-first) ────────────────────────

    def _tick_orphan(self) -> bool:
        with self._triage_lock:
            orph = next((o for o in self._orphan_q.values()
                         if o.status not in ("resolved", "unreachable")
                         and o.ip and self._backoff_due(f"or:{o.ip}")), None)
        if not orph:
            return False

        # Budget + rate-limit
        if not self._consume_probe_budget(1):
            return False
        if self._probe_delay > 0:
            time.sleep(self._probe_delay)

        orph.last_checked = _dt.datetime.now()
        self._set_task(f"P4 orphan {orph.ip or orph.mac} — {orph.reason}", "triage")
        try:
            if ping_host(orph.ip, 800) or test_tcp_port(orph.ip, 80, 1.0):
                orph.status = "resolved"
                self._backoff_clear(f"or:{orph.ip}")
                self._get_or_create(orph.ip, "Orphan")
                try:
                    self._scan_and_fingerprint(orph.ip)
                except Exception:
                    pass
            else:
                if self._backoff_fail(f"or:{orph.ip}") >= 3:
                    orph.status = "unreachable"
        except Exception:
            pass
        return True

    # ── Evidence → queue classification ─────────────────────────────────

    def _add_candidate(self, cidr: str, source: str, confidence: int,
                       observed_ip: str = "", gateway: str = ""):
        with self._triage_lock:
            c = self._candidate_q.get(cidr)
            if not c:
                c = CandidateSubnet(cidr=cidr, source=source, confidence=confidence)
                self._candidate_q[cidr] = c
            c.last_seen = _dt.datetime.now()
            c.confidence = max(c.confidence, confidence)
            if observed_ip and observed_ip not in c.observed_ips:
                c.observed_ips.append(observed_ip)
            if gateway and not c.suspected_gateway:
                c.suspected_gateway = gateway

    def _add_mismatch(self, ip: str, reason: str, mac: str = "",
                      gateway: str = "", cidr: str = "", priority: int = 50):
        with self._triage_lock:
            m = self._mismatch_q.get(ip)
            if not m:
                m = MismatchEntry(ip=ip, reason=reason, mac=mac,
                                  suspected_gateway=gateway,
                                  suspected_cidr=cidr, priority=priority)
                self._mismatch_q[ip] = m
            m.last_seen = _dt.datetime.now()
            if mac and not m.mac:
                m.mac = mac
            if gateway and not m.suspected_gateway:
                m.suspected_gateway = gateway
            if cidr and not m.suspected_cidr:
                m.suspected_cidr = cidr

    def _add_orphan(self, ip: str, reason: str, mac: str = "", status: str = "passive_seen"):
        key = ip or mac
        if not key:
            return
        with self._triage_lock:
            o = self._orphan_q.get(key)
            if not o:
                o = OrphanEntry(ip=ip, mac=mac, reason=reason, status=status)
                self._orphan_q[key] = o
            o.last_seen = _dt.datetime.now()

    def _triage_ingest(self, ip: str, kind: str, detail: str, raw: str):
        """Classify a passive signal into the right queue. Evidence only —
        never invents subnets; a lone foreign IP is a LOW-confidence /24."""
        if not ip:
            return

        # Multicast groups — track, never scan
        if ip.startswith(("224.", "239.", "234.")):
            self._observe_multicast(ip, protocol_hint=kind)
            return

        # APIPA — isolated-segment orphan, not a scan target
        if is_apipa(ip):
            self._add_orphan(ip, APIPA_WARNING, status="passive_seen")
            dev = self._get_or_create(ip, "Passive-APIPA")
            dev.apipa_seen = True
            dev.poe_state = "link_up_no_dhcp"
            if not dev.notes:
                dev.notes = APIPA_WARNING
            return

        iface_ip = self.selected_interface.ip if self.selected_interface else ""
        iface_subnet = ip_to_subnet(iface_ip) if iface_ip else ""
        ip_subnet = ip_to_subnet(ip)
        foreign = bool(iface_subnet) and ip_subnet != iface_subnet

        # SADP/ONVIF reports carry the device's own IP/mask/gateway → HIGH
        # confidence candidate + a precise mismatch entry.
        rep_ip = rep_mask = rep_gw = ""
        for fld, pat in (("ip", r'IPv4Address[>=]\s*([0-9.]+)'),
                         ("mask", r'IPv4SubnetMask[>=]\s*([0-9.]+)'),
                         ("gw", r'IPv4Gateway[>=]\s*([0-9.]+)')):
            m = re.search(pat, raw or "")
            if m:
                if fld == "ip":   rep_ip = m.group(1)
                if fld == "mask": rep_mask = m.group(1)
                if fld == "gw":   rep_gw = m.group(1)

        if rep_ip and rep_mask:
            try:
                net = ipaddress.IPv4Network(f"{rep_ip}/{rep_mask}", strict=False)
                self._add_candidate(str(net), "sadp", confidence=85,
                                    observed_ip=rep_ip, gateway=rep_gw)
                self._add_mismatch(rep_ip,
                                   f"SADP reports {rep_ip}/{rep_mask} gw {rep_gw}",
                                   gateway=rep_gw, cidr=str(net), priority=20)
                # Gateway mismatch: reported gateway doesn't belong to reported subnet
                if rep_gw:
                    gw_subnet = ip_to_subnet(rep_gw)
                    if gw_subnet != str(net).split("/")[0] + "/24" and gw_subnet != str(net):
                        self._add_gateway_mismatch(
                            rep_ip, rep_gw,
                            reason=f"SADP: device reports gateway {rep_gw} outside its own subnet {net}",
                            evidence_type="sadp",
                            next_action=f"Verify device at {rep_ip}; check static config",
                        )
            except Exception:
                pass

        if kind == "subnet_mismatch_visible":
            self._add_mismatch(ip, detail or "Reported IP differs from sender",
                               priority=20)
            self._add_candidate(ip_subnet, "observed_ip", confidence=25,
                                observed_ip=ip)
            return

        if foreign:
            # Seen on the wire but outside our scope: mismatch + low-conf /24.
            self._add_mismatch(ip, f"{kind} from foreign subnet {ip_subnet}",
                               priority=40)
            self._add_candidate(ip_subnet, "observed_ip", confidence=25,
                                observed_ip=ip)
            # Passive-only camera-ish signal with no active reach yet → orphan.
            if kind in ("mdns_camera_service", "ssdp_camera_service",
                        "onvif_probe_match_generic"):
                self._add_orphan(ip, f"Passive {kind}, foreign subnet")

    # ── External evidence ingestion (silent / orphaned devices) ─────────
    #
    # Truly silent devices (powered, cabled, but not announcing) cannot be
    # seen passively or by probing.  The only way to know they exist is an
    # out-of-band source the operator pastes in: a switch MAC/port table, a
    # DHCP lease list, a router ARP dump, or an NVR channel list.  Each line
    # becomes evidence → an orphan / mismatch / candidate, never a guess.

    _MAC_RE = re.compile(
        r'(?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}'      # aa:bb:.. / aa-bb-..
        r'|(?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}')        # Cisco aabb.ccdd.eeff
    _IPV4_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    _HOST_TOKEN_RE = re.compile(r'\b([A-Za-z0-9][A-Za-z0-9._-]{2,})\b')
    _PORT_RE = re.compile(
        r'\b(?:Gi|Te|Fa|Eth|Po|Twe|Fo|Hu|xe|ge)\S*\d|\bport\s*\d+\b',
        re.IGNORECASE)

    @staticmethod
    def _norm_mac(raw: str) -> str:
        h = re.sub(r'[^0-9a-fA-F]', '', raw).lower()
        if len(h) != 12:
            return ""
        return ":".join(h[i:i + 2] for i in range(0, 12, 2))

    def _mac_to_known_ip(self, mac: str) -> str:
        """Correlate a MAC against already-known devices so a switch-table
        MAC with no IP can inherit one we learned elsewhere."""
        if not mac:
            return ""
        for d in self.devices.values():
            if d.mac and d.mac.lower() == mac:
                return d.ip
        return ""

    def _extract_hostname_from_line(self, line: str, ip: str = "", mac: str = "") -> str:
        """Best-effort hostname extractor for pasted lease/table lines."""
        if not line:
            return ""

        explicit_patterns = [
            r'hostname\s*[:=]\s*([A-Za-z0-9._-]+)',
            r'host\s*[:=]\s*([A-Za-z0-9._-]+)',
            r'name\s*[:=]\s*([A-Za-z0-9._-]+)',
            r'system\s+name\s*[:=]?\s*([A-Za-z0-9._-]+)',
            r'client-id\s*[:=]\s*([A-Za-z0-9._-]+)',
            r'sysname\s*[:=]\s*([A-Za-z0-9._-]+)',
            r'ptr\s*[:=]\s*([A-Za-z0-9._-]+)',
        ]
        for pattern in explicit_patterns:
            m = re.search(pattern, line, re.IGNORECASE)
            if m:
                token = m.group(1).strip().strip(",;")
                if token:
                    return token.split(".", 1)[0]

        skip = {
            "dhcp", "lease", "dynamic", "static", "active", "expired", "ethernet",
            "switch", "router", "camera", "device", "unknown", "port", "vlan",
            "arp", "table", "channel", "enabled", "disabled", "online", "offline",
            "snmp", "sysdescr", "sysname", "dns", "ptr",
        }
        for match in self._HOST_TOKEN_RE.finditer(line):
            token = match.group(1).strip().strip(",;")
            token_l = token.lower()
            if token_l in skip:
                continue
            if ip and token == ip:
                continue
            if mac and token_l == mac.lower():
                continue
            if self._IPV4_RE.fullmatch(token) or token.isdigit():
                continue
            if "." in token:
                suffix = token.rsplit(".", 1)[-1].lower()
                if suffix in {"local", "lan", "corp", "home", "arpa"}:
                    token = token.split(".", 1)[0]
            if len(token) >= 3:
                return token
        return ""

    def _apply_external_identity(self, device: DiscoveredDevice, kind: str,
                                 line: str = "", mac: str = "", hostname: str = ""):
        """Fold pasted evidence into device identity without active probing."""
        if mac and not device.mac:
            device.mac = mac
            if device.vendor == "Unknown":
                device.vendor = lookup_vendor(mac)
        if hostname and not device.hostname:
            device.hostname = hostname
        lower = (line or "").lower()
        if kind == "lldp" and "LLDP" not in device.discovery_methods:
            device.discovery_methods.append("LLDP")
        if kind == "snmp" and "SNMP" not in device.discovery_methods:
            device.discovery_methods.append("SNMP")
        if kind == "dns" and "DNS" not in device.discovery_methods:
            device.discovery_methods.append("DNS")
        if kind == "snmp":
            self._record_evidence(device, "snmp_sysname_seen",
                                  "SNMP identity text supplied",
                                  "external_snmp", raw=(line or "")[:200])
            if any(token in lower for token in ("printer", "laserjet", "xerox", "brother", "canon", "epson")):
                self._record_evidence(device, "snmp_printer_hint",
                                      "SNMP text suggests a printer/copier",
                                      "external_snmp", raw=(line or "")[:200])
            if any(token in lower for token in ("switch", "router", "gateway", "firewall", "access point", "controller", "ubiquiti", "cisco", "aruba", "juniper", "fortinet", "mikrotik")):
                self._record_evidence(device, "snmp_infra_hint",
                                      "SNMP text suggests infrastructure gear",
                                      "external_snmp", raw=(line or "")[:200])
        if kind == "dns" and hostname:
            self._record_evidence(device, "dns_name_seen",
                                  f"DNS name observed: {hostname}",
                                  "external_dns", raw=(line or "")[:200])
        self._refresh_device_type(device)
        device.last_seen = _dt.datetime.now()

    def ingest_external_evidence(self, kind: str, text: str) -> dict:
        """Parse pasted/uploaded out-of-band data and feed the triage queues.

        kind: 'switch_mac' | 'dhcp' | 'dhcp_lease' | 'arp' | 'nvr' | 'lldp' | 'snmp' | 'dns'
        Returns a summary the UI can show.
        """
        kind = (kind or "").strip().lower()
        if kind == "dhcp_lease":
            kind = "dhcp"
        if kind == "lldp_neighbor":
            kind = "lldp"
        lines = [ln for ln in (text or "").splitlines() if ln.strip()]
        iface_ip = self.selected_interface.ip if self.selected_interface else ""
        iface_subnet = ip_to_subnet(iface_ip) if iface_ip else ""
        added = {"orphans": 0, "mismatch": 0, "candidates": 0, "devices": 0, "lines": len(lines)}

        ev_kind = {
            "switch_mac": "switch_mac_seen",
            "dhcp":       "dhcp_lease_seen",
            "arp":        "router_arp_seen",
            "nvr":        "nvr_channel_listed",
            "lldp":       "lldp_neighbor",
            "snmp":       "snmp_sysname_seen",
            "dns":        "dns_name_seen",
        }.get(kind, "external_seen")
        ev_weight = {"nvr_channel_listed": 30}.get(ev_kind, 5)
        orphan_status = {
            "switch_mac": "switch_seen",
            "dhcp":       "dhcp_seen",
            "arp":        "passive_seen",
            "nvr":        "nvr_seen",
            "lldp":       "switch_seen",
            "snmp":       "needs_manual_check",
            "dns":        "needs_manual_check",
        }.get(kind, "needs_manual_check")

        for ln in lines:
            macs = [self._norm_mac(m) for m in self._MAC_RE.findall(ln)]
            macs = [m for m in macs if m]
            ips = [ip for ip in self._IPV4_RE.findall(ln)
                   if all(0 <= int(o) <= 255 for o in ip.split("."))]
            mac = macs[0] if macs else ""
            ip = ips[0] if ips else ""
            hostname = self._extract_hostname_from_line(ln, ip=ip, mac=mac)
            pm = self._PORT_RE.search(ln)
            port = pm.group(0) if pm else ""

            if not ip and mac:
                ip = self._mac_to_known_ip(mac)

            reason = f"{kind} table"
            if port:
                reason += f" port {port}"
            if mac and not ip:
                reason += f" MAC {mac} (no IP — silent)"

            if ip:
                ip_subnet = ip_to_subnet(ip)
                foreign = bool(iface_subnet) and ip_subnet != iface_subnet
                dev = self._get_or_create(ip, ev_kind)
                self._apply_external_identity(dev, kind, line=ln, mac=mac, hostname=hostname)
                before = len(dev.evidence)
                self._record_evidence(dev, ev_kind,
                                      f"Listed in {kind} source: {ln.strip()[:120]}",
                                      f"external_{kind}", raw=ln.strip()[:200],
                                      weight=ev_weight)
                if len(dev.evidence) > before:
                    added["devices"] += 1
                if foreign:
                    self._add_mismatch(ip, f"{reason} (subnet {ip_subnet})",
                                       mac=mac, priority=30)
                    self._add_candidate(ip_subnet, kind, confidence=40,
                                        observed_ip=ip)
                    added["mismatch"] += 1
                    added["candidates"] += 1
                # NVR-listed but we can't reach it → real orphaned camera.
                if kind == "nvr":
                    self._add_orphan(ip, "Listed on NVR but not reachable",
                                     mac=mac, status="nvr_seen")
                    added["orphans"] += 1
            elif mac:
                # MAC only (classic silent device on a switch port).
                self._add_orphan("", reason, mac=mac, status=orphan_status)
                added["orphans"] += 1

        self._set_task(
            f"Ingested {kind}: +{added['orphans']} orphan, "
            f"+{added['mismatch']} mismatch, +{added['candidates']} candidate",
            "triage")
        return added

    def _start_dpi_collector(self):
        if self._dpi:
            return
        iface_ip = self.selected_interface.ip if self.selected_interface else ""
        self._dpi = DPICollector()
        # DPI callback now includes sensor_id (7-arg form).
        # The lambda unpacks all args so _handle_passive_evidence gets provenance.
        self._dpi.on_evidence = lambda ip, kind, detail, source, weight, raw, sensor_id="": \
            self._handle_passive_evidence(ip, kind, detail, source, weight, raw, sensor_id)
        self._dpi.start(iface_ip)

        # Gap 3: PassiveListener was instantiated but never wired — now it is.
        # It binds the same multicast ports (3702/1900/37020) that DPICollector
        # already claims, so each _listen_* starts with a try/except OSError
        # and silently skips when the port is already held by DPICollector.
        # PassiveListener adds the dahua/ssdp/onvif callbacks as a second
        # source of evidence — belt-and-suspenders against rare race windows
        # where DPICollector hasn't bound yet at scan start.
        if not self._passive_listener:
            try:
                pl = PassiveListener()
                pl.on_onvif = lambda ip, raw: self._handle_passive_evidence(
                    ip, "onvif_probe_match_generic",
                    "Passive ONVIF announcement", "passive_onvif", 15, raw[:500])
                pl.on_ssdp = lambda ip, raw: self._handle_passive_evidence(
                    ip, "ssdp_camera_service",
                    "Passive SSDP announcement", "passive_ssdp", 10, raw[:500])
                pl.on_dahua = lambda ip, data: self._handle_passive_evidence(
                    ip, "dahua_udp_response",
                    "Passive Dahua UDP announcement", "passive_dahua", 35,
                    data[:500].decode("utf-8", errors="replace"))
                pl.start(iface_ip)
                self._passive_listener = pl
            except Exception:
                pass  # Non-fatal — DPICollector is the primary listener

    def _stop_dpi_collector(self):
        if self._dpi:
            self._dpi.stop()
            self._dpi = None
        if self._passive_listener:
            try:
                self._passive_listener.stop()
            except Exception:
                pass
            self._passive_listener = None

    # Evidence kinds that are too weak or explicitly negative to justify
    # creating a brand-new device record.  We still update the record if one
    # already exists (a laptop might later be overtaken by a camera at the
    # same IP), but we will NOT mint a new DiscoveredDevice just because we
    # saw a DHCP request or an LLDP frame from a switch.
    _PASSIVE_NO_CREATE_KINDS: frozenset = frozenset({
        "dhcp_request",       # +3  — every device on the network sends these
        "lldp_neighbor",      # +2  — switches and uplink routers; almost never cameras
        "router_arp_seen",    # +5  — inferred from router ARP dump, not direct contact
        "switch_mac_seen",    # +5  — seen in switch CAM table, not direct contact
        "wsd_non_camera",     # -20 — explicitly identified as printer/PC/media-server
        "windows_wsd_host",   # -30 — explicitly identified as Windows host
    })

    def _handle_passive_evidence(self, ip: str, kind: str, detail: str, source: str,
                                 weight: int, raw: str, sensor_id: str = ""):
        # Passive listening is continuous and must NOT probe; it only records
        # evidence and feeds the triage queues. The sequential worker decides
        # what (if anything) to actively check.

        # Multicast — track group, never create a device entry
        if ip.startswith(("224.", "239.", "234.")):
            self._observe_multicast(ip, protocol_hint=kind)
            return

        # For weak/negative evidence kinds: update an existing record if present,
        # but do NOT create a new one.  This prevents the device list from filling
        # up with every laptop, phone, printer, and switch on the network just
        # because they sent a DHCP request or LLDP frame.
        if kind in self._PASSIVE_NO_CREATE_KINDS:
            device = self.devices.get(ip)
            if device is None:
                return   # not yet known — skip rather than pollute the list
        else:
            device = self._get_or_create(ip, "Passive-DPI")

        self._record_evidence(device, kind, detail, source, raw=raw, weight=weight,
                              sensor_id=sensor_id)

        # Gap 4: IGMP Membership Report — raw = group IP, src = joining host.
        # Update MulticastGroup.listeners so the UI can show which hosts are
        # subscribed to each camera stream group.
        if kind == "igmp_multicast_stream" and raw:
            group_ip = raw.strip()
            if group_ip:
                with self._triage_lock:
                    if group_ip not in self._multicast_groups:
                        self._multicast_groups[group_ip] = MulticastGroup(
                            group=group_ip, protocol_hint="igmp_join")
                    mg = self._multicast_groups[group_ip]
                    mg.last_seen = _dt.datetime.now()
                    mg.packet_count += 1
                    if ip not in mg.listeners:
                        mg.listeners.append(ip)
                    if ip not in mg.related_ips:
                        mg.related_ips.append(ip)
                # Dynamically join the group so the RTP listener can capture
                # the actual video stream — no static group list needed.
                if self._dpi:
                    try:
                        self._dpi.join_rtp_group(group_ip)
                    except Exception:
                        pass

        # Gap 5: RTP flow — raw = group IP or empty for unicast flows.
        if kind == "rtp_flow" and raw:
            group_ip = raw.strip()
            if group_ip:
                with self._triage_lock:
                    if group_ip not in self._multicast_groups:
                        self._multicast_groups[group_ip] = MulticastGroup(
                            group=group_ip, protocol_hint="rtp_stream")
                    mg = self._multicast_groups[group_ip]
                    mg.last_seen = _dt.datetime.now()
                    mg.packet_count += 1
                    if ip not in mg.sources:
                        mg.sources.append(ip)

        # If the DPI collector sees a device sending ARP for a gateway that
        # doesn't belong to the device's own subnet, record a gateway mismatch.
        # Pattern: "ARP who-has <target_gw> tell <device_ip>"
        if kind in ("arp_request", "arp_for_gateway"):
            gw_m = re.search(r'who.has\s+([\d.]+)', detail or "")
            if not gw_m:
                gw_m = re.search(r'gateway[:\s]+([\d.]+)', detail or "", re.I)
            if gw_m:
                target_gw = gw_m.group(1)
                iface_ip = self.selected_interface.ip if self.selected_interface else ""
                iface_subnet = ip_to_subnet(iface_ip) if iface_ip else ""
                gw_subnet = ip_to_subnet(target_gw)
                ip_subnet = ip_to_subnet(ip)
                # Gateway mismatch: device is ARPing for a GW on a different
                # subnet than its own IP — classic "old static config" signal.
                if (gw_subnet != ip_subnet
                        and bool(iface_subnet)
                        and gw_subnet != iface_subnet):
                    try:
                        self._add_gateway_mismatch(
                            ip, target_gw,
                            reason=(f"Device at {ip} sent ARP for gateway {target_gw} "
                                    f"(belongs to {gw_subnet}, not {ip_subnet})"),
                            evidence_type="arp_for_gateway",
                            next_action=f"Check static config; validate {gw_subnet}",
                        )
                    except Exception:
                        pass

        try:
            self._triage_ingest(ip, kind, detail, raw)
        except Exception:
            pass

    def _probe_all_protocols(self, iface_ips: List[str], timeout: float = 3.0):
        """Run ONVIF, SSDP, and Dahua probes concurrently across all interface IPs.

        Each probe now binds its own ephemeral UDP port (see send_onvif_probe),
        so they neither collide with each other nor with the always-on
        DPICollector on 3702/1900/37020/5353.  3.0s window: a burst of dozens of
        ProbeMatch/SSDP replies must all land before the listener thread joins —
        accuracy matters more than shaving a second here.
        """
        from .discovery import send_onvif_probe, send_ssdp_search, send_dahua_probe, send_mdns_probe
        tasks = []
        for ip in iface_ips:
            tasks.append(('onvif', ip))
            tasks.append(('ssdp', ip))
            tasks.append(('dahua', ip))
            tasks.append(('mdns', ip))

        def run_task(task):
            kind, ip = task
            if self._stopping:
                return
            try:
                if kind == 'onvif':
                    self._merge_onvif_devices(send_onvif_probe(ip, timeout=timeout))
                elif kind == 'ssdp':
                    self._merge_ssdp_devices(send_ssdp_search(ip, timeout=timeout))
                elif kind == 'dahua':
                    self._merge_dahua_devices(send_dahua_probe(ip, timeout=timeout))
                elif kind == 'mdns':
                    self._merge_mdns_devices(send_mdns_probe(ip, timeout=timeout))
            except Exception:
                pass

        # Cap at 8: 4 protocols × up to 2 interface IPs is the common case
        with ThreadPoolExecutor(max_workers=min(len(tasks), 8)) as ex:
            futs = {ex.submit(run_task, t): t for t in tasks}
            for fut in as_completed(futs):
                try:
                    fut.result()
                except Exception:
                    pass

    def _fingerprint_all_serial(self, ips: List[str], phase: str = "verify"):
        """Fingerprint devices one at a time — no concurrency.
        One bad device cannot abort the rest; exceptions are swallowed per IP."""
        total = len(ips)
        for i, ip in enumerate(ips, start=1):
            if self._stopping:
                break
            try:
                self._scan_and_fingerprint(ip)
            except Exception:
                pass
            self._emit_progress(phase, i, total, f"Fingerprinted {ip} ({i}/{total})")

    def _validate_dpi_all_serial(self, ips: List[str], phase: str = "dpi"):
        """Validate DPI stages one device at a time."""
        total = len(ips)
        for i, ip in enumerate(ips, start=1):
            if self._stopping:
                break
            try:
                self._validate_dpi_stages(ip)
            except Exception:
                pass
            self._emit_progress(phase, i, total, f"DPI validated {ip} ({i}/{total})")

    # ─── Mode 3: Active Sweep ─────────────────────────────────────────

    def _has_local_ip_for_subnet(self, subnet_cidr: str) -> bool:
        """Return True if the selected interface already has an IP on this subnet."""
        if not self.selected_interface:
            return False
        try:
            net = ipaddress.IPv4Network(subnet_cidr, strict=False)
        except Exception:
            return False
        for ip in self.selected_interface.all_ips:
            try:
                if ipaddress.IPv4Address(ip) in net:
                    return True
            except Exception:
                pass
        return False

    def _sweep_one_subnet(self, subnet: str, iface_name: str,
                          subnet_idx: int, subnet_total: int):
        """
        Scan one /24 subnet with no concurrency at all.

        Steps:
          1. If the subnet has no local IP → add a single secondary IP via netsh
          2. Ping 1 → fingerprint if alive → Ping 2 → fingerprint if alive → …
          3. Remove the temporary IP (if one was added)

        Everything is synchronous; the caller simply waits for this to finish.
        """
        base = ".".join(subnet.split(".")[:3])
        label = f"[{subnet_idx}/{subnet_total}] {subnet}"
        temp_ip = None

        try:
            # ── Temporary secondary IP ──────────────────────────────────────
            if (self.selected_interface and iface_name
                    and not self._has_local_ip_for_subnet(subnet)):
                candidate = f"{base}.200"
                self._emit_progress("sweep", subnet_idx, subnet_total,
                                    f"{label} — adding {candidate}...")
                if add_secondary_ip(iface_name, candidate):
                    temp_ip = candidate
                    time.sleep(0.5)   # give Windows time to register the address

            # ── Sequential scan: 1 IP at a time ────────────────────────────
            self._emit_progress("sweep", subnet_idx, subnet_total,
                                f"{label} — scanning...")
            for i in range(1, 255):
                if self._stopping:
                    break
                ip = f"{base}.{i}"
                try:
                    if ping_host(ip, 500):
                        device = self._get_or_create(ip, "Ping")
                        # If a prior stage (Listen / Fingerprint) already ran a
                        # full port-scan on this IP, don't repeat the work — just
                        # refresh the timestamp and move on.
                        if device.open_ports:
                            device.last_seen = _dt.datetime.now()
                            self._update_subnet_mismatch(device)
                            self._emit_device_updated(device)
                        else:
                            self._emit_progress("sweep", subnet_idx, subnet_total,
                                                f"{label} — {ip} alive, fingerprinting...")
                            try:
                                self._scan_and_fingerprint(ip)
                            except Exception:
                                pass
                            # Prune the device if fingerprinting found zero camera
                            # signal and there's no other reason to track it.
                            # This keeps the list focused on cameras/NVRs and
                            # removes routers, workstations, and printers that
                            # happened to respond to ping.
                            device = self.devices.get(ip)
                            if device and self._is_non_camera_device(device):
                                with self._devices_lock:
                                    self.devices.pop(ip, None)
                except Exception:
                    pass

            self._emit_progress("sweep", subnet_idx, subnet_total,
                                f"{label} — done")
        finally:
            # ── Remove temporary IP ─────────────────────────────────────────
            if temp_ip and iface_name:
                try:
                    remove_secondary_ip(iface_name, temp_ip)
                except Exception:
                    pass

    # ─── Helpers ──────────────────────────────────────────────────────

    def _collect_arp_entries(self):
        entries = get_arp_table()
        for entry in entries:
            ip = entry["ip"]
            mac = entry["mac"]
            if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                continue
            # Multicast — track group, never scan
            if ip.startswith(("224.", "239.", "234.")):
                self._observe_multicast(ip, protocol_hint="multicast")
                continue

            # APIPA — isolated segment signal, not a scan target
            if is_apipa(ip):
                dev = self._get_or_create(ip, "ARP-APIPA")
                dev.apipa_seen = True
                if mac and not dev.mac:
                    dev.mac = mac
                if dev.poe_state not in ("poe_powered_no_ip", "link_up_no_dhcp"):
                    dev.poe_state = "link_up_no_dhcp"
                if not dev.notes:
                    dev.notes = APIPA_WARNING
                self._add_orphan(ip, APIPA_WARNING, mac=mac,
                                 status="passive_seen")
                self._emit_device_updated(dev)
                continue

            # Only create a new device entry from the ARP table if:
            #   (a) we already know about this IP from another source, OR
            #   (b) the MAC OUI belongs to a known camera/NVR vendor, OR
            #   (c) the device is on a foreign subnet (subnet mismatch → triage)
            # This prevents the device list from being flooded with every
            # laptop, phone, and router that appears in the ARP cache.
            vendor_from_mac = lookup_vendor(mac) if mac else "Unknown"
            is_camera_oui = any(
                kw in vendor_from_mac.lower() for kw in CAMERA_VENDOR_KEYWORDS
            )
            already_known = ip in self.devices
            iface_subnet  = (ip_to_subnet(self.selected_interface.ip)
                             if self.selected_interface and self.selected_interface.ip
                             else "")
            ip_subnet = ip_to_subnet(ip)
            is_foreign = bool(iface_subnet) and ip_subnet != iface_subnet

            if not (already_known or is_camera_oui or is_foreign):
                continue   # plain workstation/router ARP entry — skip

            device = self._get_or_create(ip, "ARP")
            if not device.mac and mac:
                device.mac = mac
                if device.vendor == "Unknown":
                    device.vendor = vendor_from_mac
            self._maybe_add_mac_vendor_evidence(device)
            if "ARP" not in device.discovery_methods:
                device.discovery_methods.append("ARP")
            device.last_seen = _dt.datetime.now()
            self._update_subnet_mismatch(device)
            self._refresh_dpi_stages(device)
            self._emit_device_updated(device)
            # An ARP entry on a foreign subnet is hard L2 proof the device is
            # connected — feed it to the triage queues (mismatch + low-conf
            # candidate). The sequential worker, not this loop, probes it.
            if device.subnet_mismatch:
                try:
                    self._triage_ingest(ip, "arp_foreign",
                                        device.subnet_mismatch, "")
                except Exception:
                    pass

    def _merge_onvif_devices(self, onvif_devices: List[OnvifDevice]):
        for od in onvif_devices:
            device = self._get_or_create(od.ip, "ONVIF")
            device.onvif_status = "found"
            if "ONVIF" not in device.protocols:
                device.protocols.append("ONVIF")
            if od.xaddrs:
                device.onvif_url = od.xaddrs[0]
            if od.model:
                device.model = od.model
            if od.manufacturer and device.vendor == "Unknown":
                device.vendor = od.manufacturer
            device.raw_responses["onvif"] = od.raw_response
            if "ONVIF" not in device.discovery_methods:
                device.discovery_methods.append("ONVIF")
            detail = "Active ONVIF ProbeMatch"
            if any("networkvideotransmitter" in t.lower() for t in od.types):
                detail += " (NetworkVideoTransmitter)"
                self._record_evidence(device, "onvif_probe_match_nvt", detail, "active_onvif",
                                      raw=od.raw_response)
            else:
                self._record_evidence(device, "onvif_probe_match_generic", detail, "active_onvif",
                                      raw=od.raw_response)
            if od.xaddrs:
                self._record_evidence(device, "onvif_device_service_url",
                                      f"ONVIF device_service: {od.xaddrs[0]}",
                                      "active_onvif", raw=od.xaddrs[0])
            device.last_seen = _dt.datetime.now()
            self._update_subnet_mismatch(device)
            self._refresh_dpi_stages(device)
            self._emit_device_updated(device)

    def _merge_ssdp_devices(self, ssdp_devices: List[SsdpDevice]):
        for sd in ssdp_devices:
            device = self._get_or_create(sd.ip, "SSDP")
            if "SSDP/UPnP" not in device.protocols:
                device.protocols.append("SSDP/UPnP")
            if sd.location:
                device.web_url = sd.location
            if sd.server and device.vendor == "Unknown":
                server_lower = sd.server.lower()
                if "hikvision" in server_lower:
                    device.vendor = "Hikvision"
                elif "dahua" in server_lower:
                    device.vendor = "Dahua/Amcrest"
                elif "axis" in server_lower:
                    device.vendor = "Axis"
            device.raw_responses["ssdp"] = str(sd.__dict__)
            if "SSDP" not in device.discovery_methods:
                device.discovery_methods.append("SSDP")
            combined = " ".join(part for part in (sd.location, sd.st, sd.server, sd.usn) if part).lower()
            if any(keyword in combined for keyword in CAMERA_VENDOR_KEYWORDS):
                self._record_evidence(device, "ssdp_camera_service",
                                      f"SSDP camera service from {sd.ip}",
                                      "active_ssdp", raw=combined)
            device.last_seen = _dt.datetime.now()
            self._update_subnet_mismatch(device)
            self._refresh_dpi_stages(device)
            self._emit_device_updated(device)

    def _merge_dahua_devices(self, dahua_devices: List[dict]):
        for dd in dahua_devices:
            ip = dd.get("ip", "")
            if not ip:
                continue
            device = self._get_or_create(ip, "Dahua-UDP")
            if "Dahua-UDP" not in device.discovery_methods:
                device.discovery_methods.append("Dahua-UDP")
            if dd.get("mac") and not device.mac:
                device.mac = dd["mac"]
                device.vendor = lookup_vendor(dd["mac"]) or "Dahua/Amcrest"
            if device.vendor == "Unknown":
                device.vendor = "Dahua/Amcrest"
            if dd.get("name") and not device.model:
                device.model = dd["name"]
            device.raw_responses["dahua_udp"] = str(dd)
            self._record_evidence(device, "dahua_udp_response",
                                  "Dahua/Amcrest UDP discovery response",
                                  "active_dahua", raw=str(dd))
            self._maybe_add_mac_vendor_evidence(device)
            device.last_seen = _dt.datetime.now()
            self._update_subnet_mismatch(device)
            self._refresh_dpi_stages(device)
            self._emit_device_updated(device)

    def _merge_mdns_devices(self, mdns_devices: List[MdnsDevice]):
        for md in mdns_devices:
            if not md.ip:
                continue
            device = self._get_or_create(md.ip, "mDNS")
            if "mDNS" not in device.discovery_methods:
                device.discovery_methods.append("mDNS")
            if "mDNS/UPnP" not in device.protocols:
                device.protocols.append("mDNS")
            svc = md.service_type or ""
            if svc and not device.model:
                device.model = svc
            if md.name and not device.hostname:
                device.hostname = md.name.split(".")[0]
            # Infer vendor from service type
            if device.vendor == "Unknown":
                if "axis" in svc.lower():
                    device.vendor = "Axis"
                elif "hikvision" in svc.lower():
                    device.vendor = "Hikvision"
                elif "onvif" in svc.lower():
                    device.vendor = "Generic ONVIF"
            device.raw_responses["mdns"] = str({"ip": md.ip, "service": svc, "name": md.name})
            self._record_evidence(device, "mdns_camera_service",
                                  f"mDNS camera service: {svc}",
                                  "active_mdns", raw=f"svc={svc} name={md.name}")
            device.last_seen = _dt.datetime.now()
            self._refresh_dpi_stages(device)
            self._emit_device_updated(device)

    def _merge_from_passive(self, ip: str, method: str, data: str):
        device = self._get_or_create(ip, method)
        if method not in device.discovery_methods:
            device.discovery_methods.append(method)
        device.last_seen = _dt.datetime.now()
        device.raw_responses[method.lower()] = data
        self._emit_device_updated(device)

    def _scan_and_fingerprint(self, ip: str):
        device = self._get_or_create(ip)

        # Port scan
        if not device.open_ports:
            device.open_ports = scan_ports(ip)

        # Reverse DNS / generic hostname enrichment
        if not device.hostname:
            rdns_name = reverse_dns_name(ip)
            if rdns_name:
                device.hostname = rdns_name.split(".")[0]
                device.raw_responses["reverse_dns"] = rdns_name

        # HTTP banner
        http_banner = ""
        if 80 in device.open_ports:
            http_banner = grab_http_banner(ip, 80)
        elif 8080 in device.open_ports:
            http_banner = grab_http_banner(ip, 8080)

        # RTSP probe
        if 554 in device.open_ports:
            rtsp_result = probe_rtsp(ip, 554)
            device.rtsp_status = "found" if rtsp_result.found else "error"
            if rtsp_result.found:
                device.rtsp_url = rtsp_result.url or f"rtsp://{ip}:554/"
                if "RTSP" not in device.protocols:
                    device.protocols.append("RTSP")
                self._record_evidence(device, "rtsp_port_open",
                                      "RTSP port responded to probe",
                                      "active_rtsp", raw=rtsp_result.banner)
                if rtsp_result.described and rtsp_result.has_video_sdp:
                    self._record_evidence(device, "rtsp_describe_response",
                                          "RTSP DESCRIBE returned SDP video media",
                                          "active_rtsp", raw=rtsp_result.banner)
            elif 554 in device.open_ports:
                self._record_evidence(device, "rtsp_port_open",
                                      "TCP 554 open with RTSP-like response",
                                      "active_rtsp", raw=rtsp_result.banner)

        # ONVIF URL
        if device.onvif_status == "not-checked" and 8899 in device.open_ports:
            device.onvif_status = "found"
            device.onvif_url = f"http://{ip}:8899/onvif/device_service"
            if "ONVIF" not in device.protocols:
                device.protocols.append("ONVIF")
            self._record_evidence(device, "onvif_device_service_url",
                                  f"ONVIF device_service: {device.onvif_url}",
                                  "active_onvif", raw=device.onvif_url)

        # Construct web URL
        if not device.web_url:
            if 80 in device.open_ports:
                device.web_url = f"http://{ip}/"
            elif 8080 in device.open_ports:
                device.web_url = f"http://{ip}:8080/"
            elif 443 in device.open_ports:
                device.web_url = f"https://{ip}/"

        # Fingerprint
        onvif_response = device.raw_responses.get("onvif", "")
        fp = fingerprint_device(device.mac, device.open_ports, http_banner, onvif_response)
        if fp.vendor and fp.vendor != "Unknown":
            device.vendor = fp.vendor
        if fp.model:
            device.model = fp.model
        device.confidence = fp.confidence
        for proto in fp.protocols:
            if proto not in device.protocols:
                device.protocols.append(proto)

        # Bridge fingerprint → evidence system.
        # `camera_confidence` is the sum of recorded Evidence weights.  When
        # active probes fail (e.g. RTSP DESCRIBE returns 401), the device may
        # have very few evidence items (e.g. only rtsp_port_open +12) even
        # though the fingerprint heuristic correctly rates it as a camera (~50%).
        # We mint a synthetic evidence item whose weight makes up the gap so the
        # evidence-based score is never *lower* than the fingerprint score.
        # The item is only added when the fingerprint contributes real signal.
        if fp.confidence >= 20:
            current_ev_score = sum(e.weight for e in device.evidence)
            gap = fp.confidence - current_ev_score
            if gap > 0:
                # Cap the bridging weight at 30 to avoid wildly inflating scores
                bridge_weight = min(gap, 30)
                detail = (f"Fingerprint heuristic: {fp.vendor or 'unknown'} "
                          f"{fp.model or ''} (score {fp.confidence}%)").strip()
                self._record_evidence(device, "fingerprint_match", detail,
                                      "fingerprint", weight=bridge_weight)

        # ONVIF device info (ODM-style: get real model/firmware/stream URIs)
        if device.onvif_status == "found" and device.onvif_url:
            try:
                # Gap 7+9: prefer saved per-device creds, fall back to zone
                # credential_profile, then anonymous.
                _cred = self.credentials.get(ip, {})
                if not _cred:
                    # Gap 9: look up credential_profile for this device's subnet
                    _zone_key = ip_to_subnet(ip)
                    _zone = self.subnet_zones.get(_zone_key)
                    _profile = _zone.credential_profile if _zone else ""
                    if _profile:
                        # credential_profile is a key into self.credentials
                        # (operator can store a shared profile credential under
                        # a profile name, e.g. "site_admin")
                        _cred = self.credentials.get(_profile, {})
                _user = _cred.get("username", "admin")
                _pass = _cred.get("password", "")
                info = query_onvif_device_info(ip, device.onvif_url, _user, _pass)
                if not info.error:
                    self._record_evidence(device, "onvif_port_responding",
                                          "ONVIF endpoint replied to SOAP",
                                          "active_onvif")
                    self._record_evidence(device, "onvif_device_info",
                                          "ONVIF GetDeviceInformation returned device metadata",
                                          "active_onvif")
                    if info.manufacturer and device.vendor in ("Unknown", ""):
                        device.vendor = info.manufacturer
                    if info.model:
                        device.model = info.model
                    if info.firmware:
                        device.firmware = info.firmware
                    if info.serial:
                        device.raw_responses["onvif_serial"] = info.serial
                    # Prefer ONVIF-provided stream URIs over guessed ones
                    if info.stream_uris:
                        device.rtsp_url = info.stream_uris[0]
                        device.raw_responses["onvif_streams"] = "\n".join(info.stream_uris)
                        device.rtsp_status = "found"
                        if "RTSP" not in device.protocols:
                            device.protocols.append("RTSP")
            except Exception:
                pass

        self._maybe_add_http_banner_evidence(device, http_banner)
        self._maybe_add_mac_vendor_evidence(device)
        self._refresh_device_type(device, http_banner=http_banner)

        # Subnet
        device.subnet = ip_to_subnet(ip)
        device.last_seen = _dt.datetime.now()
        self._update_subnet_mismatch(device)
        self._refresh_dpi_stages(device)

        self._emit_device_updated(device)

    def _refresh_device_type(self, device: DiscoveredDevice, http_banner: str = ""):
        result = classify_device_type(
            vendor=device.vendor,
            open_ports=device.open_ports,
            protocols=device.protocols,
            http_banner=http_banner,
            model=device.model,
            hostname=device.hostname,
            camera_confidence=device.camera_confidence,
        )
        device.device_class = result.device_type
        device.warn_reset = result.warn_reset
        device.classification_rationale = result.rationale

    # ─── Subnet Watch (Wireshark-inspired) ───────────────────────────
    # Any subnet we observe in live traffic gets automatically configured
    # and scanned — no user intervention required.

    def start_subnet_watch(self):
        """Start background sniffer that detects and auto-scans new subnets."""
        if self._watch_active:
            return
        self._watch_active = True
        self._sniffer = SubnetSniffer()

        # Seed with subnets we already know so they don't fire as "new"
        seeds = list(self.subnet_zones.keys())
        if self.selected_interface:
            seeds.append(ip_to_subnet(self.selected_interface.ip))
        for s in discover_local_subnets():
            seeds.append(s)
        self._sniffer.seed(seeds)

        def _on_new(sniffed: SniffedSubnet):
            self._emit_progress(
                "watch", 0, 0,
                f"New subnet sniffed: {sniffed.subnet} (via {sniffed.source}, first IP {sniffed.first_seen_ip})"
            )
            if self.on_subnet_found:
                self.on_subnet_found(sniffed)
            # Auto-configure access and scan in a background thread
            zone = SubnetZone(subnet=sniffed.subnet, label=f"Auto ({sniffed.source})", method="auto")
            self.add_subnet_zone(zone)
            threading.Thread(target=self._auto_scan_subnet, args=(sniffed.subnet,), daemon=True).start()

        self._sniffer.on_new_subnet = _on_new
        self._sniffer.start(self.selected_interface.ip if self.selected_interface else "")

    def stop_subnet_watch(self):
        self._watch_active = False
        if self._sniffer:
            self._sniffer.stop()
            self._sniffer = None

    def _auto_scan_subnet(self, subnet: str):
        """Enqueue a freshly-discovered subnet and ensure a worker is running.

        Appends a ScopeCursor so the triage engine walks it in priority order.
        If no triage loop is currently active (watch mode running between scans,
        or scan completed before the new subnet arrived) a bounded worker thread
        is started so the queue doesn't sit idle indefinitely.
        """
        self._emit_progress("auto-scan", 0, 1,
                            f"New subnet {subnet} — queued for triage walk")
        with self._triage_lock:
            if not any(s.cidr == subnet for s in self._known_scopes):
                self._known_scopes.append(
                    ScopeCursor(cidr=subnet, source="sniffed"))

        # If the main triage loop is not running, start a lightweight worker
        # that drains the new scope.  This handles watch-mode-only operation
        # where run() was never called (or finished) before the subnet arrived.
        if not self._triage_running:
            def _watch_worker():
                try:
                    self._run_triage("sweep", None)
                except Exception:
                    pass
            threading.Thread(target=_watch_worker, daemon=True,
                             name="watch-triage-worker").start()

    def _validate_dpi_stages(self, ip: str):
        """Run all DPI protocol-stage checks for a device."""
        device = self._get_or_create(ip)
        now = _dt.datetime.now

        # Stage 1: Link (L2 reachability)
        reachable = ping_host(ip, 1500)
        device.dpi_stages["link"] = DPIStageResult(
            stage="link",
            status="pass" if reachable else "fail",
            detail="ICMP reply received" if reachable else "No ICMP reply",
            timestamp=now(),
        )

        # Stage 2: DHCP/IP assignment
        # If we have ARP entry, IP is assigned (static or DHCP)
        arp_ok = bool(device.mac) and device.mac != ""
        device.dpi_stages["dhcp"] = DPIStageResult(
            stage="dhcp",
            status="pass" if arp_ok else "unchecked",
            detail=f"MAC resolved: {device.mac}" if arp_ok else "No ARP entry",
            timestamp=now(),
        )

        # Stage 3: Discovery (ONVIF/SSDP)
        discovery_ok = device.onvif_status == "found" or "SSDP" in device.discovery_methods
        methods = ", ".join(device.discovery_methods) if device.discovery_methods else "none"
        device.dpi_stages["discovery"] = DPIStageResult(
            stage="discovery",
            status="pass" if discovery_ok else "fail",
            detail=f"Methods: {methods}",
            timestamp=now(),
        )

        # Stage 4: Auth (HTTP/HTTPS admin)
        auth_ok = bool(device.web_url) and (80 in device.open_ports or 443 in device.open_ports or 8080 in device.open_ports)
        device.dpi_stages["auth"] = DPIStageResult(
            stage="auth",
            status="pass" if auth_ok else "fail",
            detail=device.web_url or "No web URL",
            timestamp=now(),
        )

        # Stage 5: RTSP
        if device.rtsp_status == "found":
            device.dpi_stages["rtsp"] = DPIStageResult(
                stage="rtsp", status="pass",
                detail=device.rtsp_url or "RTSP responding",
                timestamp=now(),
            )
        elif 554 in device.open_ports:
            device.dpi_stages["rtsp"] = DPIStageResult(
                stage="rtsp", status="fail",
                detail="Port 554 open but RTSP negotiation failed",
                timestamp=now(),
            )
        else:
            device.dpi_stages["rtsp"] = DPIStageResult(
                stage="rtsp", status="na",
                detail="No RTSP port detected",
                timestamp=now(),
            )

        # Stage 6: ONVIF Control
        if device.onvif_status == "found":
            device.dpi_stages["onvif_ctrl"] = DPIStageResult(
                stage="onvif_ctrl", status="pass",
                detail=device.onvif_url or "ONVIF endpoint found",
                timestamp=now(),
            )
        elif 8899 in device.open_ports or 3702 in device.open_ports:
            device.dpi_stages["onvif_ctrl"] = DPIStageResult(
                stage="onvif_ctrl", status="fail",
                detail="ONVIF ports open but no response",
                timestamp=now(),
            )
        else:
            device.dpi_stages["onvif_ctrl"] = DPIStageResult(
                stage="onvif_ctrl", status="na",
                detail="No ONVIF ports detected",
                timestamp=now(),
            )

        # Stage 7: NTP — UDP protocol, cannot reliably check via TCP
        if reachable:
            ntp_ok = test_tcp_port(ip, 123, 1.0)
            device.dpi_stages["ntp"] = DPIStageResult(
                stage="ntp",
                status="pass" if ntp_ok else "na",
                detail="TCP 123 reachable (may not be NTP — NTP uses UDP)" if ntp_ok else "NTP uses UDP 123 — cannot verify via TCP from this position",
                timestamp=now(),
            )
        else:
            device.dpi_stages["ntp"] = DPIStageResult(
                stage="ntp", status="na",
                detail="Device not reachable, NTP check skipped",
                timestamp=now(),
            )

        # Stage 8: DNS — requires capture at gateway to verify camera DNS queries
        device.dpi_stages["dns"] = DPIStageResult(
            stage="dns",
            status="na",
            detail="DNS check requires capture position at gateway (cannot verify from endpoint)",
            timestamp=now(),
        )

        # Stage 9: Cloud egress
        device.dpi_stages["cloud"] = DPIStageResult(
            stage="cloud",
            status="na",
            detail="Cloud/P2P egress requires capture at network egress point",
            timestamp=now(),
        )

        # Stage 10: Recording path — cameras don't run SMB/FTP servers;
        # these ports would be on the NVR, not the camera
        device.dpi_stages["recording"] = DPIStageResult(
            stage="recording",
            status="na",
            detail="Recording path must be verified at NVR/storage side, not from camera endpoint",
            timestamp=now(),
        )

        # Assign subnet zone
        device.subnet_zone = self._find_subnet_zone(ip)

        device.last_seen = now()
        self._refresh_dpi_stages(device, preserve_explicit=True)
        self._emit_device_updated(device)

    def _record_evidence(self, device: DiscoveredDevice, kind: str, detail: str, source: str,
                         raw: str = "", weight: Optional[int] = None,
                         sensor_id: str = ""):
        """Append an evidence item to the device ledger with full provenance.

        Provenance fields are populated from the orchestrator's current
        interface/capture-position so every evidence item carries the context
        of where it was observed — not just what was observed.
        """
        iface_name  = self.selected_interface.name if self.selected_interface else ""
        cap_pos     = self.capture_position.position if self.capture_position else "unknown"
        vis_limit   = (
            f"Observed from {cap_pos} via {iface_name}" if iface_name else
            f"Observed from {cap_pos}"
        )
        evidence = Evidence(
            kind=kind,
            detail=detail,
            source=source,
            weight=EVIDENCE_WEIGHTS.get(kind, 0) if weight is None else weight,
            raw=raw[:500] if raw else "",
            sensor_id=sensor_id or source,
            interface=iface_name,
            capture_position=cap_pos,
            visibility_limit=vis_limit,
        )
        if not device.add_evidence(evidence):
            return

        if kind in {"onvif_probe_match_nvt", "onvif_probe_match_generic", "onvif_device_service_url", "onvif_device_info", "onvif_port_responding"}:
            device.onvif_status = "found"
            if "ONVIF" not in device.protocols:
                device.protocols.append("ONVIF")
            if "ONVIF" not in device.discovery_methods:
                device.discovery_methods.append("ONVIF")
        if kind == "onvif_device_service_url":
            url = raw or detail.split(": ", 1)[-1]
            parsed = urlparse(url)
            if parsed.scheme and parsed.netloc:
                device.onvif_url = url
        if kind in {"sadp_response", "dahua_udp_response"} and "SADP" not in device.discovery_methods:
            device.discovery_methods.append("SADP")
        if kind in {"rtsp_port_open", "rtsp_describe_response", "rtsp_setup_play"}:
            device.rtsp_status = "found"
            if "RTSP" not in device.protocols:
                device.protocols.append("RTSP")
            if not device.rtsp_url:
                device.rtsp_url = f"rtsp://{device.ip}:554/"
        if kind == "ssdp_camera_service" and "SSDP" not in device.discovery_methods:
            device.discovery_methods.append("SSDP")
        if kind == "mdns_camera_service" and "mDNS" not in device.discovery_methods:
            device.discovery_methods.append("mDNS")
        if kind == "lldp_neighbor" and "LLDP" not in device.discovery_methods:
            device.discovery_methods.append("LLDP")
            # Extract chassis MAC and system name from raw evidence
            if raw:
                for part in raw.split():
                    if part.startswith("chassis=") and ":" in part and not device.mac:
                        device.mac = part.split("=", 1)[1]
                        if device.vendor == "Unknown":
                            device.vendor = lookup_vendor(device.mac)
                    if part.startswith("name=") and not device.hostname:
                        device.hostname = part.split("=", 1)[1]
        if kind == "subnet_mismatch_visible" and not device.subnet_mismatch:
            device.subnet_mismatch = detail

        if raw and kind not in device.raw_responses:
            device.raw_responses[kind] = raw[:500]

        self._update_subnet_mismatch(device)
        self._refresh_dpi_stages(device)
        device.last_seen = _dt.datetime.now()
        self._emit_device_updated(device)

    # ── Camera-vs-infrastructure discrimination ────────────────────────────

    # Ports that are almost always camera/NVR (any one of these = keep the entry)
    _CAMERA_PORTS: frozenset = frozenset({
        554,    # RTSP
        8554,   # RTSP alternate
        8899,   # ONVIF
        37777,  # Dahua TCP
        8000,   # Hikvision SDK / SADP management
        34567,  # Dahua P2P
    })

    def _is_non_camera_device(self, device: DiscoveredDevice) -> bool:
        """Return True when the device has no detectable camera signal at all.

        Used by the ping-sweep path to prune routers, workstations, and printers
        that responded to ping but showed no camera characteristics.  We keep a
        device if ANY of the following is true:

          • camera_confidence > 0 (any positive evidence)
          • open_ports contains a known camera port (554, 8899, …)
          • device_class is nvr / gateway / seed / infrastructure
          • it has a subnet_mismatch flag (triage needs to investigate)
          • it was added from a protocol-level source (ONVIF, SADP, RTSP, …)
        """
        if device.camera_confidence > 0:
            return False
        if device.open_ports and self._CAMERA_PORTS.intersection(device.open_ports):
            return False
        if device.device_class in ("nvr", "bridge", "router", "switch", "server",
                                   "gateway", "infrastructure", "seed", "seed_nvr"):
            return False
        if device.subnet_mismatch:
            return False
        # Preserve anything discovered by a protocol scanner (not just ping)
        strong_methods = {"ONVIF", "SADP", "Dahua-UDP", "SSDP", "mDNS",
                          "RTSP", "Passive-DPI", "seed", "seed_nvr"}
        if strong_methods.intersection(device.discovery_methods):
            return False
        return True

    def _maybe_add_mac_vendor_evidence(self, device: DiscoveredDevice):
        vendor = lookup_vendor(device.mac)
        if vendor != "Unknown":
            if device.vendor == "Unknown":
                device.vendor = vendor
            # Only award camera evidence when the OUI actually belongs to a camera
            # vendor.  Any recognized MAC (Intel NIC, Raspberry Pi, etc.) used to
            # get +10 spuriously — inflating confidence for non-camera devices.
            vendor_lower = vendor.lower()
            if any(kw in vendor_lower for kw in CAMERA_VENDOR_KEYWORDS):
                self._record_evidence(device, "mac_oui_camera",
                                      f"MAC OUI matches camera vendor {vendor}",
                                      "arp")

    def _maybe_add_http_banner_evidence(self, device: DiscoveredDevice, banner: str):
        if not banner:
            return
        lower = banner.lower()
        for keyword in CAMERA_VENDOR_KEYWORDS:
            if keyword in lower:
                detail = f"HTTP banner references camera marker '{keyword}'"
                self._record_evidence(device, "http_camera_banner", detail, "active_http",
                                      raw=banner)
                break

    def _local_subnets(self) -> set:
        """Return the set of all subnets the selected interface has an IP on.

        Multi-homed adapters (primary + secondary IPs added by the scanner)
        should not produce false "foreign subnet" alerts for the subnets we
        deliberately added a secondary address to.
        """
        if not self.selected_interface:
            return set()
        subnets = set()
        for s in self.selected_interface.all_subnets():
            subnets.add(s)
        # Also include any temporarily-added secondary IPs
        for cidr in self._scope_temp_ip:
            subnets.add(cidr)
        return subnets

    def _update_subnet_mismatch(self, device: DiscoveredDevice):
        if not self.selected_interface or not device.ip:
            return
        device.subnet = device.subnet or ip_to_subnet(device.ip)
        # Compare against ALL locally-assigned subnets, not just the primary.
        # A device reachable via a secondary IP we added is not a mismatch.
        local_subnets = self._local_subnets()
        if not local_subnets or device.subnet in local_subnets:
            return

        l2_methods = {"ONVIF", "SSDP", "SADP", "Dahua-UDP", "Passive-DPI", "ARP", "Sniff"}
        if any(method in l2_methods for method in device.discovery_methods):
            device.subnet_mismatch = (
                f"Device visible by local discovery on {iface_subnet}, "
                f"but reports or uses {device.subnet}"
            )

    def _refresh_dpi_stages(self, device: DiscoveredDevice, preserve_explicit: bool = False):
        if preserve_explicit and device.dpi_stages:
            existing = device.dpi_stages.copy()
        else:
            existing = {}

        now = _dt.datetime.now()
        evidence_kinds = {e.kind for e in device.evidence}
        discovery_ok = bool({
            "onvif_probe_match_nvt", "onvif_probe_match_generic", "onvif_device_service_url",
            "sadp_response", "dahua_udp_response", "ssdp_camera_service", "mdns_camera_service",
        } & evidence_kinds) or device.onvif_status == "found"

        # Link: L2 reachability (ARP or ping)
        link_pass = bool(device.mac or "ping_responded" in evidence_kinds or "ARP" in device.discovery_methods)
        device.dpi_stages["link"] = existing.get("link", DPIStageResult(
            stage="link",
            status="pass" if link_pass else "unchecked",
            detail=f"MAC resolved: {device.mac}" if device.mac else ("Ping responded" if "ping_responded" in evidence_kinds else "No L2 signal yet"),
            timestamp=now,
        ))

        # DHCP / IP assignment
        dhcp_pass = bool(device.mac or "dhcp_lease_seen" in evidence_kinds or "dhcp_request" in evidence_kinds)
        device.dpi_stages["dhcp"] = existing.get("dhcp", DPIStageResult(
            stage="dhcp",
            status="pass" if dhcp_pass else "unchecked",
            detail=f"MAC resolved: {device.mac}" if device.mac else ("DHCP evidence seen" if dhcp_pass else "No ARP/DHCP identity yet"),
            timestamp=now,
        ))

        # Discovery
        device.dpi_stages["discovery"] = existing.get("discovery", DPIStageResult(
            stage="discovery",
            status="pass" if discovery_ok else "fail",
            detail=", ".join(device.discovery_methods) if device.discovery_methods else "No discovery evidence",
            timestamp=now,
        ))

        # Auth reachable
        auth_pass = bool(device.web_url) or bool({"http_camera_banner", "onvif_device_info"} & evidence_kinds)
        device.dpi_stages["auth"] = existing.get("auth", DPIStageResult(
            stage="auth",
            status="pass" if auth_pass else "fail",
            detail=device.web_url or "No web/admin endpoint seen",
            timestamp=now,
        ))

        # RTSP stream
        rtsp_evidence = {"rtsp_describe_response", "rtsp_setup_play", "rtsp_port_open"} & evidence_kinds
        rtsp_pass = bool(rtsp_evidence)
        rtsp_na = 554 not in device.open_ports and not device.rtsp_url
        device.dpi_stages["rtsp"] = existing.get("rtsp", DPIStageResult(
            stage="rtsp",
            status="pass" if rtsp_pass else ("na" if rtsp_na else "fail"),
            detail=device.rtsp_url or ("No RTSP evidence" if rtsp_na else "Port 554 open but probe incomplete"),
            timestamp=now,
        ))

        # ONVIF control
        onvif_evidence = {"onvif_device_service_url", "onvif_port_responding", "onvif_device_info"} & evidence_kinds
        onvif_pass = bool(onvif_evidence) or device.onvif_status == "found"
        onvif_na = 8899 not in device.open_ports and not device.onvif_url
        device.dpi_stages["onvif_ctrl"] = existing.get("onvif_ctrl", DPIStageResult(
            stage="onvif_ctrl",
            status="pass" if onvif_pass else ("na" if onvif_na else "fail"),
            detail=device.onvif_url or "No ONVIF control evidence",
            timestamp=now,
        ))

        # NTP sync
        ntp_pass = "ntp_port_open" in evidence_kinds or 123 in device.open_ports
        device.dpi_stages["ntp"] = existing.get("ntp", DPIStageResult(
            stage="ntp",
            status="pass" if ntp_pass else "unchecked",
            detail="NTP port 123 open" if ntp_pass else "No NTP evidence",
            timestamp=now,
        ))

        # DNS
        dns_pass = "dns_query_seen" in evidence_kinds or 53 in device.open_ports
        device.dpi_stages["dns"] = existing.get("dns", DPIStageResult(
            stage="dns",
            status="pass" if dns_pass else "unchecked",
            detail="DNS port 53 open" if dns_pass else "No DNS evidence",
            timestamp=now,
        ))

        # Cloud / P2P egress
        cloud_pass = "cloud_egress_seen" in evidence_kinds
        cloud_fail = "cloud_egress_blocked" in evidence_kinds
        device.dpi_stages["cloud"] = existing.get("cloud", DPIStageResult(
            stage="cloud",
            status="pass" if cloud_pass else ("fail" if cloud_fail else "unchecked"),
            detail="Cloud/P2P egress detected" if cloud_pass else ("Cloud egress blocked" if cloud_fail else "No cloud egress evidence"),
            timestamp=now,
        ))

        # Recording path
        if "subnet_mismatch_visible" in evidence_kinds or device.subnet_mismatch:
            device.dpi_stages["recording"] = existing.get("recording", DPIStageResult(
                stage="recording",
                status="unchecked",
                detail=device.subnet_mismatch or "Layer-2 visible, but IP/subnet mismatch needs repair",
                timestamp=now,
            ))
        else:
            rec_pass = "nvr_channel_match" in evidence_kinds or "nvr_channel_listed" in evidence_kinds
            device.dpi_stages.setdefault("recording", DPIStageResult(
                stage="recording",
                status="pass" if rec_pass else "na",
                detail="Listed in NVR channel list" if rec_pass else "Recording path must be verified at NVR/storage side, not from camera endpoint",
                timestamp=now,
            ))

    # ─── Subnet Zone Management ───────────────────────────────────────

    def add_subnet_zone(self, zone: SubnetZone) -> bool:
        """Add a subnet zone and make it reachable."""
        self.subnet_zones[zone.subnet] = zone

        # Try to make subnet reachable based on method
        if zone.method == "route" and zone.gateway:
            success = add_static_route(zone.subnet, zone.gateway)
            if success:
                zone.routes_added.append(f"{zone.subnet} via {zone.gateway}")
            return success

        elif zone.method == "secondary_ip" and self.selected_interface:
            base = ".".join(zone.subnet.split(".")[:3])
            temp_ip = f"{base}.100"
            success = add_secondary_ip(self.selected_interface.name, temp_ip)
            if success:
                zone.added_ips.append(temp_ip)
            return success

        elif zone.method == "auto":
            # Try secondary IP first, then route
            if self.selected_interface:
                base = ".".join(zone.subnet.split(".")[:3])
                temp_ip = f"{base}.100"
                if add_secondary_ip(self.selected_interface.name, temp_ip):
                    zone.added_ips.append(temp_ip)
                    zone.method = "secondary_ip"
                    return True

            # Try default gateway for route
            if self.selected_interface and self.selected_interface.gateway:
                if add_static_route(zone.subnet, self.selected_interface.gateway):
                    zone.routes_added.append(f"{zone.subnet} via {self.selected_interface.gateway}")
                    zone.method = "route"
                    return True

        return True  # Zone added even if we can't make it reachable yet

    def remove_subnet_zone(self, subnet: str) -> bool:
        """Remove a subnet zone and clean up any added IPs/routes."""
        zone = self.subnet_zones.pop(subnet, None)
        if not zone:
            return False

        # Clean up added IPs
        if self.selected_interface:
            for ip in zone.added_ips:
                remove_secondary_ip(self.selected_interface.name, ip)

        # Clean up added routes
        for route_spec in zone.routes_added:
            parts = route_spec.split(" via ")
            if len(parts) == 2:
                remove_static_route(parts[0].strip(), parts[1].strip())

        return True

    def cleanup_all_zones(self):
        """Remove all subnet zones and clean up."""
        for subnet in list(self.subnet_zones.keys()):
            self.remove_subnet_zone(subnet)

    def probe_subnet_zone(self, subnet: str) -> dict:
        """Probe a subnet zone for connectivity."""
        return probe_subnet_connectivity(subnet)

    def _find_subnet_zone(self, ip: str) -> str:
        """Find which subnet zone an IP belongs to."""
        subnet = ip_to_subnet(ip)
        if subnet in self.subnet_zones:
            zone = self.subnet_zones[subnet]
            return zone.label or zone.subnet
        return subnet

    # ─── Capture Position ─────────────────────────────────────────────

    def _auto_detect_capture_position(self):
        """Auto-detect capture position from interface type."""
        interfaces = get_interfaces()
        ethernet = [i for i in interfaces if i.iface_type == "ethernet"]
        wifi = [i for i in interfaces if i.iface_type == "wi-fi"]

        if ethernet:
            self.capture_position = CapturePosition(
                position="ethernet_same",
                can_see_unicast=True,
                can_see_broadcast=True,
                can_see_multicast=True,
                can_see_rtsp=True,
            )
        elif wifi:
            self.capture_position = CapturePosition(
                position="wifi",
                can_see_unicast=False,
                can_see_broadcast=True,
                can_see_multicast=True,
                can_see_rtsp=False,
                notes="Wi-Fi capture: cannot see unicast camera-to-NVR traffic",
            )

    def set_capture_position(self, position: str):
        """Manually set the capture position (locks auto-detection)."""
        self._capture_position_manual = True
        presets = {
            "wifi": CapturePosition(position="wifi", can_see_unicast=False, can_see_broadcast=True, can_see_multicast=True, can_see_rtsp=False, notes="Wi-Fi capture: limited visibility"),
            "ethernet_same": CapturePosition(position="ethernet_same", can_see_unicast=True, can_see_broadcast=True, can_see_multicast=True, can_see_rtsp=True),
            "span_port": CapturePosition(position="span_port", can_see_unicast=True, can_see_broadcast=True, can_see_multicast=True, can_see_rtsp=True, notes="Full visibility via SPAN/mirror port"),
            "inline_tap": CapturePosition(position="inline_tap", can_see_unicast=True, can_see_broadcast=True, can_see_multicast=True, can_see_rtsp=True, notes="Full visibility via inline tap"),
            "nvr_capture": CapturePosition(position="nvr_capture", can_see_unicast=True, can_see_broadcast=True, can_see_multicast=True, can_see_rtsp=True, notes="Capture at NVR interface"),
        }
        self.capture_position = presets.get(position, CapturePosition(position=position))
