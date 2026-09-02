"""Discovery protocols: ONVIF WS-Discovery, SSDP, mDNS, port scan, RTSP probe, HTTP banner"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import socket
import struct
import threading
import time
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from . import ONVIF_PROBE_TEMPLATE, SSDP_SEARCH_TEMPLATE, ALL_CAMERA_PORTS


# ─── ONVIF WS-Discovery ─────────────────────────────────────────────

@dataclass
class OnvifDevice:
    ip: str
    xaddrs: List[str] = field(default_factory=list)
    scopes: List[str] = field(default_factory=list)
    types: List[str] = field(default_factory=list)
    model: str = ""
    manufacturer: str = ""
    raw_response: str = ""


def send_onvif_probe(interface_ip: str = "", timeout: float = 3.0) -> List[OnvifDevice]:
    """Send ONVIF WS-Discovery probe and collect camera responses."""
    devices: List[OnvifDevice] = []
    seen_ips: set[str] = set()
    lock = threading.Lock()

    ONVIF_MULTICAST = "239.255.255.250"
    ONVIF_PORT = 3702

    message_id = str(uuid.uuid4())
    probe_msg = ONVIF_PROBE_TEMPLATE.replace("{message_id}", message_id)
    probe_bytes = probe_msg.encode("utf-8")

    def listener(sock: socket.socket):
        sock.settimeout(timeout)
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(65535)
                response = data.decode("utf-8", errors="replace")
                source_ip = addr[0]
                device = _parse_onvif_response(response, source_ip)
                if device:
                    with lock:
                        if source_ip not in seen_ips:
                            seen_ips.add(source_ip)
                            devices.append(device)
            except socket.timeout:
                break
            except Exception:
                continue

    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        if interface_ip:
            try:
                sock.setsockopt(
                    socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                    socket.inet_aton(interface_ip)
                )
            except Exception:
                pass

        sock.setsockopt(
            socket.IPPROTO_IP, socket.IP_MULTICAST_TTL,
            struct.pack("b", 4)
        )

        # CRITICAL: bind to an EPHEMERAL port, never the well-known 3702.
        #
        # The always-on DPICollector binds UDP 3702 for passive WS-Discovery
        # (Hello/Bye). If this active probe also bound 3702, two sockets would
        # share the port; on Windows the OS delivers each incoming unicast
        # datagram to only ONE of them, non-deterministically — so the 66
        # ProbeMatch replies get split arbitrarily between the two sockets and
        # this probe sees only a random fraction (the "66 vs 7" bug).
        #
        # WS-Discovery ProbeMatch replies are unicast back to the *source port*
        # of the Probe, so an ephemeral source port receives them all cleanly
        # with zero contention. Any non-conformant camera that replies only to
        # the multicast group is still caught by the DPICollector on 3702.
        # (This mirrors send_ssdp_search, which already binds ("", 0).)
        sock.bind(("", 0))

        # Start listener thread
        listener_thread = threading.Thread(target=listener, args=(sock,), daemon=True)
        listener_thread.start()

        # Send probe to multicast and broadcast
        sock.sendto(probe_bytes, (ONVIF_MULTICAST, ONVIF_PORT))
        try:
            sock.sendto(probe_bytes, ("255.255.255.255", ONVIF_PORT))
        except Exception:
            pass

        # Wait for listener to finish
        listener_thread.join(timeout=timeout)

    finally:
        try:
            sock.close()
        except Exception:
            pass

    return devices


def _parse_onvif_response(response: str, source_ip: str) -> Optional[OnvifDevice]:
    """Parse an ONVIF WS-Discovery response."""
    try:
        # Must be a ProbeMatch response
        if "ProbeMatch" not in response and "probeMatch" not in response:
            return None

        xaddrs = []
        scopes = []
        types_list = []

        # Extract XAddrs
        xaddr_matches = re.findall(r"<d:XAddrs>(.*?)</d:XAddrs>", response, re.DOTALL)
        for xm in xaddr_matches:
            xaddrs.extend(xm.strip().split())

        # Extract Scopes
        scopes_match = re.search(r"<d:Scopes>(.*?)</d:Scopes>", response, re.DOTALL)
        if scopes_match:
            scopes = scopes_match.group(1).strip().split()

        # Extract Types
        types_matches = re.findall(r"<d:Types>(.*?)</d:Types>", response, re.DOTALL)
        types_list = [t.strip() for t in types_matches]

        # Extract model and manufacturer from scopes
        model = ""
        manufacturer = ""
        from urllib.parse import unquote
        for scope in scopes:
            name_m = re.match(r"onvif://www\.onvif\.org/name/(.+)", scope)
            if name_m:
                model = unquote(name_m.group(1))
            hw_m = re.match(r"onvif://www\.onvif\.org/hardware/(.+)", scope)
            if hw_m and not model:
                model = unquote(hw_m.group(1))
            mfr_m = re.match(r"onvif://www\.onvif\.org/manufacturer/(.+)", scope)
            if mfr_m:
                manufacturer = unquote(mfr_m.group(1))

        return OnvifDevice(
            ip=source_ip,
            xaddrs=xaddrs,
            scopes=scopes,
            types=types_list,
            model=model,
            manufacturer=manufacturer,
            raw_response=response,
        )
    except Exception:
        return None


# ─── SSDP/UPnP Discovery ────────────────────────────────────────────

@dataclass
class SsdpDevice:
    ip: str
    port: int
    location: str
    st: str
    server: str
    usn: str


def send_ssdp_search(interface_ip: str = "", timeout: float = 3.0) -> List[SsdpDevice]:
    """Send SSDP M-SEARCH and collect device responses."""
    devices: List[SsdpDevice] = []
    seen_locations: set[str] = set()
    lock = threading.Lock()

    SSDP_MULTICAST = "239.255.255.250"
    SSDP_PORT = 1900
    search_bytes = SSDP_SEARCH_TEMPLATE.encode("utf-8")

    def listener(sock: socket.socket):
        sock.settimeout(timeout)
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(65535)
                response = data.decode("utf-8", errors="replace")
                device = _parse_ssdp_response(response, addr[0], addr[1])
                if device and device.location not in seen_locations:
                    with lock:
                        if device.location not in seen_locations:
                            seen_locations.add(device.location)
                            devices.append(device)
            except socket.timeout:
                break
            except Exception:
                continue

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if interface_ip:
            try:
                sock.setsockopt(
                    socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                    socket.inet_aton(interface_ip)
                )
            except Exception:
                pass

        sock.bind(("", 0))

        try:
            sock.setsockopt(
                socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                socket.inet_aton(SSDP_MULTICAST) + socket.inet_aton(interface_ip or "0.0.0.0")
            )
        except Exception:
            pass

        listener_thread = threading.Thread(target=listener, args=(sock,), daemon=True)
        listener_thread.start()

        sock.sendto(search_bytes, (SSDP_MULTICAST, SSDP_PORT))
        try:
            sock.sendto(search_bytes, ("255.255.255.255", SSDP_PORT))
        except Exception:
            pass

        listener_thread.join(timeout=timeout)
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return devices


def _parse_ssdp_response(response: str, ip: str, port: int) -> Optional[SsdpDevice]:
    """Parse an SSDP response. Prefer IP from LOCATION header over source addr."""
    headers: Dict[str, str] = {}
    for line in response.split("\r\n"):
        idx = line.find(":")
        if idx > 0:
            key = line[:idx].strip().lower()
            val = line[idx + 1:].strip()
            headers[key] = val

    if not headers.get("location") and not headers.get("st"):
        return None

    # Extract IP from LOCATION header — more reliable than source addr
    location = headers.get("location", "")
    if location:
        try:
            from urllib.parse import urlparse
            parsed = urlparse(location)
            if parsed.hostname:
                ip = parsed.hostname
        except Exception:
            pass

    return SsdpDevice(
        ip=ip,
        port=port,
        location=location,
        st=headers.get("st", ""),
        server=headers.get("server", ""),
        usn=headers.get("usn", ""),
    )


# ─── TCP Port Scanner ───────────────────────────────────────────────

def scan_port(ip: str, port: int, timeout: float = 3.0) -> bool:
    """Check if a TCP port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def scan_ports(ip: str, ports: List[int] = None, timeout: float = 1.5,
               callback: Callable = None) -> List[int]:
    """Scan discovery-relevant TCP ports on a host.
    Ports for one device are probed concurrently (bounded, fast) but the
    orchestrator ensures only one device is fingerprinted at a time.
    Timeout reduced to 1.5 s: open ports on LAN reply in <10 ms; firewalled
    ports that don't RST are the only ones that hit the timeout ceiling."""
    if ports is None:
        ports = ALL_CAMERA_PORTS
    open_ports = _scan_port_batch(ip, ports, timeout)
    if callback:
        callback(len(ports), len(ports))
    return sorted(open_ports)


def _scan_port_batch(ip: str, ports: List[int], timeout: float) -> List[int]:
    """Probe all ports of a single device concurrently.
    This is bounded to len(ports) threads (≤ 12) — not a scalability concern."""
    open_ports: List[int] = []
    lock = threading.Lock()

    def check_port(port: int):
        if scan_port(ip, port, timeout):
            with lock:
                open_ports.append(port)

    threads = []
    for port in ports:
        t = threading.Thread(target=check_port, args=(port,), daemon=True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join(timeout=timeout + 0.5)

    return sorted(open_ports)


# ─── HTTP Banner Grab ───────────────────────────────────────────────

def grab_http_banner(ip: str, port: int = 80, timeout: float = 3.0) -> str:
    """Grab HTTP banner from a web server."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        request = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
        sock.sendall(request.encode("utf-8"))

        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if len(response) > 8192:
                    break
            except socket.timeout:
                break

        sock.close()
        return response.decode("utf-8", errors="replace")
    except Exception:
        return ""


def reverse_dns_name(ip: str, timeout: float = 1.5) -> str:
    """Best-effort reverse DNS lookup for generic host enrichment."""
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        host, _, _ = socket.gethostbyaddr(ip)
        return (host or "").strip().rstrip(".")
    except Exception:
        return ""
    finally:
        socket.setdefaulttimeout(old_timeout)


# ─── RTSP Probe ─────────────────────────────────────────────────────

@dataclass
class RtspResult:
    found: bool
    banner: str
    described: bool = False
    has_video_sdp: bool = False
    url: str = ""


def probe_rtsp(ip: str, port: int = 554, timeout: float = 3.0) -> RtspResult:
    """Probe an RTSP server with OPTIONS and a best-effort DESCRIBE."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        requests = [
            "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: CamDiscover/1.0\r\n\r\n",
            (
                f"DESCRIBE rtsp://{ip}:{port}/ RTSP/1.0\r\n"
                "CSeq: 2\r\n"
                "Accept: application/sdp\r\n"
                "User-Agent: CamDiscover/1.0\r\n\r\n"
            ),
        ]

        responses: list[str] = []
        for request in requests:
            sock.sendall(request.encode("utf-8"))
            response = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > 8192:
                        break
                    hdr_end = response.find(b"\r\n\r\n")
                    if hdr_end == -1:
                        continue          # headers not complete yet
                    # Parse Content-Length so we know whether a body follows.
                    # Without this, OPTIONS response data can leak into the
                    # subsequent DESCRIBE read because we break too early.
                    cl_m = re.search(rb"Content-Length:\s*(\d+)", response, re.IGNORECASE)
                    if not cl_m:
                        break             # no body — response complete
                    body_needed = int(cl_m.group(1))
                    if len(response) >= hdr_end + 4 + body_needed:
                        break             # full body received
                except socket.timeout:
                    break
            responses.append(response.decode("utf-8", errors="replace"))

        sock.close()
        combined = "\n".join(r for r in responses if r)
        lower = combined.lower()
        described = "describe" in lower and "rtsp/" in lower
        has_video_sdp = "m=video" in lower or "a=rtpmap" in lower
        return RtspResult(
            found="rtsp" in lower,
            banner=combined,
            described=described,
            has_video_sdp=has_video_sdp,
            url=f"rtsp://{ip}:{port}/",
        )
    except Exception:
        return RtspResult(found=False, banner="")


# ─── ONVIF Device Info (ODM-style) ──────────────────────────────────
# Like ONVIF Device Manager: query the device directly for real model,
# firmware, serial number, and proper RTSP stream URIs instead of guessing.

def _ws_security_header(username: str, password: str) -> str:
    """Build ONVIF WS-Security PasswordDigest header.

    ONVIF cameras require: PasswordDigest = Base64(SHA1(nonce + created + password))
    HTTP Basic/Digest auth is rejected by most cameras.
    """
    nonce_bytes = os.urandom(16)
    created = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    created_bytes = created.encode("utf-8")
    password_bytes = password.encode("utf-8")
    digest = base64.b64encode(
        hashlib.sha1(nonce_bytes + created_bytes + password_bytes).digest()
    ).decode("utf-8")
    nonce_b64 = base64.b64encode(nonce_bytes).decode("utf-8")
    return (
        '<s:Header>'
        '<Security s:mustUnderstand="1"'
        ' xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">'
        '<UsernameToken>'
        f'<Username>{username}</Username>'
        f'<Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">'
        f'{digest}</Password>'
        f'<Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">'
        f'{nonce_b64}</Nonce>'
        f'<Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">'
        f'{created}</Created>'
        '</UsernameToken>'
        '</Security>'
        '</s:Header>'
    )


def _onvif_soap(url: str, username: str, password: str, body_xml: str,
                timeout: float = 5.0) -> str:
    """Send a SOAP envelope to an ONVIF endpoint using WS-Security PasswordDigest."""
    security_header = _ws_security_header(username, password) if (username or password) else ""
    envelope = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
        ' xmlns:tds="http://www.onvif.org/ver10/device/wsdl"'
        ' xmlns:trt="http://www.onvif.org/ver10/media/wsdl"'
        ' xmlns:timg="http://www.onvif.org/ver20/imaging/wsdl"'
        ' xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl"'
        ' xmlns:tev="http://www.onvif.org/ver10/events/wsdl"'
        ' xmlns:tt="http://www.onvif.org/ver10/schema">'
        f'{security_header}'
        f'<s:Body>{body_xml}</s:Body>'
        '</s:Envelope>'
    )
    data = envelope.encode("utf-8")
    req = urllib.request.Request(
        url, data=data,
        headers={
            "Content-Type": 'application/soap+xml; charset=utf-8',
            "User-Agent": "CamDiscover/1.0",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read(131072).decode("utf-8", errors="replace")


@dataclass
class OnvifDeviceInfo:
    manufacturer: str = ""
    model: str = ""
    firmware: str = ""
    serial: str = ""
    hardware_id: str = ""
    stream_uris: List[str] = field(default_factory=list)
    error: str = ""


@dataclass
class OnvifDeviceAudit:
    manufacturer: str = ""
    model: str = ""
    firmware: str = ""
    serial: str = ""
    hardware_id: str = ""
    stream_uris: List[str] = field(default_factory=list)
    snapshot_uris: List[str] = field(default_factory=list)
    scopes: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    capabilities: List[str] = field(default_factory=list)
    media_profile_tokens: List[str] = field(default_factory=list)
    service_urls: Dict[str, str] = field(default_factory=dict)
    reported_ipv4_addresses: List[str] = field(default_factory=list)
    default_gateways: List[str] = field(default_factory=list)
    dns_servers: List[str] = field(default_factory=list)
    ntp_servers: List[str] = field(default_factory=list)
    system_datetime: str = ""
    user_count: int = 0
    supports_device: bool = False
    supports_media: bool = False
    supports_events: bool = False
    supports_imaging: bool = False
    supports_ptz: bool = False
    supports_analytics: bool = False
    checks: Dict[str, bool] = field(default_factory=dict)
    error: str = ""


def _xml_text(xml: str, tag: str) -> str:
    match = re.search(rf"<(?:\w+:)?{re.escape(tag)}[^>]*>(.*?)</(?:\w+:)?{re.escape(tag)}>", xml, re.DOTALL)
    if not match:
        return ""
    return re.sub(r"<[^>]+>", "", match.group(1)).strip()


def _xml_texts(xml: str, tag: str) -> List[str]:
    values: List[str] = []
    for match in re.finditer(rf"<(?:\w+:)?{re.escape(tag)}[^>]*>(.*?)</(?:\w+:)?{re.escape(tag)}>", xml, re.DOTALL):
        value = re.sub(r"<[^>]+>", "", match.group(1)).strip()
        if value and value not in values:
            values.append(value)
    return values


def _canonical_onvif_service(namespace: str) -> str:
    ns = (namespace or "").lower()
    if "device/wsdl" in ns:
        return "device"
    if "media/wsdl" in ns:
        return "media"
    if "events/wsdl" in ns:
        return "events"
    if "imaging/wsdl" in ns:
        return "imaging"
    if "ptz/wsdl" in ns:
        return "ptz"
    if "analytics/wsdl" in ns:
        return "analytics"
    return ""


def _candidate_service_urls(ip: str, onvif_url: str, service_urls: Dict[str, str], service_name: str) -> List[str]:
    candidates: List[str] = []
    explicit = service_urls.get(service_name, "")
    if explicit:
        candidates.append(explicit)
    if "device_service" in onvif_url:
        candidates.append(onvif_url.replace("device_service", f"{service_name}_service"))
    for port in (8899, 80, 8080):
        candidates.append(f"http://{ip}:{port}/onvif/{service_name}_service")
    unique: List[str] = []
    for item in candidates:
        if item and item not in unique:
            unique.append(item)
    return unique


def _record_support(audit: OnvifDeviceAudit) -> None:
    services = set(audit.services)
    caps = set(audit.capabilities)
    audit.supports_device = "device" in services or "device" in caps
    audit.supports_media = "media" in services or "media" in caps or bool(audit.media_profile_tokens)
    audit.supports_events = "events" in services or "events" in caps
    audit.supports_imaging = "imaging" in services or "imaging" in caps
    audit.supports_ptz = "ptz" in services or "ptz" in caps
    audit.supports_analytics = "analytics" in services or "analytics" in caps


def query_onvif_device_audit(
    ip: str,
    onvif_url: str = "",
    username: str = "admin",
    password: str = "",
    timeout: float = 5.0,
) -> OnvifDeviceAudit:
    """Run an ODM-style ONVIF capability audit against a discovered device."""
    if not onvif_url:
        onvif_url = f"http://{ip}:8899/onvif/device_service"

    audit = OnvifDeviceAudit()

    def _call(check_name: str, url: str, body_xml: str) -> str:
        try:
            response = _onvif_soap(url, username, password, body_xml, timeout=timeout)
            audit.checks[check_name] = True
            return response
        except Exception as exc:
            audit.checks[check_name] = False
            if not audit.error and check_name == "get_device_information":
                audit.error = str(exc)
            return ""

    device_info_resp = _call("get_device_information", onvif_url, "<tds:GetDeviceInformation/>")
    if not device_info_resp:
        return audit

    audit.manufacturer = _xml_text(device_info_resp, "Manufacturer")
    audit.model = _xml_text(device_info_resp, "Model")
    audit.firmware = _xml_text(device_info_resp, "FirmwareVersion")
    audit.serial = _xml_text(device_info_resp, "SerialNumber")
    audit.hardware_id = _xml_text(device_info_resp, "HardwareId")

    services_resp = _call("get_services", onvif_url, "<tds:GetServices><tds:IncludeCapability>false</tds:IncludeCapability></tds:GetServices>")
    if services_resp:
        for block in re.findall(r"<(?:\w+:)?Service\b[^>]*>(.*?)</(?:\w+:)?Service>", services_resp, re.DOTALL):
            namespace = _xml_text(block, "Namespace")
            xaddr = _xml_text(block, "XAddr")
            canonical = _canonical_onvif_service(namespace)
            if canonical:
                if canonical not in audit.services:
                    audit.services.append(canonical)
                if xaddr:
                    audit.service_urls[canonical] = xaddr

    capabilities_resp = _call("get_capabilities", onvif_url, "<tds:GetCapabilities><tds:Category>All</tds:Category></tds:GetCapabilities>")
    if capabilities_resp:
        for capability_name in ("device", "media", "events", "imaging", "ptz", "analytics"):
            if re.search(rf"<(?:\w+:)?{capability_name.capitalize()}\b", capabilities_resp, re.IGNORECASE):
                audit.capabilities.append(capability_name)

    scopes_resp = _call("get_scopes", onvif_url, "<tds:GetScopes/>")
    if scopes_resp:
        audit.scopes = _xml_texts(scopes_resp, "ScopeItem")

    network_resp = _call("get_network_interfaces", onvif_url, "<tds:GetNetworkInterfaces/>")
    if network_resp:
        audit.reported_ipv4_addresses = _xml_texts(network_resp, "IPv4Address")

    gateway_resp = _call("get_network_default_gateway", onvif_url, "<tds:GetNetworkDefaultGateway/>")
    if gateway_resp:
        audit.default_gateways = _xml_texts(gateway_resp, "IPv4Address")

    dns_resp = _call("get_dns", onvif_url, "<tds:GetDNS/>")
    if dns_resp:
        audit.dns_servers = _xml_texts(dns_resp, "IPv4Address")

    ntp_resp = _call("get_ntp", onvif_url, "<tds:GetNTP/>")
    if ntp_resp:
        audit.ntp_servers = _xml_texts(ntp_resp, "IPv4Address")

    dt_resp = _call("get_system_date_and_time", onvif_url, "<tds:GetSystemDateAndTime/>")
    if dt_resp:
        year = _xml_text(dt_resp, "Year")
        month = _xml_text(dt_resp, "Month")
        day = _xml_text(dt_resp, "Day")
        hour = _xml_text(dt_resp, "Hour")
        minute = _xml_text(dt_resp, "Minute")
        second = _xml_text(dt_resp, "Second")
        if all((year, month, day, hour, minute, second)):
            audit.system_datetime = f"{year.zfill(4)}-{month.zfill(2)}-{day.zfill(2)}T{hour.zfill(2)}:{minute.zfill(2)}:{second.zfill(2)}"

    users_resp = _call("get_users", onvif_url, "<tds:GetUsers/>")
    if users_resp:
        audit.user_count = len(re.findall(r"<(?:\w+:)?User\b", users_resp))

    media_urls = _candidate_service_urls(ip, onvif_url, audit.service_urls, "media")
    profiles_resp = ""
    media_url = ""
    for candidate in media_urls:
        profiles_resp = _call("get_profiles", candidate, "<trt:GetProfiles/>")
        if profiles_resp:
            media_url = candidate
            audit.service_urls.setdefault("media", candidate)
            break
    if profiles_resp:
        audit.media_profile_tokens = re.findall(
            r'<(?:\w+:)?Profiles\b[^>]*token="([^"]+)"',
            profiles_resp,
        )[:8]
        video_source_tokens = re.findall(r'VideoSourceConfiguration[^>]*token="([^"]+)"', profiles_resp)
        for token in audit.media_profile_tokens[:4]:
            stream_resp = _call(
                f"get_stream_uri:{token}",
                media_url,
                f"<trt:GetStreamUri><trt:StreamSetup><tt:Stream>RTP-Unicast</tt:Stream><tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport></trt:StreamSetup><trt:ProfileToken>{token}</trt:ProfileToken></trt:GetStreamUri>",
            )
            uri = _xml_text(stream_resp, "Uri")
            if uri.startswith("rtsp://") and uri not in audit.stream_uris:
                audit.stream_uris.append(uri)

            snapshot_resp = _call(
                f"get_snapshot_uri:{token}",
                media_url,
                f"<trt:GetSnapshotUri><trt:ProfileToken>{token}</trt:ProfileToken></trt:GetSnapshotUri>",
            )
            snapshot_uri = _xml_text(snapshot_resp, "Uri")
            if snapshot_uri and snapshot_uri not in audit.snapshot_uris:
                audit.snapshot_uris.append(snapshot_uri)

        _call("get_video_encoder_configurations", media_url, "<trt:GetVideoEncoderConfigurations/>")

        ptz_url = audit.service_urls.get("ptz") or media_url
        _call("get_ptz_configurations", ptz_url, "<tptz:GetConfigurations/>")

        imaging_urls = _candidate_service_urls(ip, onvif_url, audit.service_urls, "imaging")
        if video_source_tokens:
            for imaging_url in imaging_urls:
                imaging_resp = _call(
                    "get_imaging_settings",
                    imaging_url,
                    f"<timg:GetImagingSettings><timg:VideoSourceToken>{video_source_tokens[0]}</timg:VideoSourceToken></timg:GetImagingSettings>",
                )
                if imaging_resp:
                    audit.service_urls.setdefault("imaging", imaging_url)
                    break

    events_urls = _candidate_service_urls(ip, onvif_url, audit.service_urls, "events")
    for events_url in events_urls:
        events_resp = _call("get_event_properties", events_url, "<tev:GetEventProperties/>")
        if events_resp:
            audit.service_urls.setdefault("events", events_url)
            break

    _record_support(audit)
    return audit


def query_onvif_device_info(ip: str, onvif_url: str = "",
                             username: str = "admin", password: str = "",
                             timeout: float = 5.0) -> OnvifDeviceInfo:
    """
    Backward-compatible summary wrapper over the richer ONVIF capability audit.
    """
    audit = query_onvif_device_audit(ip, onvif_url, username, password, timeout=timeout)
    return OnvifDeviceInfo(
        manufacturer=audit.manufacturer,
        model=audit.model,
        firmware=audit.firmware,
        serial=audit.serial,
        hardware_id=audit.hardware_id,
        stream_uris=list(audit.stream_uris),
        error=audit.error,
    )


# ─── Dahua / Amcrest UDP Discovery ──────────────────────────────────

# Dahua cameras listen on UDP 37020 for a specific broadcast probe.
# Amcrest is an OEM of Dahua and uses the same protocol.
_DAHUA_PROBE = bytes.fromhex(
    "ff010000"   # magic
    "00000000"   # sequence
    "00000000"   # padding
    "00000000"
)


def send_dahua_probe(interface_ip: str = "", timeout: float = 3.0) -> List[dict]:
    """
    Broadcast Dahua/Amcrest UDP discovery on port 37020 and collect responses.
    Returns list of dicts with keys: ip, mac, sn, name, version.
    """
    found: List[dict] = []
    seen: set = set()
    lock = threading.Lock()

    def _listen(sock: socket.socket):
        sock.settimeout(timeout)
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(2048)
                ip = addr[0]
                with lock:
                    if ip in seen:
                        continue
                    seen.add(ip)
                info = _parse_dahua_response(data, ip)
                with lock:
                    found.append(info)
            except socket.timeout:
                break
            except Exception:
                continue

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        if interface_ip:
            try:
                sock.bind((interface_ip, 0))
            except Exception:
                sock.bind(("", 0))
        else:
            sock.bind(("", 0))

        listener_t = threading.Thread(target=_listen, args=(sock,), daemon=True)
        listener_t.start()

        sock.sendto(_DAHUA_PROBE, ("255.255.255.255", 37020))

        listener_t.join(timeout=timeout)
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return found


def _parse_dahua_response(data: bytes, ip: str) -> dict:
    """Parse a Dahua UDP discovery response into a dict."""
    result = {"ip": ip, "mac": "", "sn": "", "name": "", "version": ""}
    try:
        text = data.decode("utf-8", errors="replace")
        # Dahua responses are sometimes XML-like or have ASCII fields
        mac_m = re.search(r"([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}", text)
        if mac_m:
            result["mac"] = mac_m.group(0).replace("-", ":").lower()
        sn_m = re.search(r"SN[:\s=]+([A-Za-z0-9\-]+)", text)
        if sn_m:
            result["sn"] = sn_m.group(1)
        name_m = re.search(r"Name[:\s=]+([A-Za-z0-9_\-]+)", text)
        if name_m:
            result["name"] = name_m.group(1)
        ver_m = re.search(r"Version[:\s=]+([^\s<&]+)", text)
        if ver_m:
            result["version"] = ver_m.group(1)
    except Exception:
        pass
    return result


# ─── Passive Listener ───────────────────────────────────────────────

class PassiveListener:
    """Listen for ONVIF and SSDP multicast traffic passively."""

    def __init__(self):
        self.running = False
        self._threads: List[threading.Thread] = []
        self._sockets: List[socket.socket] = []
        self.on_onvif: Optional[Callable[[str, str], None]] = None
        self.on_ssdp: Optional[Callable[[str, str], None]] = None
        self.on_dahua: Optional[Callable[[str, bytes], None]] = None

    def start(self, interface_ip: str = ""):
        """Start passive listening."""
        self.running = True

        # ONVIF listener
        t = threading.Thread(target=self._listen_onvif, args=(interface_ip,), daemon=True)
        t.start()
        self._threads.append(t)

        # SSDP listener
        t = threading.Thread(target=self._listen_ssdp, args=(interface_ip,), daemon=True)
        t.start()
        self._threads.append(t)

        # Dahua/Amcrest listener
        t = threading.Thread(target=self._listen_dahua, args=(interface_ip,), daemon=True)
        t.start()
        self._threads.append(t)

    def stop(self):
        """Stop passive listening."""
        self.running = False
        for sock in self._sockets:
            try:
                sock.close()
            except Exception:
                pass
        for t in self._threads:
            t.join(timeout=2)

    def _listen_onvif(self, interface_ip: str):
        """Listen for ONVIF WS-Discovery traffic."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("", 3702))

            try:
                sock.setsockopt(
                    socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                    socket.inet_aton("239.255.255.250") + socket.inet_aton(interface_ip or "0.0.0.0")
                )
            except Exception:
                pass

            self._sockets.append(sock)
            sock.settimeout(1.0)

            while self.running:
                try:
                    data, addr = sock.recvfrom(65535)
                    response = data.decode("utf-8", errors="replace")
                    if "soap-envelope" in response or "discovery" in response.lower():
                        if self.on_onvif:
                            self.on_onvif(addr[0], response)
                except socket.timeout:
                    continue
                except Exception:
                    continue
        except Exception:
            pass

    def _listen_dahua(self, interface_ip: str):
        """Listen for Dahua/Amcrest UDP discovery responses on port 37020."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            if interface_ip:
                try:
                    sock.bind((interface_ip, 37020))
                except OSError:
                    sock.bind(("", 37020))
            else:
                sock.bind(("", 37020))
            self._sockets.append(sock)
            sock.settimeout(1.0)
            while self.running:
                try:
                    data, addr = sock.recvfrom(65535)
                    if data and addr[0]:
                        if self.on_dahua:
                            self.on_dahua(addr[0], data)
                except socket.timeout:
                    continue
                except Exception:
                    continue
        except Exception:
            pass

    def _listen_ssdp(self, interface_ip: str):
        """Listen for SSDP NOTIFY traffic."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("", 1900))

            try:
                sock.setsockopt(
                    socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                    socket.inet_aton("239.255.255.250") + socket.inet_aton(interface_ip or "0.0.0.0")
                )
            except Exception:
                pass

            self._sockets.append(sock)
            sock.settimeout(1.0)

            while self.running:
                try:
                    data, addr = sock.recvfrom(65535)
                    response = data.decode("utf-8", errors="replace")
                    if "NOTIFY" in response or "HTTP/1.1" in response:
                        if self.on_ssdp:
                            self.on_ssdp(addr[0], response)
                except socket.timeout:
                    continue
                except Exception:
                    continue
        except Exception:
            pass


# ─── mDNS Active Probe ───────────────────────────────────────────────

@dataclass
class MdnsDevice:
    ip: str
    service_type: str = ""
    name: str = ""
    port: int = 0
    raw_response: str = ""


def send_mdns_probe(interface_ip: str = "", timeout: float = 3.0) -> List[MdnsDevice]:
    """Send active mDNS queries for camera-related service types.

    mDNS (RFC 6762) queries multicast 224.0.0.251:5353 for:
      _onvif._tcp.local       — ONVIF cameras
      _rtsp._tcp.local        — RTSP servers
      _axis-video._tcp.local  — Axis cameras
      _hikvision._tcp.local   — Hikvision devices (non-standard)
    """
    MDNS_MULTICAST = "224.0.0.251"
    MDNS_PORT = 5353

    camera_services = [
        "_onvif._tcp.local",
        "_rtsp._tcp.local",
        "_axis-video._tcp.local",
        "_hikvision._tcp.local",
    ]

    devices: List[MdnsDevice] = []
    seen: set = set()
    lock = threading.Lock()

    def build_mdns_query(name: str) -> bytes:
        header = struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0)
        qname = b""
        for label in name.split("."):
            qname += struct.pack("B", len(label)) + label.encode("ascii")
        qname += b"\x00"
        question = qname + struct.pack("!HH", 12, 1)  # PTR, IN
        return header + question

    def listener(sock: socket.socket):
        sock.settimeout(timeout)
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(65535)
                if len(data) < 12:
                    continue
                src_ip = addr[0]
                flags = struct.unpack("!H", data[2:4])[0]
                if not (flags & 0x8000):
                    continue
                device = _parse_mdns_response(data, src_ip)
                if device:
                    key = (device.ip, device.service_type)
                    with lock:
                        if key not in seen:
                            seen.add(key)
                            devices.append(device)
            except socket.timeout:
                break
            except Exception:
                continue

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if interface_ip:
            try:
                sock.setsockopt(
                    socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                    socket.inet_aton(interface_ip)
                )
            except Exception:
                pass
        try:
            sock.bind(("", 0))
        except OSError:
            sock.bind(("", 5353))
        try:
            sock.setsockopt(
                socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                socket.inet_aton(MDNS_MULTICAST) + socket.inet_aton(interface_ip or "0.0.0.0")
            )
        except Exception:
            pass

        listener_thread = threading.Thread(target=listener, args=(sock,), daemon=True)
        listener_thread.start()

        for svc in camera_services:
            try:
                query = build_mdns_query(svc)
                sock.sendto(query, (MDNS_MULTICAST, MDNS_PORT))
            except Exception:
                pass

        listener_thread.join(timeout=timeout)
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return devices


def _parse_mdns_response(data: bytes, src_ip: str) -> Optional[MdnsDevice]:
    try:
        if len(data) < 12:
            return None
        qdcount = struct.unpack("!H", data[4:6])[0]
        ancount = struct.unpack("!H", data[6:8])[0]
        if ancount == 0:
            return None

        pos = 12
        for _ in range(qdcount):
            while pos < len(data):
                label_len = data[pos]
                pos += 1
                if label_len == 0:
                    break
                pos += label_len
            pos += 4

        for _ in range(ancount):
            if pos + 10 > len(data):
                break
            while pos < len(data):
                label_len = data[pos]
                if label_len == 0:
                    pos += 1
                    break
                if label_len >= 0xC0:
                    pos += 2
                    break
                pos += 1 + label_len
            rtype = struct.unpack("!H", data[pos:pos+2])[0]
            pos += 2
            pos += 2  # class
            pos += 4  # ttl
            rdlength = struct.unpack("!H", data[pos:pos+2])[0]
            pos += 2
            rdata = data[pos:pos+rdlength]
            pos += rdlength

            if rtype == 12:  # PTR record
                try:
                    ptr_name = _decode_dns_name(data, rdata)
                    return MdnsDevice(
                        ip=src_ip,
                        service_type=_extract_service_type(ptr_name),
                        name=ptr_name,
                        raw_response=data[:200].hex(),
                    )
                except Exception:
                    pass
        return None
    except Exception:
        return None


def _decode_dns_name(full_packet: bytes, name_data: bytes) -> str:
    labels = []
    pos_in_rd = 0
    seen_ptrs = set()
    while pos_in_rd < len(name_data):
        label_len = name_data[pos_in_rd]
        if label_len == 0:
            break
        if label_len >= 0xC0:
            pointer = ((label_len & 0x3F) << 8) | name_data[pos_in_rd + 1]
            if pointer in seen_ptrs or pointer >= len(full_packet):
                break
            seen_ptrs.add(pointer)
            sub = _decode_dns_name(full_packet, full_packet[pointer:])
            if sub:
                labels.append(sub)
            break
        else:
            pos_in_rd += 1
            label = name_data[pos_in_rd:pos_in_rd + label_len]
            try:
                labels.append(label.decode("ascii", errors="replace"))
            except Exception:
                pass
            pos_in_rd += label_len
    return ".".join(labels)


def _extract_service_type(name: str) -> str:
    lower = name.lower()
    for svc in ("_onvif._tcp", "_rtsp._tcp", "_axis-video._tcp", "_hikvision._tcp"):
        if svc in lower:
            return svc + ".local"
    return name
