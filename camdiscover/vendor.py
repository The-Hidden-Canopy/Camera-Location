"""MAC OUI vendor lookup, camera fingerprinting, and generic device typing."""

from __future__ import annotations
from dataclasses import dataclass
from typing import List


# Curated OUI database for camera & network vendors
OUI_DB: dict[str, str] = {
    # Amcrest / Dahua
    "3c:ef:8c": "Dahua/Amcrest",
    "40:2c:76": "Dahua/Amcrest",
    "4c:11:bf": "Dahua/Amcrest",       # also used by Uniview OEM
    "48:34:29": "Dahua/Amcrest",
    "a0:bd:1d": "Dahua/Amcrest",       # also used by Uniview OEM
    "e0:50:8b": "Dahua/Amcrest",       # also used by Hanwha OEM
    "f8:4d:fc": "Dahua/Amcrest",       # also used by Uniview OEM
    "90:02:a9": "Dahua/Amcrest",
    "38:af:29": "Dahua/Amcrest",
    "20:17:42": "Dahua/Amcrest",
    "e4:e2:24": "Dahua/Amcrest",
    "2c:39:96": "Dahua/Amcrest",
    "58:60:5f": "Dahua/Amcrest",
    "f0:ad:4e": "Dahua/Amcrest",
    "9c:8e:cd": "Dahua/Amcrest",
    "a0:60:32": "Dahua/Amcrest",

    # Hikvision
    "18:68:cb": "Hikvision",
    "28:57:be": "Hikvision",
    "34:e4:2a": "Hikvision",
    "44:19:b6": "Hikvision",
    "54:e4:bd": "Hikvision",
    "60:5b:c4": "Hikvision",
    "6c:b9:5b": "Hikvision",
    "7c:49:eb": "Hikvision",       # also used by some Reolink OEM boards
    "a4:14:37": "Hikvision",
    "c0:56:e3": "Hikvision",       # also used by some Dahua OEM boards
    "ec:17:2f": "Hikvision",
    "b0:c5:ca": "Hikvision",       # also used by Dahua/Amcrest & Reolink OEM
    "d4:43:a8": "Hikvision",       # also used by Dahua/Amcrest & Hanwha OEM
    "fc:9f:fd": "Hikvision",
    "3c:1b:f8": "Hikvision",
    "54:8c:81": "Hikvision",
    "24:48:45": "Hikvision",
    "98:f1:12": "Hikvision",
    "24:28:fd": "Hikvision",
    "4c:f5:dc": "Hikvision",

    # Axis
    "00:40:8c": "Axis",
    "ac:cc:8e": "Axis",
    "b8:a4:4f": "Axis",
    "00:08:51": "Axis",
    "e8:43:5e": "Axis",

    # Hanwha / Wisenet
    "00:09:18": "Hanwha/Wisenet",
    "e0:50:8b": "Hanwha/Wisenet",
    "d4:43:a8": "Hanwha/Wisenet",

    # Bosch
    "00:0a:7a": "Bosch",
    "00:40:93": "Bosch",

    # Uniview
    "4c:11:bf": "Uniview",
    "a0:bd:1d": "Uniview",
    "f8:4d:fc": "Uniview",

    # Reolink
    "b0:c5:ca": "Reolink",
    "7c:49:eb": "Reolink",

    # Vivotek
    "00:02:d1": "Vivotek",
    "00:17:e3": "Vivotek",
    "b8:a4:2d": "Vivotek",

    # Avigilon
    "00:26:7e": "Avigilon",
    "c8:2a:14": "Avigilon",

    # Lorex
    "28:ef:01": "Lorex",
    "50:2d:8b": "Lorex",

    # Infrastructure (useful for filtering)
    "00:1a:2b": "Ubiquiti",
    "24:5a:4c": "Ubiquiti",
    "78:8a:20": "Ubiquiti",
    "f0:9f:c2": "Ubiquiti",
    "fc:ec:da": "Ubiquiti",
    "00:15:5d": "Microsoft Hyper-V",
    "00:50:56": "VMware",
    "00:0c:29": "VMware",
    "00:1c:42": "Parallels",
}


def lookup_vendor(mac: str) -> str:
    """Look up vendor from MAC address using OUI prefix."""
    if not mac or mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return "Unknown"
    normalized = mac.lower().replace("-", ":").replace(".", ":")
    oui = ":".join(normalized.split(":")[:3])
    return OUI_DB.get(oui, "Unknown")


@dataclass
class FingerprintResult:
    vendor: str
    model: str
    confidence: int
    protocols: List[str]


@dataclass
class DeviceTypeResult:
    device_type: str
    confidence: int
    warn_reset: bool = False


def fingerprint_device(
    mac: str,
    open_ports: List[int],
    http_banner: str = "",
    onvif_response: str = "",
) -> FingerprintResult:
    """Fingerprint a device based on MAC, ports, and protocol responses."""
    mac_vendor = lookup_vendor(mac)
    result = FingerprintResult(
        vendor=mac_vendor if mac_vendor != "Unknown" else "",
        model="",
        confidence=0,
        protocols=[],
    )

    # Port-based fingerprinting
    if 37777 in open_ports or 37778 in open_ports:
        if not result.vendor:
            result.vendor = "Dahua/Amcrest"
        result.protocols.append("Dahua SDK")
        result.confidence += 30

    if 8000 in open_ports:
        if not result.vendor:
            result.vendor = "Hikvision"
        result.protocols.append("Hikvision SDK")
        result.confidence += 25

    if 554 in open_ports:
        result.protocols.append("RTSP")
        result.confidence += 15

    if 8899 in open_ports:
        result.protocols.append("ONVIF")
        result.confidence += 20

    if 80 in open_ports or 8080 in open_ports:
        result.protocols.append("HTTP")
        result.confidence += 10

    if 443 in open_ports:
        result.protocols.append("HTTPS")
        result.confidence += 10

    # Banner-based fingerprinting
    banner_lower = http_banner.lower()
    vendor_keywords = {
        "hikvision": "Hikvision",
        "dvr": "Hikvision",
        "ivms": "Hikvision",
        "dahua": "Dahua/Amcrest",
        "amcrest": "Dahua/Amcrest",
        "axis": "Axis",
        "vivotek": "Vivotek",
        "reolink": "Reolink",
        "uniview": "Uniview",
        "hanwha": "Hanwha/Wisenet",
        "wisenet": "Hanwha/Wisenet",
        "bosch": "Bosch",
        "avigilon": "Avigilon",
        "lorex": "Lorex",
    }
    for keyword, vendor in vendor_keywords.items():
        if keyword in banner_lower:
            result.vendor = vendor
            result.confidence += 40
            break

    # ONVIF response fingerprinting
    if onvif_response:
        onvif_lower = onvif_response.lower()
        for keyword, vendor in vendor_keywords.items():
            if keyword in onvif_lower:
                result.vendor = vendor
                result.confidence += 35
                break

        # Extract model from ONVIF scopes
        import re
        name_match = re.search(r"name/([\w-]+)", onvif_response)
        if name_match:
            result.model = name_match.group(1)
        hw_match = re.search(r"hardware/([\w-]+)", onvif_response)
        if hw_match:
            result.model = result.model or hw_match.group(1)
        scopes_match = re.search(r"<d:Scopes>(.*?)</d:Scopes>", onvif_response, re.DOTALL)
        if scopes_match:
            scopes = scopes_match.group(1)
            name_m = re.search(r"onvif://www\.onvif\.org/name/(.+?)(?:\s|</)", scopes)
            if name_m:
                from urllib.parse import unquote
                result.model = unquote(name_m.group(1))
            mfr_m = re.search(r"onvif://www\.onvif\.org/manufacturer/(.+?)(?:\s|</)", scopes)
            if mfr_m and result.vendor == "Unknown":
                from urllib.parse import unquote
                result.vendor = unquote(mfr_m.group(1))

    # MAC vendor confirmation
    if mac_vendor != "Unknown":
        if result.vendor and mac_vendor.split("/")[0] in result.vendor:
            result.confidence += 20
        elif not result.vendor:
            result.vendor = mac_vendor
            result.confidence += 25

    # Camera confidence heuristic
    camera_ports = {80, 443, 554, 8000, 8080, 8899, 37777, 37778}
    camera_port_count = len([p for p in open_ports if p in camera_ports])
    if camera_port_count >= 3:
        result.confidence += 20
    elif camera_port_count >= 2:
        result.confidence += 10

    result.confidence = min(result.confidence, 100)
    return result


def classify_device_type(
    vendor: str,
    open_ports: List[int],
    protocols: List[str],
    http_banner: str = "",
    model: str = "",
    hostname: str = "",
    camera_confidence: int = 0,
) -> DeviceTypeResult:
    """Classify a discovered host using ordered evidence tiers.

    Resolution order (most specific/authoritative first):
      1. Explicit infrastructure identity  — protect bridges, routers, switches
      2. Explicit printer/endpoint identity
      3. NVR identity
      4. Confirmed camera protocol evidence (camera_confidence, NOT bare TCP 554)
      5. Camera-port hint (554 present AND no strong non-camera signal)
      6. Ambiguous network device / unknown

    A device is never classified as a camera solely because TCP 554 is open —
    infrastructure devices can expose port 554 for RTSP-based management.
    """
    vendor_l = (vendor or "").lower()
    banner_l = (http_banner or "").lower()
    model_l = (model or "").lower()
    host_l = (hostname or "").lower()
    proto_l = " ".join((protocols or [])).lower()
    port_set = set(open_ports or [])
    joined = " ".join(part for part in (vendor_l, banner_l, model_l, host_l, proto_l) if part)

    printer_ports = {631, 9100}
    endpoint_ports = {445, 3389}
    infra_ports = {22, 23, 53}

    # ── Tier 1: Explicit infrastructure ──────────────────────────────────────
    # Checked before camera so a Ubiquiti radio exposing RTSP-like port 554
    # doesn't get misclassified as a camera.  Uses "bridge" to match the
    # protected-class set in seeds.WARN_RESET_CLASSES.
    _INFRA_TOKENS = (
        "ubiquiti", "unifi", "airmax", "nanobeam", "nanostation",
        "mikrotik", "routerboard",
        "cisco", "catalyst", "meraki",
        "juniper", "aruba", "fortinet", "sophos", "pfsense", "opnsense",
        "router", "gateway", "firewall",
        "switch", "access point", "access_point",
    )
    if any(token in joined for token in _INFRA_TOKENS):
        # Distinguish bridges (wireless uplinks) from routers/switches
        if any(t in joined for t in ("bridge", "nanobeam", "nanostation", "airbridge", "airmax")):
            return DeviceTypeResult("bridge", 82, warn_reset=True)
        if any(t in joined for t in ("switch", "catalyst")):
            return DeviceTypeResult("switch", 80, warn_reset=True)
        if any(t in joined for t in ("router", "gateway", "firewall", "mikrotik", "fortinet",
                                     "sophos", "pfsense", "opnsense")):
            return DeviceTypeResult("router", 80, warn_reset=True)
        return DeviceTypeResult("bridge", 76, warn_reset=True)   # generic infra

    if port_set.intersection(infra_ports) and any(t in joined for t in (
            "controller", "gateway", "router", "switch", "dns", "ap")):
        return DeviceTypeResult("router", 72, warn_reset=True)

    # ── Tier 2: Printer / endpoint ────────────────────────────────────────────
    if port_set.intersection(printer_ports) or any(t in joined for t in (
            "printer", "laserjet", "deskjet", "xerox", "brother", "canon", "epson")):
        return DeviceTypeResult("printer", 80)

    if any(t in joined for t in ("vmware", "hyper-v", "parallels", "virtualbox")):
        return DeviceTypeResult("server", 80, warn_reset=True)

    if port_set.intersection(endpoint_ports) and any(t in joined for t in (
            "desktop", "laptop", "windows", "workstation")):
        return DeviceTypeResult("server", 65, warn_reset=True)

    # ── Tier 3: NVR identity ──────────────────────────────────────────────────
    if any(t in joined for t in ("nvr", "dvr", "network video recorder", "digital video recorder")):
        return DeviceTypeResult("nvr", 85, warn_reset=True)

    if port_set.intersection({22, 161, 162, 179, 443}) and any(t in joined for t in (
            "server", "nas", "synology", "qnap")):
        return DeviceTypeResult("server", 70, warn_reset=True)

    # ── Tier 4: Confirmed camera (protocol evidence) ──────────────────────────
    # Require camera_confidence ≥ 50 — i.e. at least one strong camera protocol
    # signal (ONVIF, RTSP DESCRIBE, SADP, Dahua, camera HTTP banner, etc.).
    # Bare TCP 554 alone = only 12 points, insufficient.
    if camera_confidence >= 50:
        return DeviceTypeResult("camera", camera_confidence)

    # ── Tier 5: Camera-port hint — keep as candidate, not confirmed ───────────
    # TCP 554/8554/8899 open but no strong protocol evidence yet.  Return camera
    # with a low score so further probing can upgrade it.
    if port_set.intersection({554, 8554, 8899}):
        return DeviceTypeResult("camera", max(camera_confidence, 30))

    if vendor_l not in ("unknown", ""):
        return DeviceTypeResult("unknown", 45)

    return DeviceTypeResult("unknown", 15)
