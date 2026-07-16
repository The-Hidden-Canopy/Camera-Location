"""MAC OUI vendor lookup, camera fingerprinting, and device classification."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from .asset_taxonomy import (
    infer_asset_class,
    infer_criticality,
    infer_operational_role,
    infer_reset_risk,
)


# Curated OUI database for camera and network vendors.
OUI_DB: dict[str, str] = {
    # Amcrest / Dahua
    "3c:ef:8c": "Dahua/Amcrest",
    "40:2c:76": "Dahua/Amcrest",
    "4c:11:bf": "Dahua/Amcrest",  # also used by Uniview OEM
    "48:34:29": "Dahua/Amcrest",
    "a0:bd:1d": "Dahua/Amcrest",  # also used by Uniview OEM
    "e0:50:8b": "Dahua/Amcrest",  # also used by Hanwha OEM
    "f8:4d:fc": "Dahua/Amcrest",  # also used by Uniview OEM
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
    "7c:49:eb": "Hikvision",  # also used by some Reolink OEM boards
    "a4:14:37": "Hikvision",
    "c0:56:e3": "Hikvision",  # also used by some Dahua OEM boards
    "ec:17:2f": "Hikvision",
    "b0:c5:ca": "Hikvision",  # also used by Dahua/Amcrest and Reolink OEM
    "d4:43:a8": "Hikvision",  # also used by Dahua/Amcrest and Hanwha OEM
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

    # Infrastructure
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
    rationale: str = ""
    asset_class: str = ""
    operational_role: str = ""
    reset_risk: str = ""
    criticality: str = ""
    evidence: List[str] = field(default_factory=list)


def _rationale(tier: int, reason: str) -> str:
    return f"Tier {tier}: {reason}"


def _device_type_result(
    device_type: str,
    confidence: int,
    *,
    warn_reset: bool = False,
    rationale: str = "",
    vendor: str = "",
    model: str = "",
    hostname: str = "",
    asset_class: str = "",
    operational_role: str = "",
    reset_risk: str = "",
    evidence: List[str] | None = None,
) -> DeviceTypeResult:
    resolved_asset_class = asset_class or infer_asset_class(
        device_type,
        vendor=vendor,
        model=model,
        hostname=hostname,
    )
    resolved_role = operational_role or infer_operational_role(
        resolved_asset_class,
        vendor=vendor,
        model=model,
        hostname=hostname,
    )
    resolved_reset_risk = infer_reset_risk(resolved_asset_class, reset_risk)
    resolved_criticality = infer_criticality(resolved_asset_class, resolved_reset_risk)
    unique_evidence: List[str] = []
    for item in evidence or []:
        if item and item not in unique_evidence:
            unique_evidence.append(item)
    return DeviceTypeResult(
        device_type=device_type,
        confidence=confidence,
        warn_reset=warn_reset or resolved_reset_risk in ("high", "critical"),
        rationale=rationale,
        asset_class=resolved_asset_class,
        operational_role=resolved_role,
        reset_risk=resolved_reset_risk,
        criticality=resolved_criticality,
        evidence=unique_evidence,
    )


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
    for keyword, detected_vendor in vendor_keywords.items():
        if keyword in banner_lower:
            result.vendor = detected_vendor
            result.confidence += 40
            break

    if onvif_response:
        onvif_lower = onvif_response.lower()
        for keyword, detected_vendor in vendor_keywords.items():
            if keyword in onvif_lower:
                result.vendor = detected_vendor
                result.confidence += 35
                break

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
            name_match = re.search(r"onvif://www\.onvif\.org/name/(.+?)(?:\s|</)", scopes)
            if name_match:
                from urllib.parse import unquote

                result.model = unquote(name_match.group(1))
            manufacturer_match = re.search(
                r"onvif://www\.onvif\.org/manufacturer/(.+?)(?:\s|</)",
                scopes,
            )
            if manufacturer_match and result.vendor == "Unknown":
                from urllib.parse import unquote

                result.vendor = unquote(manufacturer_match.group(1))

    if mac_vendor != "Unknown":
        if result.vendor and mac_vendor.split("/")[0] in result.vendor:
            result.confidence += 20
        elif not result.vendor:
            result.vendor = mac_vendor
            result.confidence += 25

    camera_ports = {80, 443, 554, 8000, 8080, 8899, 37777, 37778}
    camera_port_count = len([port for port in open_ports if port in camera_ports])
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

    Resolution order:
      1. Explicit infrastructure identity
      2. Explicit printer or endpoint identity
      3. NVR identity
      4. Confirmed camera protocol evidence
      5. Camera-port hint
      6. Ambiguous network device or unknown

    A device is never classified as a camera solely because TCP 554 is open.
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
    identity_evidence: List[str] = []
    if vendor and vendor != "Unknown":
        identity_evidence.append(f"vendor={vendor}")
    if model:
        identity_evidence.append(f"model={model}")
    if hostname:
        identity_evidence.append(f"hostname={hostname}")

    infra_tokens = (
        "ubiquiti",
        "unifi",
        "airmax",
        "nanobeam",
        "nanostation",
        "litebeam",
        "powerbeam",
        "liteap",
        "rocket prism",
        "mikrotik",
        "routerboard",
        "cisco",
        "catalyst",
        "meraki",
        "antaira",
        "fs.com",
        "juniper",
        "aruba",
        "fortinet",
        "sophos",
        "pfsense",
        "opnsense",
        "router",
        "gateway",
        "firewall",
        "switch",
        "access point",
        "access_point",
    )
    if any(token in joined for token in infra_tokens):
        if any(token in joined for token in ("liteap", "uap", "access point", "sector", "rocket prism")):
            return _device_type_result(
                "bridge",
                84,
                warn_reset=True,
                rationale=_rationale(1, "infra keyword match (wireless AP)"),
                vendor=vendor,
                model=model,
                hostname=hostname,
                asset_class="access_point",
                operational_role="backhaul_hub",
                reset_risk="critical",
                evidence=identity_evidence + [
                    "wireless infrastructure keywords indicate AP/sector role",
                ],
            )
        if any(
            token in joined
            for token in ("bridge", "nanobeam", "nanostation", "litebeam", "powerbeam", "airbridge", "airmax")
        ):
            return _device_type_result(
                "bridge",
                82,
                warn_reset=True,
                rationale=_rationale(1, "infra keyword match (wireless bridge)"),
                vendor=vendor,
                model=model,
                hostname=hostname,
                asset_class="wireless_bridge",
                operational_role="remote_bridge",
                reset_risk="critical",
                evidence=identity_evidence + [
                    "wireless infrastructure keywords indicate bridge/uplink role",
                ],
            )
        if any(
            token in joined
            for token in ("switch", "catalyst", "antaira", "fs.com", "edge switch", "edgeswitch")
        ):
            asset_class = "poe_switch" if any(token in joined for token in ("poe", "antaira")) else "managed_switch"
            return _device_type_result(
                "switch",
                80,
                warn_reset=True,
                rationale=_rationale(1, "infra keyword match (switch)"),
                vendor=vendor,
                model=model,
                hostname=hostname,
                asset_class=asset_class,
                operational_role="poe_source" if asset_class == "poe_switch" else "",
                reset_risk="high",
                evidence=identity_evidence + [
                    "switch platform keywords present",
                ],
            )
        if any(
            token in joined
            for token in ("router", "gateway", "firewall", "mikrotik", "fortinet", "sophos", "pfsense", "opnsense")
        ):
            return _device_type_result(
                "router",
                80,
                warn_reset=True,
                rationale=_rationale(1, "infra keyword match (router/gateway)"),
                vendor=vendor,
                model=model,
                hostname=hostname,
                asset_class="router_firewall",
                operational_role="network_gateway",
                reset_risk="critical",
                evidence=identity_evidence + [
                    "gateway or firewall keywords present",
                ],
            )
        return _device_type_result(
            "bridge",
            76,
            warn_reset=True,
            rationale=_rationale(1, "infra keyword match (generic)"),
            vendor=vendor,
            model=model,
            hostname=hostname,
            evidence=identity_evidence + [
                "infrastructure keywords present without more specific role evidence",
            ],
        )

    if port_set.intersection(infra_ports) and any(
        token in joined for token in ("controller", "gateway", "router", "switch", "dns", "ap")
    ):
        return _device_type_result(
            "router",
            72,
            warn_reset=True,
            rationale=_rationale(1, "infra ports + keyword"),
            vendor=vendor,
            model=model,
            hostname=hostname,
            asset_class="router_firewall",
            operational_role="network_gateway",
            reset_risk="critical",
            evidence=identity_evidence + [
                "infra ports combined with gateway/controller keywords",
            ],
        )

    if port_set.intersection(printer_ports) or any(
        token in joined for token in ("printer", "laserjet", "deskjet", "xerox", "brother", "canon", "epson")
    ):
        return _device_type_result(
            "printer",
            80,
            rationale=_rationale(2, "printer ports or keyword"),
            vendor=vendor,
            model=model,
            hostname=hostname,
            evidence=identity_evidence + [
                "printer service ports or printer model keyword present",
            ],
        )

    if any(token in joined for token in ("vmware", "hyper-v", "parallels", "virtualbox")):
        return _device_type_result(
            "server",
            80,
            warn_reset=True,
            rationale=_rationale(2, "virtualisation keyword"),
            vendor=vendor,
            model=model,
            hostname=hostname,
            asset_class="server_nas",
            reset_risk="high",
            evidence=identity_evidence + [
                "virtualisation platform keyword present",
            ],
        )

    if port_set.intersection(endpoint_ports) and any(
        token in joined for token in ("desktop", "laptop", "windows", "workstation")
    ):
        return _device_type_result(
            "server",
            65,
            rationale=_rationale(2, "endpoint ports + keyword"),
            vendor=vendor,
            model=model,
            hostname=hostname,
            asset_class="workstation",
            operational_role="installer_laptop" if "laptop" in joined else "workstation",
            reset_risk="low",
            evidence=identity_evidence + [
                "endpoint ports combined with workstation keywords",
            ],
        )

    if any(token in joined for token in ("petrocloud", "twenty20")):
        return _device_type_result(
            "server",
            72,
            warn_reset=True,
            rationale=_rationale(2, "legacy controller keyword"),
            vendor=vendor,
            model=model,
            hostname=hostname,
            asset_class="legacy_video_appliance",
            operational_role="legacy_controller",
            reset_risk="high",
            evidence=identity_evidence + [
                "legacy video appliance keyword present",
            ],
        )

    if any(token in joined for token in ("raspberry", "relay", "controller")):
        return _device_type_result(
            "server",
            60,
            rationale=_rationale(2, "controller keyword"),
            vendor=vendor,
            model=model,
            hostname=hostname,
            asset_class="iot_controller",
            reset_risk="moderate",
            evidence=identity_evidence + [
                "embedded controller keyword present",
            ],
        )

    if any(token in joined for token in ("nvr", "dvr", "network video recorder", "digital video recorder")):
        return _device_type_result(
            "nvr",
            85,
            warn_reset=True,
            rationale=_rationale(3, "NVR/DVR keyword"),
            vendor=vendor,
            model=model,
            hostname=hostname,
            reset_risk="critical",
            evidence=identity_evidence + [
                "NVR or DVR keyword present",
            ],
        )

    if port_set.intersection({22, 161, 162, 179, 443}) and any(
        token in joined for token in ("server", "nas", "synology", "qnap")
    ):
        return _device_type_result(
            "server",
            70,
            warn_reset=True,
            rationale=_rationale(3, "server/NAS ports + keyword"),
            vendor=vendor,
            model=model,
            hostname=hostname,
            asset_class="server_nas",
            reset_risk="high",
            evidence=identity_evidence + [
                "server or NAS management ports with platform keywords",
            ],
        )

    if camera_confidence >= 50:
        return _device_type_result(
            "camera",
            camera_confidence,
            rationale=_rationale(4, f"camera_confidence={camera_confidence} >= 50"),
            vendor=vendor,
            model=model,
            hostname=hostname,
            asset_class="camera",
            operational_role="camera_endpoint",
            reset_risk="moderate",
            evidence=identity_evidence + [
                f"camera_confidence={camera_confidence}",
                "protocol evidence confirms camera role",
            ],
        )

    if port_set.intersection({554, 8554, 8899}):
        return _device_type_result(
            "camera",
            max(camera_confidence, 30),
            rationale=_rationale(5, "camera ports open (554/8554/8899) but no strong protocol evidence"),
            vendor=vendor,
            model=model,
            hostname=hostname,
            asset_class="camera",
            operational_role="camera_endpoint",
            reset_risk="moderate",
            evidence=identity_evidence + [
                "camera-adjacent ports open without confirming protocol evidence",
            ],
        )

    if vendor_l not in ("unknown", ""):
        return _device_type_result(
            "unknown",
            45,
            rationale=_rationale(6, f"vendor={vendor_l} but no matching rule"),
            vendor=vendor,
            model=model,
            hostname=hostname,
            asset_class="unknown_endpoint",
            reset_risk="moderate",
            evidence=identity_evidence + [
                "known vendor but no class rule matched",
            ],
        )

    return _device_type_result(
        "unknown",
        15,
        rationale=_rationale(6, "no distinguishing evidence"),
        vendor=vendor,
        model=model,
        hostname=hostname,
        asset_class="unknown_endpoint",
        reset_risk="moderate",
        evidence=["no distinguishing evidence"],
    )
