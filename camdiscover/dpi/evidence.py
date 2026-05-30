"""
Evidence weights and camera confidence scoring.

Every signal is assigned a weight (positive = camera evidence, negative = non-camera).
camera_confidence = clamp(0, sum(weights), 100)

This mirrors the scoring model from the architecture document:
  +40  ONVIF ProbeMatch with NetworkVideoTransmitter
  +35  SADP / Dahua UDP response
  +30  RTSP DESCRIBE/SETUP/PLAY
  ...
  -30  Windows WSD host
"""

from typing import TYPE_CHECKING

# Forward ref only — Evidence is defined in models.py to avoid circular import.
if TYPE_CHECKING:
    from ..models import Evidence


# ─── Weight table ─────────────────────────────────────────────────────────────

EVIDENCE_WEIGHTS: dict[str, int] = {
    # ── Strongest camera signals ─────────────────────────────────────────
    "onvif_probe_match_nvt":     40,   # WS-Discovery ProbeMatch with NetworkVideoTransmitter
    "sadp_response":             35,   # Hikvision SADP UDP 37020 response
    "dahua_udp_response":        35,   # Dahua/Amcrest UDP probe response
    "rtsp_describe_response":    30,   # RTSP DESCRIBE received with SDP video track
    "rtsp_setup_play":           25,   # RTSP SETUP+PLAY confirms active stream
    "onvif_device_service_url":  25,   # device_service XAddr extracted from WS-Discovery
    # ── Strong signals ───────────────────────────────────────────────────
    "onvif_device_info":         22,   # GetDeviceInformation returned data
    "onvif_port_responding":     18,   # ONVIF endpoint replied to SOAP
    "http_camera_banner":        20,   # HTTP banner matches camera/NVR vendor keyword
    "rtsp_port_open":            12,   # TCP 554/8554 open and OPTIONS responded
    # ── Moderate signals ─────────────────────────────────────────────────
    "onvif_probe_match_generic": 15,   # WS-Discovery match without explicit NVT type
    "rtp_media_flow":            15,   # Long-lived RTP/RTCP flow from device
    "ssdp_camera_service":       10,   # SSDP service type contains camera keywords
    "mac_oui_camera":            10,   # MAC OUI matches known camera vendor
    "dhcp_hostname_camera":      10,   # DHCP hostname implies camera or NVR
    "mdns_camera_service":       10,   # mDNS service name implies camera
    # ── Infrastructure witness signals (Arm 6) ───────────────────────────
    "nvr_channel_match":         20,   # Device listed on NVR channel — strong camera proof
    "switch_mac_seen":            5,   # Device seen in switch MAC table
    "dhcp_lease_seen":            8,   # Device has a DHCP lease
    "router_arp_seen":            5,   # Device in router ARP dump
    "snmp_sysname_seen":          8,   # SNMP sysName/sysDescr style identity seen
    "snmp_printer_hint":        -30,   # SNMP text confirms printer/copier — definitely not a camera
    "snmp_infra_hint":          -25,   # SNMP text confirms router/switch/AP/firewall — not a camera
    "dns_name_seen":              6,   # DNS or reverse-DNS name supplied from external evidence
    # ── Weak supporting signals ──────────────────────────────────────────
    "igmp_multicast_stream":      5,   # IGMP join on known video multicast group
    "rtp_flow":                   8,   # RTP media flow from device (passive)
    "lldp_neighbor":              2,   # LLDP frame seen — L2 presence only (mostly switches/routers)
    "dhcp_request":               3,   # Device sent DHCP request (passive DHCP snoop)
    "subnet_mismatch_visible":    5,   # SADP visible but IP outside scanner subnet
    "nvr_channel_listed":        30,   # Listed in NVR external channel dump (ingested evidence)
    # ── Fingerprint bridge ───────────────────────────────────────────────
    # Synthetic item minted by _scan_and_fingerprint when the heuristic score
    # exceeds the raw evidence total.  Weight is set dynamically (capped at 30).
    "fingerprint_match":         0,    # weight overridden by caller; registered for metadata lookups
    # ── Negative evidence ────────────────────────────────────────────────
    "wsd_non_camera":           -20,   # WS-Discovery with clearly non-camera type
    "windows_wsd_host":         -30,   # Windows WSD (printer/scan/computer)
}


# ─── Camera vendor keywords ───────────────────────────────────────────────────

CAMERA_VENDOR_KEYWORDS: frozenset[str] = frozenset({
    "hikvision", "dahua", "amcrest", "axis", "reolink", "uniview", "hanwha",
    "wisenet", "bosch", "avigilon", "vivotek", "pelco", "flir", "basler",
    "mobotix", "arecont", "geovision", "cp-plus", "cp plus", "tiandy",
    "tvt", "acti", "digital watchdog", "nvr", "dvr", "ipcam", "ipcamera",
    "network camera", "network video", "onvif camera", "ip camera",
    "surveillance", "security camera", "cctv",
})

NON_CAMERA_WSD_KEYWORDS: frozenset[str] = frozenset({
    "printer", "scanner", "print_basic", "printbasic",
    "pub:computer", "computer", "microsoft", "windows", "urn:schemas-microsoft",
    "urn:schemas-upnp-org:device:basic", "dial-multiscreen",
    "urn:schemas-upnp-org:device:mediaserver",
    "urn:schemas-upnp-org:device:mediarenderer",
})


# ─── Scoring ──────────────────────────────────────────────────────────────────

def score_evidence(evidence_list) -> int:
    """
    Compute 0-100 camera confidence score from a list of Evidence objects.
    Each Evidence has a .weight attribute.
    """
    if not evidence_list:
        return 0
    total = sum(getattr(e, "weight", 0) for e in evidence_list)
    return max(0, min(100, total))
