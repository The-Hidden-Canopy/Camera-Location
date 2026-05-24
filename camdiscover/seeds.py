"""
Runtime constants for device classification, PoE state labels, and APIPA detection.

No historical discovery data lives here.  Every scan starts from zero and
discovers the network purely from live traffic and active probing.
"""

from __future__ import annotations
from typing import Dict, List


# ─── Device class metadata ────────────────────────────────────────────────────

DEVICE_CLASSES = {
    "camera":    "IP Camera",
    "nvr":       "NVR / DVR",
    "server":    "Server / PC",
    "bridge":    "Wireless Bridge",
    "router":    "Router / Firewall",
    "switch":    "Network Switch",
    "unknown":   "Unknown Device",
}

# Classes that should never be reset without explicit confirmation
WARN_RESET_CLASSES = {"bridge", "router", "nvr", "switch", "server"}

INFRASTRUCTURE_WARNINGS: Dict[str, str] = {
    "bridge":  (
        "This appears to be a wireless bridge/uplink. "
        "Resetting it may disconnect all cameras on the remote segment."
    ),
    "nvr": (
        "This is an NVR/DVR. Restarting or changing its IP will cause "
        "recording gaps and may disconnect cameras."
    ),
    "router": (
        "This is a router/gateway. Any change affects all devices on its segments."
    ),
    "switch": (
        "This is a switch. MAC/VLAN changes affect all connected devices."
    ),
    "server": (
        "This is an infrastructure server. Confirm its role before any action."
    ),
}


# ─── PoE / physical link states ───────────────────────────────────────────────

POE_STATES: Dict[str, str] = {
    "poe_powered_no_ip":          "PoE powered — no IP assigned",
    "link_up_no_dhcp":            "Link up — no DHCP lease",
    "link_up_wrong_subnet":       "Link up — IP on wrong subnet",
    "link_up_silent":             "Link up — no traffic seen",
    "camera_seen_by_switch_only": "Visible via switch MAC table only",
    "camera_seen_by_nvr_only":    "Listed on NVR — not reachable by IP",
    "camera_seen_by_packets_only":"Seen in passive capture only",
    "unknown":                    "Unknown physical state",
}


# ─── APIPA detection ──────────────────────────────────────────────────────────

APIPA_PREFIX = "169.254."

APIPA_WARNING = (
    "APIPA address detected (169.254.x.x). This usually means: "
    "no DHCP response, isolated segment, wrong VLAN, or device booted "
    "before the network was ready. Treating as orphan — not scanning."
)

def is_apipa(ip: str) -> bool:
    return ip.startswith(APIPA_PREFIX)
