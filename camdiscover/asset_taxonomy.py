"""Shared taxonomy helpers for live devices and durable assets."""

from __future__ import annotations


def _joined_text(*parts: str) -> str:
    return " ".join((part or "").strip().lower() for part in parts if part)


def infer_asset_class(
    device_class: str,
    vendor: str = "",
    model: str = "",
    hostname: str = "",
) -> str:
    joined = _joined_text(vendor, model, hostname)
    device_class = (device_class or "").strip().lower()

    if device_class == "camera":
        return "camera"
    if device_class == "nvr":
        return "nvr"
    if device_class == "bridge":
        if any(token in joined for token in ("liteap", "uap", "access point", "sector")):
            return "access_point"
        return "wireless_bridge"
    if device_class == "switch":
        if any(token in joined for token in ("poe", "antaira")):
            return "poe_switch"
        return "managed_switch"
    if device_class == "router":
        return "router_firewall"
    if device_class == "server":
        if any(token in joined for token in ("desktop", "laptop", "workstation", "windows 10", "windows 11")):
            return "workstation"
        return "server_nas"
    if device_class == "computer":
        return "workstation"
    if device_class == "printer":
        return "printer"
    if any(token in joined for token in ("petrocloud", "twenty20")):
        return "legacy_video_appliance"
    if any(token in joined for token in ("raspberry", "relay", "controller")):
        return "iot_controller"
    return "unknown_endpoint"


def infer_operational_role(
    asset_class: str,
    vendor: str = "",
    model: str = "",
    hostname: str = "",
) -> str:
    joined = _joined_text(vendor, model, hostname)
    asset_class = (asset_class or "").strip().lower()

    if asset_class == "camera":
        return "camera_endpoint"
    if asset_class == "nvr":
        return "recorder"
    if asset_class == "access_point":
        return "backhaul_hub"
    if asset_class == "wireless_bridge":
        return "remote_bridge"
    if asset_class == "poe_switch":
        return "poe_source"
    if asset_class == "router_firewall":
        return "network_gateway"
    if asset_class == "workstation":
        return "installer_laptop" if "laptop" in joined else "workstation"
    if asset_class == "legacy_video_appliance":
        return "legacy_controller"
    if asset_class == "iot_controller":
        return "legacy_controller" if "relay" in joined else "iot_controller"
    if asset_class == "server_nas":
        return "infrastructure_host"
    return "unknown"


def infer_reset_risk(asset_class: str, current_reset_risk: str = "") -> str:
    current_reset_risk = (current_reset_risk or "").strip().lower()
    if current_reset_risk and current_reset_risk != "unknown":
        return current_reset_risk

    asset_class = (asset_class or "").strip().lower()
    if asset_class in ("nvr", "access_point", "wireless_bridge", "router_firewall"):
        return "critical"
    if asset_class in ("poe_switch", "managed_switch", "server_nas", "legacy_video_appliance"):
        return "high"
    if asset_class in ("camera", "iot_controller", "unknown_endpoint"):
        return "moderate"
    return "low"


def infer_criticality(asset_class: str, reset_risk: str = "") -> str:
    asset_class = (asset_class or "").strip().lower()
    reset_risk = (reset_risk or "").strip().lower()

    if asset_class in ("nvr", "access_point", "wireless_bridge", "router_firewall"):
        return "critical"
    if reset_risk == "critical":
        return "critical"
    if asset_class in ("poe_switch", "managed_switch", "server_nas"):
        return "high"
    if asset_class in ("camera", "nvr", "router_firewall", "access_point", "wireless_bridge", "legacy_video_appliance"):
        return "high" if reset_risk == "high" else "normal"
    if asset_class in ("workstation", "printer"):
        return "low"
    return "normal"
