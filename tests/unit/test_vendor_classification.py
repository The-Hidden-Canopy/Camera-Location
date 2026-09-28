import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from camdiscover.models import DiscoveredDevice
from camdiscover.vendor import classify_device_type


def test_classify_ubiquiti_sector_as_access_point_with_legacy_bridge_bucket():
    result = classify_device_type(
        vendor="Ubiquiti",
        open_ports=[22, 80, 443, 554],
        protocols=["HTTP"],
        model="LiteAP GPS",
        hostname="north-sector-ap",
    )

    assert result.device_type == "bridge"
    assert result.asset_class == "access_point"
    assert result.operational_role == "backhaul_hub"
    assert result.reset_risk == "critical"
    assert result.criticality == "critical"
    assert "vendor=Ubiquiti" in result.evidence


def test_classify_antaira_switch_as_poe_source():
    result = classify_device_type(
        vendor="Antaira",
        open_ports=[22, 80, 161],
        protocols=["HTTP", "SNMP"],
        model="LNP-0800G-24",
        hostname="north-antaira-poe",
    )

    assert result.device_type == "switch"
    assert result.asset_class == "poe_switch"
    assert result.operational_role == "poe_source"
    assert result.reset_risk == "high"
    assert "switch platform keywords present" in result.evidence


def test_live_device_asset_view_prefers_classifier_overrides():
    result = classify_device_type(
        vendor="Ubiquiti",
        open_ports=[22, 80, 443],
        protocols=["HTTP"],
        model="NanoBeam M5",
        hostname="pump-house-link",
    )
    device = DiscoveredDevice(
        device_id="dev-1",
        ip="192.168.88.50",
        device_class=result.device_type,
        vendor="Ubiquiti",
        model="NanoBeam M5",
        hostname="pump-house-link",
        reset_risk=result.reset_risk,
        warn_reset=result.warn_reset,
        classification_rationale=result.rationale,
        asset_class_override=result.asset_class,
        operational_role_override=result.operational_role,
        criticality_override=result.criticality,
        classification_signals=list(result.evidence),
    )

    payload = device.to_dict()
    assert payload["device_class"] == "bridge"
    assert payload["asset_class"] == "wireless_bridge"
    assert payload["operational_role"] == "remote_bridge"
    assert payload["criticality"] == "critical"
    assert "wireless infrastructure keywords indicate bridge/uplink role" in payload["classification_evidence"]
