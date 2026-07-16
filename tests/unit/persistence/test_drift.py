"""Tests for baseline-aware drift detection."""

import os
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

os.environ.setdefault("CAM_SECRET_BACKEND", "plain")
os.environ.setdefault("CAM_SECRET_DIR", str(Path(__file__).resolve().parent / "_test_secrets"))

from camdiscover.domain.models import CameraAsset, DeviceEndpoint, Site
from camdiscover.models import DiscoveredDevice
from camdiscover.persistence.db import Database
from camdiscover.persistence.repos import AssetRepo, EndpointRepo, SiteRepo
from camdiscover.services.drift import DriftService


def _mem_db():
    db = Database(":memory:")
    db.migrate()
    return db


def _make_site(db: Database) -> Site:
    site = Site(
        site_id=str(uuid.uuid4()),
        name="Drift Farm",
        authorized_classes=["camera", "nvr", "poe_switch", "wireless_bridge", "access_point"],
        expected_subnets=["192.168.88.0/24"],
        known_old_subnets=["192.168.1.0/24"],
        unauthorized_device_alerts=True,
    )
    SiteRepo(db).save(site)
    return site


def _device(**kwargs) -> DiscoveredDevice:
    defaults = dict(
        device_id=str(uuid.uuid4()),
        ip="192.168.88.34",
        mac="18:68:cb:11:22:33",
        serial="SN-DRIFT-1",
        vendor="Hikvision",
        model="DS-2CD2347",
        onvif_uuid="uuid-drift-1",
        device_class="camera",
        subnet="192.168.88.0/24",
    )
    defaults.update(kwargs)
    return DiscoveredDevice(**defaults)


def test_drift_flags_known_ip_moves_and_missing_assets():
    db = _mem_db()
    site = _make_site(db)
    assets = AssetRepo(db)
    endpoints = EndpointRepo(db)

    moved_asset = CameraAsset(
        asset_id=str(uuid.uuid4()),
        site_id=site.site_id,
        serial="SN-DRIFT-1",
        asset_class="camera",
    )
    missing_asset = CameraAsset(
        asset_id=str(uuid.uuid4()),
        site_id=site.site_id,
        serial="SN-DRIFT-2",
        asset_class="wireless_bridge",
    )
    assets.save(moved_asset)
    assets.save(missing_asset)
    endpoints.save(
        DeviceEndpoint(
            endpoint_id=str(uuid.uuid4()),
            asset_id=moved_asset.asset_id,
            ip="192.168.88.34",
            mac="18:68:cb:11:22:33",
            is_current=True,
            device_class="camera",
        )
    )

    report = DriftService(db).analyze(
        site.site_id,
        [_device(ip="192.168.88.99")],
    )
    finding_types = [item.finding_type for item in report.findings]

    assert "known_device_new_ip" in finding_types
    assert "infrastructure_missing" in finding_types


def test_drift_flags_unknown_and_unauthorized_devices_on_expected_subnet():
    db = _mem_db()
    site = _make_site(db)

    report = DriftService(db).analyze(
        site.site_id,
        [
            _device(
                serial="",
                onvif_uuid="",
                mac="aa:bb:cc:dd:ee:ff",
                vendor="Microsoft",
                model="Windows Laptop",
                device_class="server",
                asset_class_override="workstation",
                operational_role_override="installer_laptop",
            )
        ],
    )

    finding_types = [item.finding_type for item in report.findings]
    assert "unknown_device_on_expected_subnet" in finding_types
    assert "unauthorized_device_class" in finding_types


def test_drift_flags_old_subnet_apipa_and_class_changes():
    db = _mem_db()
    site = _make_site(db)
    assets = AssetRepo(db)
    endpoints = EndpointRepo(db)

    asset = CameraAsset(
        asset_id=str(uuid.uuid4()),
        site_id=site.site_id,
        serial="SN-DRIFT-3",
        asset_class="camera",
    )
    assets.save(asset)
    endpoints.save(
        DeviceEndpoint(
            endpoint_id=str(uuid.uuid4()),
            asset_id=asset.asset_id,
            ip="192.168.88.40",
            mac="24:5a:4c:11:22:33",
            is_current=True,
            device_class="camera",
        )
    )

    report = DriftService(db).analyze(
        site.site_id,
        [
            _device(
                serial="SN-DRIFT-3",
                onvif_uuid="",
                ip="169.254.10.20",
                subnet="192.168.1.0/24",
                mac="24:5a:4c:11:22:33",
                vendor="Ubiquiti",
                model="NanoBeam M5",
                device_class="bridge",
                asset_class_override="wireless_bridge",
                operational_role_override="remote_bridge",
                criticality_override="critical",
                apipa_seen=True,
            )
        ],
    )

    finding_types = [item.finding_type for item in report.findings]
    assert "device_class_changed" in finding_types
    assert "device_on_old_subnet" in finding_types
    assert "apipa_recovery_mode_device_seen" in finding_types
