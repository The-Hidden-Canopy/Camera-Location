"""Tests for reconciliation: durable asset/endpoint split and identity moves."""

import os
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

os.environ.setdefault("CAM_SECRET_BACKEND", "plain")
os.environ.setdefault("CAM_SECRET_DIR", str(Path(__file__).resolve().parent / "_test_secrets"))

from camdiscover.models import DiscoveredDevice, Evidence
from camdiscover.domain.models import Site, CameraAsset, DeviceEndpoint
from camdiscover.persistence.db import Database
from camdiscover.persistence.repos import SiteRepo, AssetRepo, EndpointRepo, ObservationRepo
from camdiscover.services.reconciliation import ReconciliationService


def _mem_db():
    db = Database(":memory:")
    db.migrate()
    return db


def _make_site(repo: SiteRepo):
    site = Site(site_id=str(uuid.uuid4()), name="Reconcile Farm")
    repo.save(site)
    return site


def _device(**kwargs):
    defaults = dict(
        device_id=str(uuid.uuid4()),
        ip="192.168.88.34",
        mac="18:68:cb:11:22:33",
        serial="SN-RECON-1",
        vendor="Hikvision",
        model="DS-2CD2347",
        onvif_uuid="uuid-abc",
        device_class="camera",
        subnet="192.168.88.0/24",
    )
    defaults.update(kwargs)
    return DiscoveredDevice(**defaults)


def _evidence(kind: str = "arp_seen", detail: str = "seen") -> Evidence:
    return Evidence(kind=kind, detail=detail, source="test", weight=40)


def test_reconcile_unknown_creates_asset_and_endpoint():
    db = _mem_db()
    site = _make_site(SiteRepo(db))
    svc = ReconciliationService(db)
    dev = _device()
    endpoint, asset, outcome = svc.reconcile_device(dev, site_id=site.site_id)
    assert asset is not None
    assert endpoint.asset_id == asset.asset_id
    assert endpoint.ip == "192.168.88.34"
    assert outcome == "new_asset_created"
    assert asset.asset_class == "camera"
    assert asset.operational_role == "camera_endpoint"
    assert asset.reset_risk == "moderate"


def test_reconcile_infrastructure_asset_sets_role_and_risk():
    db = _mem_db()
    site = _make_site(SiteRepo(db))
    svc = ReconciliationService(db)
    dev = _device(
        vendor="Ubiquiti",
        model="NanoBeam M5",
        serial="",
        onvif_uuid="",
        device_class="bridge",
    )
    endpoint, asset, outcome = svc.reconcile_device(dev, site_id=site.site_id)

    assert outcome == "new_asset_created"
    assert asset is not None
    assert endpoint.asset_id == asset.asset_id
    assert asset.asset_class == "wireless_bridge"
    assert asset.operational_role == "remote_bridge"
    assert asset.criticality == "critical"
    assert asset.reset_risk == "critical"


def test_reconcile_serial_match_returns_existing_asset():
    db = _mem_db()
    site = _make_site(SiteRepo(db))
    asset_repo = AssetRepo(db)
    asset = CameraAsset(asset_id=str(uuid.uuid4()), site_id=site.site_id, serial="SN-RECON-2")
    asset_repo.save(asset)

    svc = ReconciliationService(db)
    dev = _device(serial="SN-RECON-2", ip="192.168.88.35", onvif_uuid="")
    endpoint, matched, outcome = svc.reconcile_device(dev, site_id=site.site_id)
    assert matched and matched.asset_id == asset.asset_id
    assert outcome == "matched_serial"


def test_reconcile_mac_move_creates_new_endpoint_with_history():
    db = _mem_db()
    site = _make_site(SiteRepo(db))
    svc = ReconciliationService(db)

    # First sighting
    svc.reconcile_device(_device(ip="192.168.88.34"), site_id=site.site_id)

    # Same MAC, new IP (network reformat scenario); clear UUID/serial so match is by MAC.
    endpoint, asset, outcome = svc.reconcile_device(
        _device(ip="10.32.57.118", onvif_uuid="", serial=""), site_id=site.site_id
    )
    assert asset is not None
    assert outcome == "moved_new_ip"

    endpoints = EndpointRepo(db).list_for_asset(asset.asset_id)
    assert len(endpoints) == 2
    current = [e for e in endpoints if e.is_current]
    assert len(current) == 1 and current[0].ip == "10.32.57.118"
    assert "192.168.88.34" in current[0].ip_history


def test_reconcile_queues():
    db = _mem_db()
    site = _make_site(SiteRepo(db))
    svc = ReconciliationService(db)
    svc.reconcile_device(_device(ip="192.168.88.34"), site_id=site.site_id)
    svc.reconcile_device(_device(ip="192.168.88.35", serial="SN-OTHER", mac="18:68:cb:11:22:44"),
                         site_id=site.site_id)
    queues = svc.reconciliation_queues(site.site_id, ["192.168.88.34", "192.168.88.35"])
    assert len(queues["matched_auto"]) == 2
    assert len(queues["new_unknown"]) == 0


if __name__ == "__main__":
    import traceback
    failures = []
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  PASS {name}")
            except Exception as e:
                failures.append((name, e))
                print(f"  FAIL {name}: {e}")
                traceback.print_exc()
    if failures:
        print(f"\n{len(failures)} test(s) failed.")
        sys.exit(1)
    print("\nAll tests passed.")
