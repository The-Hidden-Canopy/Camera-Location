"""Tests for network rebuild reconciliation."""

import os
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

os.environ.setdefault("CAM_SECRET_BACKEND", "plain")
os.environ.setdefault("CAM_SECRET_DIR", str(Path(__file__).resolve().parent / "_test_secrets"))

from camdiscover.models import DiscoveredDevice
from camdiscover.domain.models import Site, CameraAsset, DeviceEndpoint
from camdiscover.persistence.db import Database
from camdiscover.persistence.repos import SiteRepo, AssetRepo, EndpointRepo
from camdiscover.services.rebuild import NetworkRebuildService, MatchConfidence


def _mem_db():
    db = Database(":memory:")
    db.migrate()
    return db


def _make_site(db):
    site = Site(site_id=str(uuid.uuid4()), name="Rebuild Farm")
    SiteRepo(db).save(site)
    return site


def _device(**kwargs):
    defaults = dict(
        device_id=str(uuid.uuid4()),
        ip="192.168.88.34",
        mac="18:68:cb:11:22:33",
        serial="SN-REB-1",
        vendor="Hikvision",
        model="DS-2CD2347",
        onvif_uuid="uuid-abc",
        device_class="camera",
        subnet="192.168.88.0/24",
    )
    defaults.update(kwargs)
    return DiscoveredDevice(**defaults)


def test_rebuild_matches_by_serial_and_lists_missing():
    db = _mem_db()
    site = _make_site(db)
    asset_repo = AssetRepo(db)
    endpoint_repo = EndpointRepo(db)

    # Previously known assets
    a1 = CameraAsset(asset_id=str(uuid.uuid4()), site_id=site.site_id,
                     serial="SN-REB-1", asset_tag="CAM-01")
    a2 = CameraAsset(asset_id=str(uuid.uuid4()), site_id=site.site_id,
                     serial="SN-REB-2", asset_tag="CAM-02")
    asset_repo.save(a1)
    asset_repo.save(a2)

    # Old endpoint for a1
    e1 = DeviceEndpoint(endpoint_id=str(uuid.uuid4()), asset_id=a1.asset_id,
                        ip="192.168.88.34", mac="18:68:cb:11:22:33", is_current=True)
    endpoint_repo.save(e1)

    svc = NetworkRebuildService(db)

    # Fresh scan after reformat: a1 now at new IP, a2 missing
    discovered = [_device(serial="SN-REB-1", ip="10.0.0.15", mac="18:68:cb:11:22:33")]
    report = svc.reconcile_session(site.site_id, discovered)

    assert len(report.matched_auto) == 1
    assert report.matched_auto[0].asset_id == a1.asset_id
    assert report.matched_auto[0].discovered_ip == "10.0.0.15"
    assert report.matched_auto[0].confidence == MatchConfidence.EXACT.value

    assert len(report.missing) == 1
    assert report.missing[0]["asset_id"] == a2.asset_id


def test_rebuild_lists_unknown_device():
    db = _mem_db()
    site = _make_site(db)

    svc = NetworkRebuildService(db)
    discovered = [_device(serial="UNKNOWN", mac="aa:bb:cc:dd:ee:ff")]
    report = svc.reconcile_session(site.site_id, discovered)

    assert len(report.new_unknown) == 1
    assert report.new_unknown[0]["ip"] == "192.168.88.34"


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
