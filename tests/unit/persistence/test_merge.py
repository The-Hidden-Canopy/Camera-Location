"""Tests for manual merge and split services."""

import os
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

os.environ.setdefault("CAM_SECRET_BACKEND", "plain")
os.environ.setdefault("CAM_SECRET_DIR", str(Path(__file__).resolve().parent / "_test_secrets"))

from camdiscover.domain.models import Site, CameraAsset, DeviceEndpoint
from camdiscover.persistence.db import Database
from camdiscover.persistence.repos import SiteRepo, AssetRepo, EndpointRepo, ObservationRepo
from camdiscover.services.merge import MergeService


def _mem_db():
    db = Database(":memory:")
    db.migrate()
    return db


def _site(db):
    site = Site(site_id=str(uuid.uuid4()), name="Merge Farm")
    SiteRepo(db).save(site)
    return site


def test_merge_assets_migrates_endpoints():
    db = _mem_db()
    site = _site(db)
    assets = AssetRepo(db)
    endpoints = EndpointRepo(db)

    keep = CameraAsset(asset_id=str(uuid.uuid4()), site_id=site.site_id, serial="KEEP")
    remove = CameraAsset(asset_id=str(uuid.uuid4()), site_id=site.site_id, serial="REMOVE")
    assets.save(keep)
    assets.save(remove)

    ep = DeviceEndpoint(endpoint_id=str(uuid.uuid4()), asset_id=remove.asset_id,
                        ip="192.168.88.50", is_current=True)
    endpoints.save(ep)

    svc = MergeService(db)
    result = svc.merge_assets(keep.asset_id, remove.asset_id)

    assert result["kept_asset_id"] == keep.asset_id
    assert result["removed_asset_id"] == remove.asset_id

    migrated = endpoints.list_for_asset(keep.asset_id)
    assert len(migrated) == 1
    assert migrated[0].asset_id == keep.asset_id


def test_split_endpoint_to_asset():
    db = _mem_db()
    site = _site(db)
    assets = AssetRepo(db)
    endpoints = EndpointRepo(db)

    old_asset = CameraAsset(asset_id=str(uuid.uuid4()), site_id=site.site_id, serial="OLD")
    assets.save(old_asset)

    ep = DeviceEndpoint(endpoint_id=str(uuid.uuid4()), asset_id=old_asset.asset_id,
                        ip="192.168.88.60", is_current=True)
    endpoints.save(ep)

    svc = MergeService(db)
    result = svc.split_endpoint_to_asset(ep.endpoint_id, {"site_id": site.site_id,
                                                            "serial": "NEW", "asset_tag": "NEW-001"})

    new_asset = assets.get(result["new_asset_id"])
    assert new_asset is not None
    assert new_asset.serial == "NEW"

    ep = endpoints.get(result["endpoint_id"])
    assert ep.asset_id == new_asset.asset_id


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
