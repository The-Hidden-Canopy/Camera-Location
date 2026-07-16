"""Tests for manual merge and split services."""

import os
import sys
import uuid
from pathlib import Path

from flask import Flask

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

os.environ.setdefault("CAM_SECRET_BACKEND", "plain")
os.environ.setdefault("CAM_SECRET_DIR", str(Path(__file__).resolve().parent / "_test_secrets"))

from camdiscover.domain.models import Site, CameraAsset, DeviceEndpoint
from camdiscover.persistence.db import Database
from camdiscover.persistence.repos import SiteRepo, AssetRepo, EndpointRepo, ObservationRepo
from camdiscover.api.routes import register_routes
from camdiscover.services.merge import MergeService


def _mem_db():
    db = Database(":memory:")
    db.migrate()
    return db


def _site(db):
    site = Site(site_id=str(uuid.uuid4()), name="Merge Farm")
    SiteRepo(db).save(site)
    return site


def _app(db):
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.config["CAMDISCOVER_DB"] = db
    register_routes(app)
    return app


def test_merge_assets_migrates_endpoints():
    db = _mem_db()
    site = _site(db)
    assets = AssetRepo(db)
    endpoints = EndpointRepo(db)
    observations = ObservationRepo(db)

    keep = CameraAsset(asset_id=str(uuid.uuid4()), site_id=site.site_id, serial="KEEP")
    remove = CameraAsset(asset_id=str(uuid.uuid4()), site_id=site.site_id, serial="REMOVE")
    assets.save(keep)
    assets.save(remove)

    ep = DeviceEndpoint(endpoint_id=str(uuid.uuid4()), asset_id=remove.asset_id,
                        ip="192.168.88.50", is_current=True)
    endpoints.save(ep)

    svc = MergeService(db)
    result = svc.merge_assets(site.site_id, keep.asset_id, remove.asset_id)

    assert result["kept_asset_id"] == keep.asset_id
    assert result["removed_asset_id"] == remove.asset_id

    migrated = endpoints.list_for_asset(keep.asset_id)
    assert len(migrated) == 1
    assert migrated[0].asset_id == keep.asset_id
    logged = observations.list_for_asset(keep.asset_id)
    assert len(logged) == 1
    assert logged[0].kind == "asset_merge"


def test_split_endpoint_to_asset():
    db = _mem_db()
    site = _site(db)
    assets = AssetRepo(db)
    endpoints = EndpointRepo(db)
    observations = ObservationRepo(db)

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
    logged = observations.list_for_asset(new_asset.asset_id)
    assert len(logged) == 1
    assert logged[0].kind == "asset_split"


def test_merge_assets_blocks_cross_site_mutation():
    db = _mem_db()
    site_a = _site(db)
    site_b = Site(site_id=str(uuid.uuid4()), name="Other Farm")
    SiteRepo(db).save(site_b)
    assets = AssetRepo(db)
    endpoints = EndpointRepo(db)
    observations = ObservationRepo(db)

    keep = CameraAsset(asset_id=str(uuid.uuid4()), site_id=site_a.site_id, serial="KEEP")
    remove = CameraAsset(asset_id=str(uuid.uuid4()), site_id=site_b.site_id, serial="REMOVE")
    assets.save(keep)
    assets.save(remove)

    ep = DeviceEndpoint(endpoint_id=str(uuid.uuid4()), asset_id=remove.asset_id,
                        ip="192.168.88.51", is_current=True)
    endpoints.save(ep)

    svc = MergeService(db)
    try:
        svc.merge_assets(site_a.site_id, keep.asset_id, remove.asset_id)
        assert False, "expected cross-site merge to be blocked"
    except ValueError as e:
        assert str(e) == "asset not found"

    preserved = endpoints.get(ep.endpoint_id)
    assert preserved.asset_id == remove.asset_id
    assert observations.list_for_asset(keep.asset_id) == []


def test_confirm_match_blocks_cross_site_endpoint_attachment():
    db = _mem_db()
    site_a = _site(db)
    site_b = Site(site_id=str(uuid.uuid4()), name="Other Farm")
    SiteRepo(db).save(site_b)
    assets = AssetRepo(db)
    endpoints = EndpointRepo(db)
    observations = ObservationRepo(db)

    asset = CameraAsset(asset_id=str(uuid.uuid4()), site_id=site_a.site_id, serial="KEEP")
    other_asset = CameraAsset(asset_id=str(uuid.uuid4()), site_id=site_b.site_id, serial="OTHER")
    assets.save(asset)
    assets.save(other_asset)

    ep = DeviceEndpoint(endpoint_id=str(uuid.uuid4()), asset_id=other_asset.asset_id,
                        ip="192.168.88.52", is_current=True)
    endpoints.save(ep)

    svc = MergeService(db)
    try:
        svc.confirm_match(site_a.site_id, asset.asset_id, ep.endpoint_id, ep.ip)
        assert False, "expected cross-site endpoint attach to be blocked"
    except ValueError as e:
        assert str(e) == "endpoint not found at site"

    preserved = endpoints.get(ep.endpoint_id)
    assert preserved.asset_id == other_asset.asset_id
    assert observations.list_for_asset(asset.asset_id) == []


def test_split_endpoint_to_asset_blocks_cross_site_mutation():
    db = _mem_db()
    site_a = _site(db)
    site_b = Site(site_id=str(uuid.uuid4()), name="Other Farm")
    SiteRepo(db).save(site_b)
    assets = AssetRepo(db)
    endpoints = EndpointRepo(db)
    observations = ObservationRepo(db)

    old_asset = CameraAsset(asset_id=str(uuid.uuid4()), site_id=site_a.site_id, serial="OLD")
    assets.save(old_asset)

    ep = DeviceEndpoint(endpoint_id=str(uuid.uuid4()), asset_id=old_asset.asset_id,
                        ip="192.168.88.61", is_current=True)
    endpoints.save(ep)

    svc = MergeService(db)
    try:
        svc.split_endpoint_to_asset(ep.endpoint_id, {
            "site_id": site_b.site_id,
            "serial": "NEW",
            "asset_tag": "NEW-001",
        })
        assert False, "expected cross-site split to be blocked"
    except ValueError as e:
        assert str(e) == "endpoint not found at site"

    preserved = endpoints.get(ep.endpoint_id)
    assert preserved.asset_id == old_asset.asset_id
    assert observations.list_for_site(site_b.site_id) == []


def test_merge_assets_route_happy_path():
    db = _mem_db()
    app = _app(db)
    site = _site(db)
    assets = AssetRepo(db)
    endpoints = EndpointRepo(db)
    observations = ObservationRepo(db)

    keep = CameraAsset(asset_id=str(uuid.uuid4()), site_id=site.site_id, serial="KEEP")
    remove = CameraAsset(asset_id=str(uuid.uuid4()), site_id=site.site_id, serial="REMOVE")
    assets.save(keep)
    assets.save(remove)

    ep = DeviceEndpoint(endpoint_id=str(uuid.uuid4()), asset_id=remove.asset_id,
                        ip="192.168.88.70", is_current=True)
    endpoints.save(ep)

    client = app.test_client()
    resp = client.post(f"/api/sites/{site.site_id}/assets/merge", json={
        "keep_asset_id": keep.asset_id,
        "remove_asset_id": remove.asset_id,
    })

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["kept_asset_id"] == keep.asset_id
    assert endpoints.get(ep.endpoint_id).asset_id == keep.asset_id
    logged = observations.list_for_asset(keep.asset_id)
    assert len(logged) == 1
    assert logged[0].kind == "asset_merge"


def test_merge_assets_route_blocks_cross_site_mutation():
    db = _mem_db()
    app = _app(db)
    site_a = _site(db)
    site_b = Site(site_id=str(uuid.uuid4()), name="Other Farm")
    SiteRepo(db).save(site_b)
    assets = AssetRepo(db)
    endpoints = EndpointRepo(db)
    observations = ObservationRepo(db)

    keep = CameraAsset(asset_id=str(uuid.uuid4()), site_id=site_a.site_id, serial="KEEP")
    remove = CameraAsset(asset_id=str(uuid.uuid4()), site_id=site_b.site_id, serial="REMOVE")
    assets.save(keep)
    assets.save(remove)

    ep = DeviceEndpoint(endpoint_id=str(uuid.uuid4()), asset_id=remove.asset_id,
                        ip="192.168.88.71", is_current=True)
    endpoints.save(ep)

    client = app.test_client()
    resp = client.post(f"/api/sites/{site_a.site_id}/assets/merge", json={
        "keep_asset_id": keep.asset_id,
        "remove_asset_id": remove.asset_id,
    })

    assert resp.status_code == 404
    assert resp.get_json()["error"] == "asset not found"
    assert endpoints.get(ep.endpoint_id).asset_id == remove.asset_id
    assert observations.list_for_asset(keep.asset_id) == []


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
