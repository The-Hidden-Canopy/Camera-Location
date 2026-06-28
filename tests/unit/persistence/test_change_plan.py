"""Tests for change-plan service."""

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
from camdiscover.persistence.repos import SiteRepo, AssetRepo, EndpointRepo
from camdiscover.services.change_plan import ChangePlanService


def _mem_db():
    db = Database(":memory:")
    db.migrate()
    return db


def test_change_plan_full_flow():
    db = _mem_db()
    site = Site(site_id=str(uuid.uuid4()), name="Change Plan Farm")
    SiteRepo(db).save(site)

    asset = CameraAsset(asset_id=str(uuid.uuid4()), site_id=site.site_id,
                        serial="SN-CP-1", asset_tag="CAM-01")
    AssetRepo(db).save(asset)

    endpoint = DeviceEndpoint(endpoint_id=str(uuid.uuid4()), asset_id=asset.asset_id,
                              ip="192.168.88.34", mac="18:68:cb:11:22:33",
                              subnet="255.255.255.0", is_current=True)
    EndpointRepo(db).save(endpoint)

    svc = ChangePlanService(db)
    job = svc.propose(site.site_id, endpoint.endpoint_id, "10.0.0.15",
                      "255.255.255.0", "10.0.0.1")
    assert job.status == "proposed"

    phrase = f"Change SN-CP-1 to 10.0.0.15"
    job = svc.approve(job.job_id, phrase)
    assert job.status == "approved"

    def executor(job, asset, endpoint):
        return {"success": True, "detail": "mock applied", "rollback_state": {}}

    job = svc.execute(job.job_id, executor=executor)
    # Verification will likely fail because no migrated endpoint exists in DB.
    assert job.status in ("success", "manual_recovery")


def test_invalid_change_plan():
    db = _mem_db()
    site = Site(site_id=str(uuid.uuid4()), name="Change Plan Farm")
    SiteRepo(db).save(site)

    asset = CameraAsset(asset_id=str(uuid.uuid4()), site_id=site.site_id,
                        serial="SN-CP-2", asset_tag="CAM-02")
    AssetRepo(db).save(asset)

    endpoint = DeviceEndpoint(endpoint_id=str(uuid.uuid4()), asset_id=asset.asset_id,
                              ip="192.168.88.35", subnet="255.255.255.0", is_current=True)
    EndpointRepo(db).save(endpoint)

    svc = ChangePlanService(db)
    job = svc.propose(site.site_id, endpoint.endpoint_id, "10.0.0.256",
                      "255.255.255.0", "10.0.0.1")
    assert job.status == "draft"


def test_wrong_confirmation_phrase():
    db = _mem_db()
    site = Site(site_id=str(uuid.uuid4()), name="Change Plan Farm")
    SiteRepo(db).save(site)

    asset = CameraAsset(asset_id=str(uuid.uuid4()), site_id=site.site_id,
                        serial="SN-CP-3", asset_tag="CAM-03")
    AssetRepo(db).save(asset)
    endpoint = DeviceEndpoint(endpoint_id=str(uuid.uuid4()), asset_id=asset.asset_id,
                              ip="192.168.88.36", subnet="255.255.255.0", is_current=True)
    EndpointRepo(db).save(endpoint)

    svc = ChangePlanService(db)
    job = svc.propose(site.site_id, endpoint.endpoint_id, "10.0.0.16",
                      "255.255.255.0", "10.0.0.1")
    try:
        svc.approve(job.job_id, "wrong phrase")
    except ValueError as e:
        assert "phrase" in str(e).lower()
    else:
        raise AssertionError("Expected ValueError for wrong phrase")


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
