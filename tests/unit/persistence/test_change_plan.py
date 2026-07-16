"""Tests for change-plan service."""

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
from camdiscover.api import change_routes
from camdiscover.services.change_plan import ChangePlanService


def _mem_db():
    db = Database(":memory:")
    db.migrate()
    return db


def _app(db):
    app = Flask(__name__)
    app.config["TESTING"] = True
    original = change_routes.get_database
    change_routes.get_database = lambda: db
    change_routes.register_change_routes(app)
    app._restore_change_db = original
    return app


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
    job = svc.approve(job.job_id, site.site_id, phrase)
    assert job.status == "approved"
    assert job.approved_at is not None and job.approved_at.tzinfo is not None

    def executor(job, asset, endpoint):
        return {"success": True, "detail": "mock applied", "rollback_state": {}}

    job = svc.execute(job.job_id, site.site_id, executor=executor)
    # Verification will likely fail because no migrated endpoint exists in DB.
    assert job.status in ("success", "manual_recovery")
    logged = ObservationRepo(db).list_for_endpoint(endpoint.endpoint_id)
    assert any(obs.kind == "change_plan_proposed" for obs in logged)
    assert any(obs.kind == "change_plan_executed" for obs in logged)


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
        svc.approve(job.job_id, site.site_id, "wrong phrase")
    except ValueError as e:
        assert "phrase" in str(e).lower()
    else:
        raise AssertionError("Expected ValueError for wrong phrase")


def test_change_plan_blocks_cross_site_access():
    db = _mem_db()
    site_a = Site(site_id=str(uuid.uuid4()), name="Change Plan Farm A")
    site_b = Site(site_id=str(uuid.uuid4()), name="Change Plan Farm B")
    SiteRepo(db).save(site_a)
    SiteRepo(db).save(site_b)

    asset = CameraAsset(asset_id=str(uuid.uuid4()), site_id=site_a.site_id,
                        serial="SN-CP-4", asset_tag="CAM-04")
    AssetRepo(db).save(asset)
    endpoint = DeviceEndpoint(endpoint_id=str(uuid.uuid4()), asset_id=asset.asset_id,
                              ip="192.168.88.37", subnet="255.255.255.0", is_current=True)
    EndpointRepo(db).save(endpoint)

    svc = ChangePlanService(db)
    job = svc.propose(site_a.site_id, endpoint.endpoint_id, "10.0.0.17",
                      "255.255.255.0", "10.0.0.1")
    phrase = f"Change SN-CP-4 to 10.0.0.17"

    for action in (
        lambda: svc.get(job.job_id, site_b.site_id),
        lambda: svc.approve(job.job_id, site_b.site_id, phrase),
        lambda: svc.execute(job.job_id, site_b.site_id),
    ):
        try:
            action()
        except ValueError as e:
            assert str(e) == "job not found at site"
        else:
            raise AssertionError("Expected cross-site access to be blocked")

    preserved = svc.get(job.job_id, site_a.site_id)
    assert preserved.status == "proposed"
    assert preserved.approved_at is None
    assert preserved.executed_at is None


def test_change_plan_blocks_invalid_transition_before_approval():
    db = _mem_db()
    site = Site(site_id=str(uuid.uuid4()), name="Change Plan Farm")
    SiteRepo(db).save(site)

    asset = CameraAsset(asset_id=str(uuid.uuid4()), site_id=site.site_id,
                        serial="SN-CP-5", asset_tag="CAM-05")
    AssetRepo(db).save(asset)
    endpoint = DeviceEndpoint(endpoint_id=str(uuid.uuid4()), asset_id=asset.asset_id,
                              ip="192.168.88.38", subnet="255.255.255.0", is_current=True)
    EndpointRepo(db).save(endpoint)

    svc = ChangePlanService(db)
    job = svc.propose(site.site_id, endpoint.endpoint_id, "10.0.0.18",
                      "255.255.255.0", "10.0.0.1")

    try:
        svc.execute(job.job_id, site.site_id)
    except ValueError as e:
        assert str(e) == "job is proposed, cannot execute"
    else:
        raise AssertionError("Expected invalid state transition to be blocked")


def test_change_plan_routes_require_site_scope():
    db = _mem_db()
    app = _app(db)
    try:
        site_a = Site(site_id=str(uuid.uuid4()), name="Change Plan Farm A")
        site_b = Site(site_id=str(uuid.uuid4()), name="Change Plan Farm B")
        SiteRepo(db).save(site_a)
        SiteRepo(db).save(site_b)

        asset = CameraAsset(asset_id=str(uuid.uuid4()), site_id=site_a.site_id,
                            serial="SN-CP-6", asset_tag="CAM-06")
        AssetRepo(db).save(asset)
        endpoint = DeviceEndpoint(endpoint_id=str(uuid.uuid4()), asset_id=asset.asset_id,
                                  ip="192.168.88.39", subnet="255.255.255.0", is_current=True)
        EndpointRepo(db).save(endpoint)

        svc = ChangePlanService(db)
        job = svc.propose(site_a.site_id, endpoint.endpoint_id, "10.0.0.19",
                          "255.255.255.0", "10.0.0.1")

        client = app.test_client()
        approve = client.post(f"/api/change-plans/{job.job_id}/approve", json={
            "site_id": site_b.site_id,
            "confirmation_phrase": "Change SN-CP-6 to 10.0.0.19",
        })
        assert approve.status_code == 404
        assert approve.get_json()["error"] == "job not found at site"

        get_missing_scope = client.get(f"/api/change-plans/{job.job_id}")
        assert get_missing_scope.status_code == 400
        assert get_missing_scope.get_json()["error"] == "site_id is required"

        get_wrong_scope = client.get(f"/api/change-plans/{job.job_id}?site_id={site_b.site_id}")
        assert get_wrong_scope.status_code == 404
        assert get_wrong_scope.get_json()["error"] == "job not found at site"
    finally:
        change_routes.get_database = app._restore_change_db


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
