"""Governance tests for legacy webapp mutation routes."""

import os
import shutil
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
from camdiscover.webapp import create_app
import camdiscover.webapp as webapp
from camdiscover.api import change_routes


def _db_at(path: Path) -> Database:
    db = Database(path)
    db.migrate()
    return db


def _workspace_temp_dir() -> Path:
    path = ROOT / ".pytest_cache" / "webapp-governance" / str(uuid.uuid4())
    path.mkdir(parents=True, exist_ok=True)
    return path


def test_legacy_set_ip_route_is_disabled():
    temp_dir = _workspace_temp_dir()
    db_path = temp_dir / "governance.db"
    app = create_app(db_path=str(db_path))

    original_onvif = webapp._set_ip_onvif
    original_hikvision = webapp._set_ip_hikvision
    original_dahua = webapp._set_ip_dahua
    try:
        def _unexpected(*args, **kwargs):
            raise AssertionError("legacy mutation helper should not be called")

        webapp._set_ip_onvif = _unexpected
        webapp._set_ip_hikvision = _unexpected
        webapp._set_ip_dahua = _unexpected

        client = app.test_client()
        resp = client.post("/api/devices/192.168.88.34/set-ip", json={
            "new_ip": "10.0.0.15",
            "netmask": "255.255.255.0",
            "gateway": "10.0.0.1",
            "username": "admin",
            "password": "secret",
        })
    finally:
        webapp._set_ip_onvif = original_onvif
        webapp._set_ip_hikvision = original_hikvision
        webapp._set_ip_dahua = original_dahua
        shutil.rmtree(temp_dir, ignore_errors=True)

    assert resp.status_code == 410
    body = resp.get_json()
    assert body["error"] == "direct device mutation is disabled"
    assert body["required_flow"] == "/api/change-plans"


def test_governed_change_plan_route_still_records_observation():
    temp_dir = _workspace_temp_dir()
    try:
        db_path = temp_dir / "governance.db"
        db = _db_at(db_path)

        site = Site(site_id=str(uuid.uuid4()), name="Governed Web Farm")
        SiteRepo(db).save(site)
        asset = CameraAsset(
            asset_id=str(uuid.uuid4()),
            site_id=site.site_id,
            serial="SN-WEB-1",
            asset_tag="CAM-WEB-1",
        )
        AssetRepo(db).save(asset)
        endpoint = DeviceEndpoint(
            endpoint_id=str(uuid.uuid4()),
            asset_id=asset.asset_id,
            ip="192.168.88.40",
            mac="18:68:cb:11:22:66",
            subnet="255.255.255.0",
            is_current=True,
        )
        EndpointRepo(db).save(endpoint)

        original_get_database = change_routes.get_database
        try:
            change_routes.get_database = lambda: db
            app = create_app(db_path=str(db_path))
            client = app.test_client()

            propose = client.post("/api/change-plans", json={
                "site_id": site.site_id,
                "endpoint_id": endpoint.endpoint_id,
                "new_ip": "10.0.0.20",
                "mask": "255.255.255.0",
                "gateway": "10.0.0.1",
                "user_id": "operator-1",
            })

            assert propose.status_code == 201
            body = propose.get_json()
            assert body["status"] == "proposed"
            assert body["site_id"] == site.site_id

            logged = ObservationRepo(db).list_for_endpoint(endpoint.endpoint_id)
            assert any(obs.kind == "change_plan_proposed" for obs in logged)
        finally:
            change_routes.get_database = original_get_database
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
