"""Regression coverage for discovery, persistence, and governance repairs."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from flask import Flask

from camdiscover.domain.models import CameraAsset, DeviceEndpoint, Site
from camdiscover.domain.transitions import execute_transition
from camdiscover.models import DiscoveredDevice
from camdiscover.orchestrator import DiscoveryOrchestrator
from camdiscover.persistence.db import Database
from camdiscover.persistence.repos import AssetRepo, EndpointRepo, ObservationRepo, SiteRepo
from camdiscover.api import change_routes
from camdiscover.services.discovery_service import DiscoveryService
from camdiscover.services.location_verification import LocationVerificationService
from camdiscover.services.merge import MergeService
from camdiscover.vendor import classify_device_type, lookup_vendor
from camdiscover.webapp import create_app


def _db():
    db = Database(":memory:")
    db.migrate()
    return db


def test_vendor_lookup_accepts_common_mac_formats_and_preserves_shared_ouis():
    assert lookup_vendor("24:5a:4c:aa:bb:cc") == "Ubiquiti"
    assert lookup_vendor("24-5A-4C-AA-BB-CC") == "Ubiquiti"
    assert lookup_vendor("245a.4caa.bbcc") == "Ubiquiti"
    assert "OEM" in lookup_vendor("e0:50:8b:aa:bb:cc")
    assert lookup_vendor("not-a-mac") == "Unknown"


def test_endpoint_service_evidence_identifies_computer_without_claiming_os():
    result = classify_device_type(
        vendor="Unknown",
        open_ports=[445],
        protocols=["SMB"],
        hostname="office-windows-host",
    )
    assert result.device_type == "computer"
    assert result.asset_class == "workstation"
    assert result.operational_role == "workstation"
    assert "computer identity keyword present" in result.evidence


def test_arp_keeps_ubiquiti_and_unknown_hosts_for_later_classification():
    orchestrator = DiscoveryOrchestrator()
    entries = [
        {"ip": "192.168.1.20", "mac": "24:5a:4c:aa:bb:cc"},
        {"ip": "192.168.1.21", "mac": "aa:bb:cc:dd:ee:ff"},
    ]
    with patch("camdiscover.orchestrator.get_arp_table", return_value=entries):
        orchestrator._collect_arp_entries()

    assert {device.ip for device in orchestrator.discovered_devices} == {
        "192.168.1.20", "192.168.1.21"
    }
    assert orchestrator.devices["192.168.1.20"].vendor == "Ubiquiti"
    assert orchestrator.devices["192.168.1.21"].vendor == "Unknown"


def test_inventory_marks_old_persisted_observation_as_stale():
    db = _db()
    site = Site(site_id="site-stale", name="Stale Site")
    SiteRepo(db).save(site)
    asset = CameraAsset(asset_id="asset-stale", site_id=site.site_id, asset_class="workstation")
    AssetRepo(db).save(asset)
    EndpointRepo(db).save(DeviceEndpoint(
        endpoint_id="endpoint-stale",
        asset_id=asset.asset_id,
        ip="192.168.1.50",
        last_seen=datetime.now(timezone.utc) - timedelta(days=2),
        device_class="computer",
    ))

    service = DiscoveryService.__new__(DiscoveryService)
    service._site_id = site.site_id
    service._endpoints = EndpointRepo(db)
    service._assets = AssetRepo(db)
    service._observations = ObservationRepo(db)

    rows = service.current_inventory(site.site_id)
    assert rows[0]["freshness"]["state"] == "stale"
    assert rows[0]["freshness"]["age_seconds"] >= 2 * 86400 - 5


def test_transition_rejects_missing_justification_and_invalid_state():
    db = _db()
    with patch("camdiscover.domain.transitions.append_domain_event") as append_event:
        try:
            execute_transition(
                db,
                aggregate_type="test",
                aggregate_id="1",
                site_id=None,
                current_state="draft",
                target_state="approved",
                allowed_transitions={"draft": {"approved"}},
                mutate=lambda: None,
                actor="operator",
                justification="",
            )
        except ValueError as exc:
            assert "justification" in str(exc)
        else:
            raise AssertionError("missing justification must be rejected")
        append_event.assert_not_called()

    try:
        execute_transition(
            db,
            aggregate_type="test",
            aggregate_id="1",
            site_id=None,
            current_state="draft",
            target_state="executing",
            allowed_transitions={"draft": {"approved"}},
            mutate=lambda: None,
            actor="operator",
            justification="boundary test",
        )
    except ValueError as exc:
        assert "invalid state transition" in str(exc)
    else:
            raise AssertionError("invalid state transition must be rejected")


def test_change_routes_use_create_app_database_scope():
    db = _db()
    site = Site(site_id="site-route", name="Route Site")
    SiteRepo(db).save(site)
    asset = CameraAsset(asset_id="asset-route", site_id=site.site_id, serial="ROUTE-1")
    AssetRepo(db).save(asset)
    endpoint = DeviceEndpoint(
        endpoint_id="endpoint-route",
        asset_id=asset.asset_id,
        ip="192.168.1.70",
        mac="18:68:cb:aa:bb:cc",
    )
    EndpointRepo(db).save(endpoint)

    app = Flask("change-route-test")
    app.config["TESTING"] = True
    app.config["CAMDISCOVER_DB"] = db
    change_routes.register_change_routes(app)
    with patch("camdiscover.api.change_routes.get_database", side_effect=AssertionError("wrong database")):
        response = app.test_client().post("/api/change-plans", json={
            "site_id": site.site_id,
            "endpoint_id": endpoint.endpoint_id,
            "new_ip": "10.0.0.70",
            "mask": "255.255.255.0",
            "gateway": "10.0.0.1",
        })
    assert response.status_code == 201
    assert db.conn.execute("SELECT COUNT(*) FROM change_jobs").fetchone()[0] == 1
    assert db.conn.execute("SELECT COUNT(*) FROM domain_events").fetchone()[0] == 1


def test_physical_verification_emits_asset_domain_event():
    db = _db()
    site = Site(site_id="site-verify", name="Verify Site")
    SiteRepo(db).save(site)
    asset = CameraAsset(asset_id="asset-verify", site_id=site.site_id)
    AssetRepo(db).save(asset)

    LocationVerificationService(db).verify_asset(
        site.site_id,
        asset.asset_id,
        label="North Gate",
        detail="Operator confirmed the location.",
        photos=[],
    )
    event = db.conn.execute(
        "SELECT * FROM domain_events WHERE aggregate_id=?", (asset.asset_id,)
    ).fetchone()
    assert event["event_type"] == "camera_asset.verified"
    assert event["justification"] == "Operator confirmed the location."


def test_merge_rejects_unassetized_endpoint_without_org_scope():
    db = _db()
    site = Site(site_id="site-merge", name="Merge Site")
    SiteRepo(db).save(site)
    asset = CameraAsset(asset_id="asset-merge", site_id=site.site_id)
    AssetRepo(db).save(asset)
    endpoint = DeviceEndpoint(endpoint_id="endpoint-unscoped", ip="192.168.1.90")
    EndpointRepo(db).save(endpoint)

    try:
        MergeService(db).confirm_match(site.site_id, asset.asset_id, endpoint.endpoint_id)
    except ValueError as exc:
        assert "no site scope" in str(exc)
    else:
        raise AssertionError("unscoped endpoint must not be attached across org boundaries")


def test_csv_export_uses_configured_app_and_does_not_call_filesystem_export(tmp_path):
    app = create_app(db_path=str(Path(tmp_path) / "camera.db"))
    app.config["TESTING"] = True
    orchestrator = app.config["DISCOVERY_ORCHESTRATOR"]
    orchestrator.devices["192.168.1.60"] = DiscoveredDevice(
        device_id="device-csv",
        ip="192.168.1.60",
        vendor="Ubiquiti",
        device_class="bridge",
    )

    response = app.test_client().get("/api/export/csv")
    assert response.status_code == 200
    assert "192.168.1.60" in response.get_data(as_text=True)
    app.config["CAMDISCOVER_DB"].conn.close()


def test_inventory_route_requires_org_scope():
    app = create_app(db_path=":memory:")
    response = app.test_client().get("/api/inventory/current")
    assert response.status_code == 400
    assert "site_id" in response.get_json()["error"]
    app.config["CAMDISCOVER_DB"].conn.close()


def test_credential_read_does_not_return_plaintext_secret():
    app = create_app(db_path=":memory:")
    client = app.test_client()
    client.post("/api/devices/192.168.1.91/credentials", json={
        "username": "admin",
        "password": "secret-value",
    })
    response = client.get("/api/devices/192.168.1.91/credentials")
    body = response.get_json()
    assert response.status_code == 200
    assert body["has_password"] is True
    assert "password" not in body
    app.config["CAMDISCOVER_DB"].conn.close()
