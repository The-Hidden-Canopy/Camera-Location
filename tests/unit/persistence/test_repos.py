"""Unit tests for the persistence layer.

These tests run against an in-memory SQLite database and exercise migrations,
repository CRUD, and durable identity lookup paths.
"""

import os
import sqlite3
import sys
import uuid
from pathlib import Path

# Ensure repo root is on path for imports.
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

os.environ.setdefault("CAM_SECRET_BACKEND", "plain")
os.environ.setdefault("CAM_SECRET_DIR", str(Path(__file__).resolve().parent / "_test_secrets"))

from camdiscover.persistence.db import Database
from camdiscover.persistence.repos import (
    SiteRepo,
    NetworkProfileRepo,
    LocationRepo,
    AssetRepo,
    EndpointRepo,
    ObservationRepo,
    TopologyRepo,
    ChangeJobRepo,
)
from camdiscover.domain.models import (
    Site,
    NetworkProfile,
    PhysicalLocation,
    CameraAsset,
    DeviceEndpoint,
    Observation,
    TopologyEdge,
    ChangeJob,
)


def _mem_db():
    """Return a migrated Database backed by an in-memory sqlite connection."""
    db = Database(":memory:")
    db.migrate()
    return db


def _make_site():
    return Site(site_id=str(uuid.uuid4()), name="Test Farm", customer="Acme")


def test_migration_creates_tables():
    db = _mem_db()
    names = db.table_names()
    assert "sites" in names
    assert "camera_assets" in names
    assert "device_endpoints" in names
    assert "observations" in names


def test_site_roundtrip():
    db = _mem_db()
    repo = SiteRepo(db)
    site = Site(
        site_id=str(uuid.uuid4()),
        name="Test Farm",
        customer="Acme",
        authorized_classes=["camera", "nvr", "poe_switch", "wireless_bridge"],
        expected_camera_count=24,
        expected_nvr_channels=32,
        expected_subnets=["192.168.88.0/24", "10.32.57.0/24"],
        expected_gateways=["192.168.88.1", "10.32.57.1"],
        known_old_subnets=["192.168.1.0/24"],
        unauthorized_device_alerts=True,
    )
    repo.save(site)
    loaded = repo.get(site.site_id)
    assert loaded and loaded.name == site.name
    assert loaded.authorized_classes == ["camera", "nvr", "poe_switch", "wireless_bridge"]
    assert loaded.expected_camera_count == 24
    assert loaded.expected_nvr_channels == 32
    assert loaded.expected_subnets == ["192.168.88.0/24", "10.32.57.0/24"]
    assert loaded.expected_gateways == ["192.168.88.1", "10.32.57.1"]
    assert loaded.known_old_subnets == ["192.168.1.0/24"]
    assert loaded.unauthorized_device_alerts is True


def test_network_profile_for_site():
    db = _mem_db()
    site_repo = SiteRepo(db)
    profile_repo = NetworkProfileRepo(db)
    site = _make_site()
    site_repo.save(site)
    profile = NetworkProfile(
        profile_id=str(uuid.uuid4()),
        site_id=site.site_id,
        subnet="192.168.88.0/24",
        gateway="192.168.88.1",
        vlan_id=88,
    )
    profile_repo.save(profile)
    found = profile_repo.find_by_subnet(site.site_id, "192.168.88.0/24")
    assert found and found.gateway == "192.168.88.1"


def test_location_roundtrip():
    db = _mem_db()
    site_repo = SiteRepo(db)
    loc_repo = LocationRepo(db)
    site = _make_site()
    site_repo.save(site)
    loc = PhysicalLocation(
        location_id=str(uuid.uuid4()),
        site_id=site.site_id,
        label="North Gate / Pole 3",
        zone="gate",
    )
    loc_repo.save(loc)
    assert loc_repo.get(loc.location_id).label == loc.label


def test_asset_and_endpoint_identity():
    db = _mem_db()
    site_repo = SiteRepo(db)
    asset_repo = AssetRepo(db)
    endpoint_repo = EndpointRepo(db)

    site = _make_site()
    site_repo.save(site)

    asset = CameraAsset(
        asset_id=str(uuid.uuid4()),
        site_id=site.site_id,
        serial="SN12345",
        manufacturer="Hikvision",
        model="DS-2CD2347G2-LU",
        asset_class="camera",
        operational_role="camera_endpoint",
        criticality="normal",
        reset_risk="moderate",
        human_confirmed=False,
    )
    asset_repo.save(asset)

    found_by_serial = asset_repo.find_by_serial(site.site_id, "SN12345")
    assert found_by_serial and found_by_serial.asset_id == asset.asset_id
    assert found_by_serial.asset_class == "camera"
    assert found_by_serial.operational_role == "camera_endpoint"
    assert found_by_serial.reset_risk == "moderate"

    endpoint = DeviceEndpoint(
        endpoint_id=str(uuid.uuid4()),
        asset_id=asset.asset_id,
        ip="192.168.88.34",
        mac="18:68:cb:11:22:33",
        is_current=True,
        device_class="camera",
    )
    endpoint_repo.save(endpoint)

    by_mac = endpoint_repo.find_by_mac("18-68-cb-11-22-33")
    assert by_mac and by_mac.asset_id == asset.asset_id


def test_endpoint_move_preserves_history():
    db = _mem_db()
    site_repo = SiteRepo(db)
    asset_repo = AssetRepo(db)
    endpoint_repo = EndpointRepo(db)

    site = _make_site()
    site_repo.save(site)

    asset = CameraAsset(
        asset_id=str(uuid.uuid4()), site_id=site.site_id, serial="SN-MOVE"
    )
    asset_repo.save(asset)

    endpoint = DeviceEndpoint(
        endpoint_id=str(uuid.uuid4()),
        asset_id=asset.asset_id,
        ip="192.168.88.34",
        mac="18:68:cb:11:22:33",
        ip_history=["192.168.88.34"],
        is_current=True,
    )
    endpoint_repo.save(endpoint)

    # Simulate IP move: mark old endpoint not current, create new endpoint.
    endpoint_repo.mark_not_current(endpoint.endpoint_id)
    new_endpoint = DeviceEndpoint(
        endpoint_id=str(uuid.uuid4()),
        asset_id=asset.asset_id,
        ip="10.32.57.118",
        mac="18:68:cb:11:22:33",
        ip_history=["192.168.88.34", "10.32.57.118"],
        is_current=True,
    )
    endpoint_repo.save(new_endpoint)

    history = endpoint_repo.list_for_asset(asset.asset_id)
    assert len(history) == 2
    current = [e for e in history if e.is_current]
    assert len(current) == 1 and current[0].ip == "10.32.57.118"


def test_observation_append_only():
    db = _mem_db()
    site_repo = SiteRepo(db)
    endpoint_repo = EndpointRepo(db)
    observation_repo = ObservationRepo(db)

    site = _make_site()
    site_repo.save(site)

    endpoint = DeviceEndpoint(
        endpoint_id=str(uuid.uuid4()),
        ip="192.168.88.10",
        mac="18:68:cb:aa:bb:cc",
        is_current=True,
    )
    endpoint_repo.save(endpoint)

    obs = Observation(
        observation_id=str(uuid.uuid4()),
        site_id=site.site_id,
        endpoint_id=endpoint.endpoint_id,
        kind="arp_seen",
        detail="Seen in ARP table",
        source="arp",
        weight=40,
    )
    observation_repo.save(obs)

    observations = observation_repo.list_for_endpoint(endpoint.endpoint_id)
    assert len(observations) == 1
    assert observations[0].weight == 40


def test_topology_edge_roundtrip():
    db = _mem_db()
    site_repo = SiteRepo(db)
    topology_repo = TopologyRepo(db)
    site = _make_site()
    site_repo.save(site)
    edge = TopologyEdge(
        edge_id=str(uuid.uuid4()),
        site_id=site.site_id,
        from_id="asset-1",
        from_type="asset",
        to_id="switch-1",
        to_type="switch",
        relation="connected_to",
        detail="port 12",
    )
    topology_repo.save(edge)
    assert topology_repo.list_for_site(site.site_id)[0].detail == "port 12"


def test_change_job_status():
    db = _mem_db()
    site_repo = SiteRepo(db)
    job_repo = ChangeJobRepo(db)
    site = _make_site()
    site_repo.save(site)
    job = ChangeJob(
        job_id=str(uuid.uuid4()),
        site_id=site.site_id,
        kind="ip_change",
        proposed={"new_ip": "192.168.88.50"},
        status="draft",
    )
    job_repo.save(job)
    loaded = job_repo.get(job.job_id)
    assert loaded and loaded.proposed["new_ip"] == "192.168.88.50"


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
