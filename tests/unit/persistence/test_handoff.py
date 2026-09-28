"""Tests for handoff package export/import and location verification."""

import os
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

os.environ.setdefault("CAM_SECRET_BACKEND", "plain")
os.environ.setdefault("CAM_SECRET_DIR", str(Path(__file__).resolve().parent / "_test_secrets"))

from camdiscover.domain.models import Site, CameraAsset, PhysicalLocation, NetworkProfile
from camdiscover.persistence.db import Database
from camdiscover.persistence.repos import SiteRepo, AssetRepo, LocationRepo, NetworkProfileRepo
from camdiscover.services.handoff import HandoffService
from camdiscover.services.location_verification import LocationVerificationService


def _mem_db():
    db = Database(":memory:")
    db.migrate()
    return db


def test_location_verification():
    db = _mem_db()
    site = Site(site_id=str(uuid.uuid4()), name="Verify Farm")
    SiteRepo(db).save(site)
    asset = CameraAsset(asset_id=str(uuid.uuid4()), site_id=site.site_id,
                        serial="SN-VERIFY", asset_tag="CAM-02")
    AssetRepo(db).save(asset)

    svc = LocationVerificationService(db)
    result = svc.verify_asset(
        site.site_id, asset.asset_id,
        label="South Gate / Pole 1", zone="gate", direction="North",
        qr_code="QR-001", detail="Confirmed with installer.",
        photos=[],  # skip binary photo in unit test
    )

    assert result["qr_code"] == "QR-001"
    assert result["installed_status"] == "verified"
    asset = AssetRepo(db).get(asset.asset_id)
    assert asset.installed_status == "verified"
    assert asset.human_confirmed is True
    assert asset.expected_location_id == result["location_id"]


def test_handoff_roundtrip():
    db = _mem_db()
    site = Site(site_id=str(uuid.uuid4()), name="Handoff Farm", customer="Acme")
    SiteRepo(db).save(site)

    profile = NetworkProfile(profile_id=str(uuid.uuid4()), site_id=site.site_id,
                             subnet="192.168.88.0/24", label="Camera VLAN")
    NetworkProfileRepo(db).save(profile)

    loc = PhysicalLocation(location_id=str(uuid.uuid4()), site_id=site.site_id,
                           label="North Gate / Pole 3", zone="gate")
    LocationRepo(db).save(loc)

    asset = CameraAsset(asset_id=str(uuid.uuid4()), site_id=site.site_id,
                        asset_tag="CAM-01", serial="SN-HANDOFF-1",
                        manufacturer="Hikvision", model="DS-2CD2347",
                        asset_class="camera", operational_role="camera_endpoint",
                        criticality="normal", reset_risk="moderate",
                        human_confirmed=True,
                        expected_location_id=loc.location_id,
                        installed_status="verified")
    AssetRepo(db).save(asset)

    svc = HandoffService(db)
    path = svc.export(site.site_id)
    assert path.exists()

    # Import into a fresh DB
    db2 = _mem_db()
    svc2 = HandoffService(db2)
    imported = svc2.import_package(path)

    imported_site = SiteRepo(db2).get(imported)
    assert imported_site and imported_site.name == "Handoff Farm"

    imported_assets = AssetRepo(db2).list_for_site(imported)
    assert len(imported_assets) == 1
    assert imported_assets[0].serial == "SN-HANDOFF-1"
    assert imported_assets[0].asset_class == "camera"
    assert imported_assets[0].operational_role == "camera_endpoint"
    assert imported_assets[0].human_confirmed is True
    assert imported_assets[0].expected_location_id is not None


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
