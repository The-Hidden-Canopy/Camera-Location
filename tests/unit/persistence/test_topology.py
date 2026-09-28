"""Tests for topology import and path queries."""

import os
import sys
import uuid
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

os.environ.setdefault("CAM_SECRET_BACKEND", "plain")
os.environ.setdefault("CAM_SECRET_DIR", str(Path(__file__).resolve().parent / "_test_secrets"))

from camdiscover.domain.models import Site
from camdiscover.persistence.db import Database
from camdiscover.persistence.repos import ObservationRepo, SiteRepo
from camdiscover.services.topology import TopologyService


def _mem_db():
    db = Database(":memory:")
    db.migrate()
    return db


def test_topology_import_and_path():
    db = _mem_db()
    site = Site(site_id=str(uuid.uuid4()), name="Top Farm")
    SiteRepo(db).save(site)

    csv_text = "from_id,from_type,to_id,to_type,relation,detail,verified,verification_evidence\n" \
               "CAM-01,asset,SW-CORE,switch,connected_to,port 12,true,operator inspected port 12\n" \
               "SW-CORE,switch,UPLINK-1,radio,uplink_to,,\n"

    svc = TopologyService(db)
    result = svc.import_csv(site.site_id, csv_text)
    assert result["created"] == 2
    assert result["replayed"] == 0
    assert len(result["errors"]) == 0

    replay = svc.import_csv(site.site_id, csv_text)
    assert replay["created"] == 0
    assert replay["replayed"] == 2
    assert len(svc.graph_for_site(site.site_id)) == 2
    assert len(ObservationRepo(db).list_for_site(site.site_id)) == 2

    path = svc.path_to_camera(site.site_id, "CAM-01")
    assert len(path) == 2
    assert path[0]["relation"] == "connected_to"
    assert path[1]["relation"] == "uplink_to"


def test_topology_add_edge():
    db = _mem_db()
    site = Site(site_id=str(uuid.uuid4()), name="Top Farm")
    SiteRepo(db).save(site)
    svc = TopologyService(db)
    edge = svc.add_edge(site.site_id, "CAM-02", "asset", "NVR-01", "nvr", "nvr_channel", "channel 3", justification="record camera to NVR topology")
    assert edge.relation == "nvr_channel"
    assert edge.site_id == site.site_id
    persisted = svc.graph_for_site(site.site_id)[0]
    assert persisted["source_observation_id"]
    assert persisted["observed_at"]
    assert persisted["validity_start"]
    assert persisted["evidence_state"] == "observed"


def test_topology_event_failure_rolls_back_edge_and_observation():
    db = _mem_db()
    site = Site(site_id=str(uuid.uuid4()), name="Top Farm")
    SiteRepo(db).save(site)
    svc = TopologyService(db)

    with patch(
        "camdiscover.services.topology.append_domain_event",
        side_effect=RuntimeError("audit unavailable"),
    ):
        try:
            svc.add_edge(site.site_id, "CAM-03", "asset", "SW-CORE", "switch", "connected_to", justification="record topology before audit failure")
        except RuntimeError as exc:
            assert str(exc) == "audit unavailable"
        else:
            raise AssertionError("topology mutation unexpectedly committed")

    assert svc.graph_for_site(site.site_id) == []
    assert ObservationRepo(db).list_for_site(site.site_id) == []


def test_topology_add_requires_justification():
    db = _mem_db()
    site = Site(site_id=str(uuid.uuid4()), name="Top Farm")
    SiteRepo(db).save(site)
    with patch("camdiscover.services.topology.append_domain_event") as append_event:
        try:
            TopologyService(db).add_edge(site.site_id, "CAM-05", "asset", "SW-CORE", "switch", "connected_to")
        except ValueError as exc:
            assert str(exc) == "topology justification is required"
        else:
            raise AssertionError("topology mutation unexpectedly accepted missing justification")
        append_event.assert_not_called()


def test_verified_topology_import_without_operator_evidence_is_rejected():
    db = _mem_db()
    site = Site(site_id=str(uuid.uuid4()), name="Top Farm")
    SiteRepo(db).save(site)
    result = TopologyService(db).import_csv(
        site.site_id,
        "from_id,from_type,to_id,to_type,relation,detail,verified\n"
        "CAM-04,asset,SW-CORE,switch,connected_to,port 4,true\n",
    )
    assert result["created"] == 0
    assert result["errors"] == ["verified topology requires explicit operator evidence"]


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
