"""Tests for topology import and path queries."""

import os
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

os.environ.setdefault("CAM_SECRET_BACKEND", "plain")
os.environ.setdefault("CAM_SECRET_DIR", str(Path(__file__).resolve().parent / "_test_secrets"))

from camdiscover.domain.models import Site
from camdiscover.persistence.db import Database
from camdiscover.persistence.repos import SiteRepo
from camdiscover.services.topology import TopologyService


def _mem_db():
    db = Database(":memory:")
    db.migrate()
    return db


def test_topology_import_and_path():
    db = _mem_db()
    site = Site(site_id=str(uuid.uuid4()), name="Top Farm")
    SiteRepo(db).save(site)

    csv_text = "from_id,from_type,to_id,to_type,relation,detail,verified\n" \
               "CAM-01,asset,SW-CORE,switch,connected_to,port 12,true\n" \
               "SW-CORE,switch,UPLINK-1,radio,uplink_to,,\n"

    svc = TopologyService(db)
    result = svc.import_csv(site.site_id, csv_text)
    assert result["created"] == 2
    assert len(result["errors"]) == 0

    path = svc.path_to_camera(site.site_id, "CAM-01")
    assert len(path) == 2
    assert path[0]["relation"] == "connected_to"
    assert path[1]["relation"] == "uplink_to"


def test_topology_add_edge():
    db = _mem_db()
    site = Site(site_id=str(uuid.uuid4()), name="Top Farm")
    SiteRepo(db).save(site)
    svc = TopologyService(db)
    edge = svc.add_edge(site.site_id, "CAM-02", "asset", "NVR-01", "nvr", "nvr_channel", "channel 3")
    assert edge.relation == "nvr_channel"
    assert edge.site_id == site.site_id


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
