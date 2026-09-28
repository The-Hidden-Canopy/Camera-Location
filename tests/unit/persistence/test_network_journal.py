"""Tests for persistent Windows network change journal."""

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
from camdiscover.persistence.repos import NetworkChangeJournalRepo


def _mem_db():
    db = Database(":memory:")
    db.migrate()
    return db


def test_journal_roundtrip():
    db = _mem_db()
    repo = NetworkChangeJournalRepo(db)
    jid = repo.add(
        operation_id="op-1",
        interface_name="Ethernet",
        ip="192.168.99.50",
        prefix_len=24,
        action="add_secondary_ip",
    )
    incomplete = repo.incomplete()
    assert len(incomplete) == 1
    assert incomplete[0]["ip"] == "192.168.99.50"

    repo.mark_complete(jid)
    assert len(repo.incomplete()) == 0


def test_journal_count():
    db = _mem_db()
    repo = NetworkChangeJournalRepo(db)
    repo.add(operation_id="a", interface_name="Ethernet", ip="192.168.99.1", prefix_len=24, action="add")
    repo.add(operation_id="b", interface_name="Ethernet", ip="192.168.99.2", prefix_len=24, action="add")
    repo.mark_complete(repo.add(operation_id="c", interface_name="Ethernet", ip="192.168.99.3", prefix_len=24, action="add"))
    assert repo.count_incomplete() == 2


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
