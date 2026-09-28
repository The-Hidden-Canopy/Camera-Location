"""Database handle and simple migration runner.

This module intentionally stays small: alembic is not required for an offline-first
single-user field tool.  Migrations are plain SQL files executed in lexical order.
"""

from __future__ import annotations

import functools
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


DEFAULT_DB_NAME = "camera_location.db"


class Database:
    """Thin wrapper around sqlite3 with migration support."""

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self._local = {}

    def _connect(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    @property
    def conn(self) -> sqlite3.Connection:
        """Per-process sqlite connection.

        Not thread-safe across threads by design; callers that need concurrency
        should create a new Database instance per thread.
        """
        key = os.getpid()
        conn = self._local.get(key)
        if conn is None:
            conn = self._connect()
            self._local[key] = conn
        return conn

    def execute(self, sql: str, params: Optional[tuple | dict] = None):
        params = params or ()
        return self.conn.execute(sql, params)

    def executescript(self, sql: str):
        with self.conn:
            self.conn.executescript(sql)

    def migrate(self, migrations_dir: Optional[Path] = None):
        """Run any SQL migration files that have not yet been applied."""
        if migrations_dir is None:
            migrations_dir = Path(__file__).with_suffix("").parent / "migrations"

        with self.conn:
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS _migrations ("
                "    version TEXT PRIMARY KEY,"
                "    applied_at TEXT NOT NULL DEFAULT (datetime('now'))"
                ")"
            )

        applied = {
            row["version"]
            for row in self.conn.execute("SELECT version FROM _migrations")
        }

        files = sorted(p for p in migrations_dir.glob("*.sql"))
        for path in files:
            version = path.stem
            if version in applied:
                continue
            sql = path.read_text(encoding="utf-8")
            with self.conn:
                self.conn.executescript(sql)
                self.conn.execute(
                    "INSERT INTO _migrations(version) VALUES(?)", (version,)
                )

    def table_names(self) -> list[str]:
        rows = self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        return [r["name"] for r in rows]


def default_db_path() -> Path:
    """Default on-disk location: '%LOCALAPPDATA%/HiddenCanopy/data/camera_location.db'"""
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_DATA_HOME")
    if not base:
        base = Path.home() / ".local" / "share"
    return Path(base) / "HiddenCanopy" / "data" / DEFAULT_DB_NAME


@functools.lru_cache(maxsize=8)
def get_database(db_path: Optional[str | Path] = None) -> Database:
    path = Path(db_path) if db_path else default_db_path()
    db = Database(path)
    db.migrate()
    return db


def new_uuid() -> str:
    return str(uuid.uuid4())


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")
