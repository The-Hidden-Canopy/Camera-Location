"""Persistence for generic network observations and the offline evidence queue."""
from __future__ import annotations
import json
from datetime import datetime, timezone
from typing import Any
from .db import Database, new_uuid, utcnow_iso


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


class NetworkScopeRepo:
    def __init__(self, db: Database): self.db = db

    def save(self, grant, *, commit=True):
        statement = """INSERT INTO network_scope_grants(scope_id,site_id,cidrs,purpose,actor,authorization_reference,authorization_state,justification,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(scope_id) DO UPDATE SET authorization_state=excluded.authorization_state,expires_at=excluded.expires_at,actor=excluded.actor,justification=excluded.justification"""
        params = (grant.scope_id, grant.site_id, _json(grant.cidrs), grant.purpose, grant.actor, grant.authorization_reference, grant.authorization_state, grant.justification, utcnow_iso(), grant.expires_at.isoformat())
        if commit:
            with self.db.conn: self.db.conn.execute(statement, params)
        else:
            self.db.conn.execute(statement, params)
        return grant

    def get(self, scope_id):
        row = self.db.conn.execute("SELECT * FROM network_scope_grants WHERE scope_id=?", (scope_id,)).fetchone()
        if not row: return None
        from ..domain.network import NetworkScopeGrant
        return NetworkScopeGrant(row["scope_id"], row["site_id"], json.loads(row["cidrs"]), row["purpose"], row["actor"], datetime.fromisoformat(row["expires_at"]), row["authorization_state"], row["authorization_reference"], row["justification"])

    def list_for_site(self, site_id):
        return [self.get(r["scope_id"]) for r in self.db.conn.execute("SELECT scope_id FROM network_scope_grants WHERE site_id=? ORDER BY expires_at DESC", (site_id,))]


class NetworkPacketQueueRepo:
    def __init__(self, db: Database): self.db = db
    def enqueue(self, packet, scope_id, *, commit=True):
        p = packet.to_dict()
        statement = "INSERT INTO network_packet_queue(packet_id,event_id,scope_id,packet_hash,signature,payload,created_at) VALUES(?,?,?,?,?,?,?)"
        params = (new_uuid(), p["event_id"], scope_id, p["packet_hash"], p.get("signature"), _json(p), utcnow_iso())
        if commit:
            with self.db.conn: self.db.conn.execute(statement, params)
        else:
            self.db.conn.execute(statement, params)
        return p
    def list(self, scope_id=None):
        sql = "SELECT * FROM network_packet_queue" + (" WHERE scope_id=?" if scope_id else "") + " ORDER BY created_at"
        return [dict(r) for r in self.db.conn.execute(sql, (scope_id,) if scope_id else ())]

    def list_for_site(self, site_id):
        return [dict(r) for r in self.db.conn.execute("SELECT q.* FROM network_packet_queue q JOIN network_scope_grants g ON g.scope_id=q.scope_id WHERE g.site_id=? ORDER BY q.created_at", (site_id,))]

    def get(self, packet_id):
        row = self.db.conn.execute("SELECT * FROM network_packet_queue WHERE packet_id=?", (packet_id,)).fetchone()
        return dict(row) if row else None

    def retry(self, packet_id, *, error=None, commit=True):
        statement = "UPDATE network_packet_queue SET status='queued', attempts=attempts+1, last_error=? WHERE packet_id=?"
        if commit:
            with self.db.conn: self.db.conn.execute(statement, (error, packet_id))
        else:
            self.db.conn.execute(statement, (error, packet_id))
        return self.get(packet_id)


class NetworkSessionRepo:
    def __init__(self, db: Database): self.db = db

    def save(self, session, *, commit=True):
        statement = """INSERT INTO network_observation_sessions(session_id,collector_id,collector_type,scope_id,observation_methods,authorization_reference,started_at,completed_at,coverage_state,failure_state,resume_cursor) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(session_id) DO UPDATE SET completed_at=excluded.completed_at,coverage_state=excluded.coverage_state,failure_state=excluded.failure_state,resume_cursor=excluded.resume_cursor"""
        params = (session.session_id, session.collector_id, session.collector_type, session.scope_id, _json(session.observation_methods), session.authorization_reference, session.started_at.isoformat(), session.completed_at.isoformat() if session.completed_at else None, session.coverage_state, session.failure_state, session.resume_cursor)
        if commit:
            with self.db.conn: self.db.conn.execute(statement, params)
        else:
            self.db.conn.execute(statement, params)
        return session
