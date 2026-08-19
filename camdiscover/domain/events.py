"""Small, durable domain-event primitive used by governed mutations."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from ..persistence.db import Database, new_uuid


@dataclass(frozen=True)
class DomainEvent:
    aggregate_type: str
    aggregate_id: str
    event_type: str
    actor: str
    justification: str
    site_id: Optional[str] = None
    from_state: Optional[str] = None
    to_state: Optional[str] = None
    payload: dict[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=new_uuid)
    occurred_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def append_domain_event(db: Database, event: DomainEvent) -> DomainEvent:
    """Append one event; callers must provide a non-empty justification."""
    if not event.justification.strip():
        raise ValueError("domain event justification is required")
    db.execute(
        """INSERT INTO domain_events
           (event_id, site_id, aggregate_type, aggregate_id, event_type,
            from_state, to_state, actor, justification, payload, occurred_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            event.event_id,
            event.site_id,
            event.aggregate_type,
            event.aggregate_id,
            event.event_type,
            event.from_state,
            event.to_state,
            event.actor,
            event.justification,
            json.dumps(event.payload, ensure_ascii=False),
            event.occurred_at.isoformat(),
        ),
    )
    db.conn.commit()
    return event
