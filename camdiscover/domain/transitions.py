"""Governed state-transition helper.

Services use this chokepoint before saving a changed aggregate.  The helper
validates the transition and emits its event immediately after the mutation.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any, Optional

from ..persistence.db import Database
from .events import DomainEvent, append_domain_event


ASSET_STATUS_TRANSITIONS = {
    "planned": {"installed", "verified", "retired"},
    "installed": {"verified", "moved", "replaced", "retired"},
    "unverified": {"installed", "verified", "moved", "replaced", "retired"},
    "verified": {"verified", "moved", "replaced", "retired"},
    "moved": {"installed", "verified", "retired"},
    "replaced": {"retired"},
    "retired": set(),
}


def execute_transition(
    db: Database,
    *,
    aggregate_type: str,
    aggregate_id: str,
    site_id: Optional[str],
    current_state: str,
    target_state: str,
    allowed_transitions: Mapping[str, set[str]],
    mutate: Callable[[], Any],
    actor: str,
    justification: str,
    payload: Optional[dict[str, Any]] = None,
) -> Any:
    """Validate, perform, and record one state transition."""
    if not justification.strip():
        raise ValueError("transition justification is required")
    if target_state not in allowed_transitions.get(current_state, set()):
        raise ValueError(
            f"invalid state transition: {current_state} -> {target_state}"
        )
    result = mutate()
    append_domain_event(
        db,
        DomainEvent(
            site_id=site_id,
            aggregate_type=aggregate_type,
            aggregate_id=aggregate_id,
            event_type=f"{aggregate_type}.{target_state}",
            from_state=current_state,
            to_state=target_state,
            actor=actor,
            justification=justification,
            payload=payload or {},
        ),
    )
    return result
