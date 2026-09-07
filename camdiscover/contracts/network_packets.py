"""Canonical, signed packets exchanged with the RegOS network-mapping context."""
from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

SCHEMA_VERSION = "1.0"
PACKET_TYPES = {"DeviceDiscoveryCandidate", "NetworkObservationEvent", "PhysicalLocationVerificationEvent"}
INBOUND_PACKET_TYPES = {"FacilityRegistryProjection", "AuthorizedDeviceSnapshot"}
ALL_PACKET_TYPES = PACKET_TYPES | INBOUND_PACKET_TYPES
OBSERVATION_KINDS = frozenset({
    "asset_seen", "interface_seen", "address_seen", "interface_address_seen",
    "service_seen", "segment_observed", "topology_edge_observed",
    "coverage_gap", "contradictory_evidence", "operator_verification",
})


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _utc(value: Optional[datetime] = None) -> str:
    value = value or datetime.now(timezone.utc)
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("packet timestamps must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class NetworkPacket:
    def __init__(self, envelope: dict[str, Any]):
        self.envelope = envelope

    @classmethod
    def create(cls, *, event_type: str, payload: dict[str, Any], source_system: str,
               source_surface: str, tenant_id: str, facility_id: str,
               collector_id: str, scope_id: str, evidence_refs: list[str],
               ambiguity: list[str], freshness: str, redaction_policy: str = "minimal",
               actor_id: str = "", signature_key: Optional[bytes] = None,
               occurred_at: Optional[datetime] = None,
               authorization_reference: str = "") -> "NetworkPacket":
        if event_type not in PACKET_TYPES:
            raise ValueError("unsupported network packet type")
        event_id = str(uuid.uuid4())
        body = {
            "event_id": event_id, "event_type": event_type, "schema_version": SCHEMA_VERSION,
            "occurred_at": _utc(occurred_at), "recorded_at": _utc(),
            "source_system": source_system, "source_surface": source_surface,
            "tenant_id": tenant_id, "facility_id": facility_id, "actor_id": actor_id,
            "device_id": payload.get("asset_id", ""), "subject_ids": payload.get("subject_ids", []),
            "jurisdiction": payload.get("jurisdiction"),
            "authority_context": {
                "collector_id": collector_id,
                "scope_id": scope_id,
                **({"authorization_reference": authorization_reference} if authorization_reference else {}),
            },
            "evidence_refs": evidence_refs, "ambiguity": ambiguity,
            "freshness": freshness, "human_approval": {"state": "not_authorized"},
            "trust_state_before": None, "trust_state_after": None,
            "redaction_policy": redaction_policy, "ontology_version": "network-1",
            "parent_event_ids": [], "accepted_for_memory": False, "accepted_for_training": False,
            "accepted_for_benchmark": False, "payload_type": "network_mapping", "payload": payload,
            "idempotency_key": f"{source_system}:{collector_id}:{event_id}",
        }
        digest = hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()
        body["packet_hash"] = digest
        body["signature"] = hmac.new(signature_key, digest.encode(), hashlib.sha256).hexdigest() if signature_key else None
        return cls(body)

    @classmethod
    def from_dict(cls, envelope: dict[str, Any]) -> "NetworkPacket":
        required = {"event_id", "event_type", "schema_version", "occurred_at", "recorded_at", "source_system", "source_surface", "tenant_id", "facility_id", "actor_id", "device_id", "subject_ids", "jurisdiction", "authority_context", "evidence_refs", "trust_state_before", "trust_state_after", "ambiguity", "freshness", "human_approval", "redaction_policy", "ontology_version", "parent_event_ids", "accepted_for_memory", "accepted_for_training", "accepted_for_benchmark", "payload_type", "payload", "packet_hash", "idempotency_key"}
        missing = required - set(envelope)
        if missing:
            raise ValueError(f"packet missing required fields: {sorted(missing)}")
        if envelope["event_type"] not in ALL_PACKET_TYPES:
            raise ValueError("unsupported network packet type")
        if not str(envelope["schema_version"]).startswith("1."):
            raise ValueError("unsupported network packet major version")
        return cls(dict(envelope))

    def _unsigned_body(self) -> dict[str, Any]:
        return {k: v for k, v in self.envelope.items() if k not in {"packet_hash", "signature"}}

    def verify(self, signature_key: Optional[bytes] = None, *, require_signature: bool = False) -> bool:
        expected = hashlib.sha256(_canonical(self._unsigned_body()).encode("utf-8")).hexdigest()
        if not hmac.compare_digest(expected, str(self.envelope.get("packet_hash", ""))):
            return False
        signature = self.envelope.get("signature")
        if require_signature and not signature:
            return False
        if signature:
            if not signature_key:
                return False
            actual = hmac.new(signature_key, expected.encode(), hashlib.sha256).hexdigest()
            return hmac.compare_digest(actual, str(signature))
        return True

    def to_dict(self) -> dict[str, Any]:
        return dict(self.envelope)
