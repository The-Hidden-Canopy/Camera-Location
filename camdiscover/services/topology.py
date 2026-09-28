"""Topology graph service: NVR, switches, radios, PoE, camera links.

Provides import helpers for CSV / LLDP-like / manual entries and exposes the
graph API the installer uses to understand how a camera is connected.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..domain.models import TopologyEdge, Observation
from ..persistence.db import Database, new_uuid
from ..persistence.repos import TopologyRepo, ObservationRepo
from ..domain.events import DomainEvent, append_domain_event

NETWORK_NODE_TYPES = {
    "asset", "interface", "address", "service", "segment", "switch_port",
    "wireless_association", "gateway", "route_boundary", "nvr", "radio", "switch",
}
NETWORK_RELATIONS = {
    "connected_to", "attached_to_port", "uplink_to", "member_of_segment",
    "routes_through", "wireless_associated_with", "hosts_service", "powered_by",
    "observed_near", "nvr_channel",
}


class TopologyService:
    def __init__(self, db: Database):
        self._db = db
        self._topo = TopologyRepo(db)
        self._obs = ObservationRepo(db)

    def add_edge(
        self,
        site_id: str,
        from_id: str,
        from_type: str,
        to_id: str,
        to_type: str,
        relation: str,
        detail: str = "",
        verified: bool = False,
        verification_evidence: str = "",
        justification: str = "",
        actor: str = "operator",
        edge_id: Optional[str] = None,
    ) -> TopologyEdge:
        if not isinstance(from_id, str) or not isinstance(to_id, str) or not from_id.strip() or not to_id.strip():
            raise ValueError("topology identifiers are required")
        if from_type not in NETWORK_NODE_TYPES or to_type not in NETWORK_NODE_TYPES:
            raise ValueError("unsupported topology node type")
        if relation not in NETWORK_RELATIONS:
            raise ValueError("unsupported topology relation")
        if not isinstance(justification, str) or not justification.strip():
            raise ValueError("topology justification is required")
        if verified and (not isinstance(verification_evidence, str) or not verification_evidence.strip()):
            raise ValueError("verified topology requires explicit operator evidence")
        observed_at = datetime.now(timezone.utc)
        edge = TopologyEdge(
            edge_id=edge_id or new_uuid(),
            site_id=site_id,
            from_id=from_id,
            from_type=from_type,
            to_id=to_id,
            to_type=to_type,
            relation=relation,
            detail=(f"{detail}; {verification_evidence.strip()}"[:255] if verified else detail),
            verified=verified,
            observed_at=observed_at,
            validity_start=observed_at,
            confidence="verified" if verified else "observed",
            evidence_state="verified" if verified else "observed",
        )
        observation = Observation(
            observation_id=new_uuid(),
            site_id=site_id,
            kind="topology_edge_added",
            detail=f"{from_type} {from_id} {relation} {to_type} {to_id}",
            source="operator",
            weight=0,
        )
        edge.source_observation_id = observation.observation_id
        edge.evidence_refs = [observation.observation_id]
        with self._db.conn:
            self._topo.save(edge, commit=False)
            self._obs.save(observation, commit=False)
            append_domain_event(self._db, DomainEvent(
                aggregate_type="topology_edge", aggregate_id=edge.edge_id,
                event_type="topology.edge_observed", actor=actor,
                justification=justification, site_id=site_id,
                payload=edge.to_dict(),
            ), commit=False)
        return edge

    def import_csv(self, site_id: str, csv_text: str) -> Dict[str, Any]:
        """Import topology from a CSV with columns:
        from_id,from_type,to_id,to_type,relation,detail,verified,verification_evidence.
        """
        reader = csv.DictReader(io.StringIO(csv_text.strip()))
        created = 0
        replayed = 0
        errors: List[str] = []
        for row in reader:
            try:
                from_id = row["from_id"].strip()
                from_type = row["from_type"].strip()
                to_id = row["to_id"].strip()
                to_type = row["to_type"].strip()
                relation = row["relation"].strip()
                detail = row.get("detail", "").strip()
                verified = row.get("verified", "").strip().lower() in ("1", "true", "yes")
                verification_evidence = (row.get("verification_evidence") or "").strip()
                replay_key = json.dumps(
                    {
                        "site_id": site_id,
                        "from_id": from_id,
                        "from_type": from_type,
                        "to_id": to_id,
                        "to_type": to_type,
                        "relation": relation,
                        "detail": detail,
                        "verified": verified,
                        "verification_evidence": verification_evidence,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                deterministic_edge_id = "csv:" + hashlib.sha256(replay_key.encode("utf-8")).hexdigest()
                if self._topo.get(deterministic_edge_id):
                    replayed += 1
                    continue
                self.add_edge(
                    site_id=site_id,
                    from_id=from_id,
                    from_type=from_type,
                    to_id=to_id,
                    to_type=to_type,
                    relation=relation,
                    detail=detail,
                    verified=verified,
                    verification_evidence=verification_evidence,
                    justification="legacy CSV topology import",
                    edge_id=deterministic_edge_id,
                )
                created += 1
            except Exception as e:
                errors.append(str(e))
        return {"created": created, "replayed": replayed, "errors": errors}

    def graph_for_site(self, site_id: str) -> List[Dict[str, Any]]:
        return [e.to_dict() for e in self._topo.list_for_site(site_id)]

    def path_from_node(
        self,
        site_id: str,
        node_id: str,
        *,
        target_id: Optional[str] = None,
        max_hops: int = 20,
    ) -> List[Dict[str, Any]]:
        """Return a bounded best-effort chain through observed topology edges.

        The graph is evidence-backed rather than a routing oracle: one edge
        per source node is selected using the existing camera-compatible
        ordering, and the result stops at ``target_id`` or the bounded hop
        count.  Callers must surface the result as observed/projected data.
        """
        if not isinstance(node_id, str) or not node_id.strip():
            raise ValueError("path source identifier is required")
        if target_id is not None and (not isinstance(target_id, str) or not target_id.strip()):
            raise ValueError("path target identifier cannot be blank")
        if not isinstance(max_hops, int) or not 1 <= max_hops <= 64:
            raise ValueError("max_hops must be between 1 and 64")
        edges = self._topo.list_for_site(site_id)
        by_from: Dict[str, TopologyEdge] = {}
        for e in edges:
            # Preserve the camera-compatible preference while keeping the
            # query generic for workstations, gateways, interfaces, and other
            # network nodes.
            if e.from_id == node_id or not by_from.get(e.from_id):
                by_from[e.from_id] = e
            if e.from_type == "asset":
                by_from[e.from_id] = e

        path: List[TopologyEdge] = []
        current_id = node_id
        for _ in range(max_hops):
            if target_id is not None and current_id == target_id:
                break
            edge = by_from.get(current_id)
            if not edge or edge in path:
                break
            path.append(edge)
            current_id = edge.to_id
        return [e.to_dict() for e in path]

    def path_to_camera(self, site_id: str, asset_id: str) -> List[Dict[str, Any]]:
        """Compatibility alias for the former camera-specific path query."""
        return self.path_from_node(site_id, asset_id)
