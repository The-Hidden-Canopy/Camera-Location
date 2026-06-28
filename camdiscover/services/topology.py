"""Topology graph service: NVR, switches, radios, PoE, camera links.

Provides import helpers for CSV / LLDP-like / manual entries and exposes the
graph API the installer uses to understand how a camera is connected.
"""

from __future__ import annotations

import csv
import io
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..domain.models import TopologyEdge, Observation
from ..persistence.db import Database, new_uuid
from ..persistence.repos import TopologyRepo, ObservationRepo


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
    ) -> TopologyEdge:
        edge = TopologyEdge(
            edge_id=new_uuid(),
            site_id=site_id,
            from_id=from_id,
            from_type=from_type,
            to_id=to_id,
            to_type=to_type,
            relation=relation,
            detail=detail,
            verified=verified,
        )
        self._topo.save(edge)
        self._obs.save(Observation(
            observation_id=new_uuid(),
            site_id=site_id,
            kind="topology_edge_added",
            detail=f"{from_type} {from_id} {relation} {to_type} {to_id}",
            source="operator",
            weight=0,
        ))
        return edge

    def import_csv(self, site_id: str, csv_text: str) -> Dict[str, Any]:
        """Import topology from a CSV with columns:
        from_id,from_type,to_id,to_type,relation,detail,verified.
        """
        reader = csv.DictReader(io.StringIO(csv_text.strip()))
        created = 0
        errors: List[str] = []
        for row in reader:
            try:
                self.add_edge(
                    site_id=site_id,
                    from_id=row["from_id"].strip(),
                    from_type=row["from_type"].strip(),
                    to_id=row["to_id"].strip(),
                    to_type=row["to_type"].strip(),
                    relation=row["relation"].strip(),
                    detail=row.get("detail", "").strip(),
                    verified=(row.get("verified", "").strip().lower() in ("1", "true", "yes")),
                )
                created += 1
            except Exception as e:
                errors.append(str(e))
        return {"created": created, "errors": errors}

    def graph_for_site(self, site_id: str) -> List[Dict[str, Any]]:
        return [e.to_dict() for e in self._topo.list_for_site(site_id)]

    def path_to_camera(self, site_id: str, asset_id: str) -> List[Dict[str, Any]]:
        """Return a best-effort chain from the camera to an upstream root."""
        edges = self._topo.list_for_site(site_id)
        by_from: Dict[str, TopologyEdge] = {}
        for e in edges:
            # prefer camera-origin edges
            if e.from_id == asset_id or not by_from.get(e.from_id):
                by_from[e.from_id] = e
            if e.from_type == "asset":
                by_from[e.from_id] = e

        path: List[TopologyEdge] = []
        current_id = asset_id
        for _ in range(20):
            edge = by_from.get(current_id)
            if not edge or edge in path:
                break
            path.append(edge)
            current_id = edge.to_id
        return [e.to_dict() for e in path]
