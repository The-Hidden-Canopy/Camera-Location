"""Adapter that mirrors discovery events into durable SQLite records.

This is deliberately non-blocking: the in-memory orchestrator remains the source
of truth for live UI updates; this service writes to the database in the same
thread as the discovery callback.  SQLite is fast enough that this does not
impact scan timing, but if it becomes a concern we can move writes to a queue.
"""

from __future__ import annotations

from typing import Any, Callable, List, Optional

from ..models import DiscoveredDevice
from ..orchestrator import DiscoveryOrchestrator
from ..persistence.db import Database, default_db_path, get_database
from ..persistence.repos import AssetRepo, EndpointRepo, ObservationRepo, SiteRepo
from ..services.reconciliation import ReconciliationService


class DiscoveryService:
    """Wires DiscoveryOrchestrator callbacks into durable asset records."""

    def __init__(
        self,
        orchestrator: DiscoveryOrchestrator,
        db: Optional[Database] = None,
        site_id: Optional[str] = None,
    ):
        self._orchestrator = orchestrator
        self._db = db or get_database()
        self._site_id = None
        self._reconciler = ReconciliationService(self._db)
        self._assets = AssetRepo(self._db)
        self._endpoints = EndpointRepo(self._db)
        self._observations = ObservationRepo(self._db)
        self._sites = SiteRepo(self._db)

        # Wrap existing callbacks so upstream still works.
        self._wrap_callbacks()
        if site_id:
            self.set_site(site_id)

    def _wrap_callbacks(self) -> None:
        original_found = self._orchestrator.on_device_found
        original_updated = self._orchestrator.on_device_updated

        def on_found(device: DiscoveredDevice):
            self._persist(device)
            if original_found:
                try:
                    original_found(device)
                except Exception:
                    pass

        def on_updated(device: DiscoveredDevice):
            self._persist(device)
            if original_updated:
                try:
                    original_updated(device)
                except Exception:
                    pass

        self._orchestrator.on_device_found = on_found
        self._orchestrator.on_device_updated = on_updated

    def _persist(self, device: DiscoveredDevice) -> None:
        try:
            endpoint, asset, _ = self._reconciler.reconcile_device(device, site_id=self._site_id)
            device.endpoint_id = endpoint.endpoint_id or ""
            device.asset_id = asset.asset_id if asset else ""
        except Exception:
            # A database write must NEVER abort discovery.
            pass

    @property
    def reconciler(self) -> ReconciliationService:
        return self._reconciler

    def set_site(self, site_id: Optional[str]) -> None:
        if site_id and not self._sites.get(site_id):
            raise ValueError(f"site not found: {site_id}")
        self._site_id = site_id
        if site_id and self._reconciler.session_id:
            # Starting work against a new site increments the observation session.
            self._reconciler.new_session()

    def current_inventory(self, site_id: Optional[str] = None) -> List[dict[str, Any]]:
        """Return persisted current endpoints with attached asset/evidence metadata."""
        resolved_site = site_id or self._site_id
        rows: List[dict[str, Any]] = []
        for endpoint in self._endpoints.list_current(resolved_site):
            asset = self._assets.get(endpoint.asset_id) if endpoint.asset_id else None
            observations = self._observations.list_for_endpoint(endpoint.endpoint_id, limit=25)
            rows.append({
                "endpoint": endpoint.to_dict(),
                "asset": asset.to_dict() if asset else None,
                "observations": [obs.to_dict() for obs in observations],
            })
        return rows


def attach_persistence(
    orchestrator: DiscoveryOrchestrator,
    db_path: Optional[str] = None,
    site_id: Optional[str] = None,
) -> DiscoveryService:
    """Convenience factory that creates or uses the default database."""
    db = get_database(db_path) if db_path else get_database()
    return DiscoveryService(orchestrator, db=db, site_id=site_id)
