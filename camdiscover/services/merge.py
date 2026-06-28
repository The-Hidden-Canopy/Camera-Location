"""Manual merge / split API for reconciliation review.

Operators can confirm a likely match, split a merged asset, or merge two assets when
a camera was replaced.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..persistence.db import Database
from ..persistence.repos import AssetRepo, EndpointRepo, ObservationRepo
from ..domain.models import Observation
from ..persistence.db import new_uuid
from ..services.reconciliation import ReconciliationService


class MergeService:
    def __init__(self, db: Database):
        self._db = db
        self._assets = AssetRepo(db)
        self._endpoints = EndpointRepo(db)
        self._obs = ObservationRepo(db)

    def confirm_match(
        self,
        site_id: str,
        asset_id: str,
        endpoint_id: Optional[str] = None,
        discovered_ip: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Operator confirms a reconciliation match.

        If `endpoint_id` is supplied, attach it to the asset and deprecate other
        current endpoints for that asset. Otherwise record a confirmation
        observation for the asset.
        """
        asset = self._assets.get(asset_id)
        if not asset or asset.site_id != site_id:
            raise ValueError("asset not found")

        endpoint = None
        if endpoint_id:
            endpoint = self._endpoints.get(endpoint_id)
            if endpoint:
                endpoint.asset_id = asset_id
                self._endpoints.save(endpoint)
                self._endpoints.deprecate_by_asset(asset_id, keep_endpoint_id=endpoint_id)

        self._obs.save(Observation(
            observation_id=new_uuid(),
            site_id=site_id,
            asset_id=asset_id,
            endpoint_id=endpoint.endpoint_id if endpoint else None,
            kind="operator_match_confirmation",
            detail=f"Operator confirmed asset match with discovered endpoint at {discovered_ip or 'unknown'}.",
            source="operator",
            weight=100,
        ))

        return {"asset_id": asset_id, "endpoint_id": endpoint.endpoint_id if endpoint else None}

    def merge_assets(self, keep_asset_id: str, remove_asset_id: str) -> Dict[str, Any]:
        """Move all endpoints and observations from `remove_asset_id` to
        `keep_asset_id`, then delete the removed asset."""
        keep = self._assets.get(keep_asset_id)
        remove = self._assets.get(remove_asset_id)
        if not keep or not remove:
            raise ValueError("asset not found")

        for endpoint in self._endpoints.list_for_asset(remove_asset_id):
            endpoint.asset_id = keep_asset_id
            self._endpoints.save(endpoint)

        self._obs.save(Observation(
            observation_id=new_uuid(),
            site_id=keep.site_id,
            asset_id=keep_asset_id,
            kind="asset_merge",
            detail=f"Merged asset {remove_asset_id} into {keep_asset_id}.",
            source="operator",
            weight=0,
        ))

        self._assets.delete(remove_asset_id)
        return {"kept_asset_id": keep_asset_id, "removed_asset_id": remove_asset_id}

    def split_endpoint_to_asset(self, endpoint_id: str, new_asset_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detach an endpoint from its current asset and give it a new asset identity."""
        endpoint = self._endpoints.get(endpoint_id)
        if not endpoint:
            raise ValueError("endpoint not found")

        from ..domain.models import CameraAsset
        new_asset = CameraAsset(
            asset_id=new_uuid(),
            site_id=new_asset_data.get("site_id"),
            asset_tag=new_asset_data.get("asset_tag", ""),
            qr_code=new_asset_data.get("qr_code", ""),
            serial=new_asset_data.get("serial", ""),
            manufacturer=new_asset_data.get("manufacturer", ""),
            model=new_asset_data.get("model", ""),
            onvif_uuid=new_asset_data.get("onvif_uuid", ""),
            installed_status="unverified",
            notes="Created by operator split during reconciliation.",
        )
        self._assets.save(new_asset)

        endpoint.asset_id = new_asset.asset_id
        self._endpoints.save(endpoint)

        self._obs.save(Observation(
            observation_id=new_uuid(),
            site_id=new_asset.site_id,
            asset_id=new_asset.asset_id,
            endpoint_id=endpoint_id,
            kind="asset_split",
            detail="Operator split endpoint into a new asset during reconciliation.",
            source="operator",
            weight=0,
        ))

        return {"new_asset_id": new_asset.asset_id, "endpoint_id": endpoint_id}
