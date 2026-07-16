"""Physical location verification service.

Captures the human evidence required to bind a camera asset to a place:
- plain-language location label
- GPS / map / floor-plan coordinates
- direction of view
- installer photos
- QR / asset-tag scan
"""

from __future__ import annotations

import base64
import hashlib
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..domain.models import CameraAsset, Observation, PhysicalLocation
from ..persistence.db import Database, new_uuid
from ..persistence.repos import AssetRepo, LocationRepo, ObservationRepo


class LocationVerificationService:
    def __init__(self, db: Database, photo_dir: Optional[Path] = None):
        self._db = db
        self._assets = AssetRepo(db)
        self._locations = LocationRepo(db)
        self._obs = ObservationRepo(db)
        self._photo_dir = photo_dir

    def _photo_dir_for(self, site_id: str) -> Path:
        base = self._photo_dir or Path.home() / "CameraLocation" / "photos"
        path = base / site_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def store_photo(self, site_id: str, asset_id: str, image_b64: str, ext: str = "jpg") -> str:
        """Persist an installer photo and return a stable reference."""
        data = base64.b64decode(image_b64)
        digest = hashlib.sha256(data).hexdigest()[:16]
        filename = f"{asset_id}_{digest}.{ext}"
        path = self._photo_dir_for(site_id) / filename
        path.write_bytes(data)
        return str(path)

    def verify_asset(
        self,
        site_id: str,
        asset_id: str,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Record operator-verified physical attribution for an asset.

        Accepts:
          location_id   — existing physical_location id
          label         — create a new plain-language location if location_id absent
          zone          — zone hint when creating a new location
          map_x, map_y  — map/floor-plan coordinates
          direction     — direction the camera faces
          qr_code       — scanned QR / asset tag
          photos        — list of base64 encoded images
          detail        — operator note
        """
        asset = self._assets.get(asset_id)
        if not asset or asset.site_id != site_id:
            raise ValueError("asset not found")

        location_id = kwargs.get("location_id")
        if not location_id and kwargs.get("label"):
            loc = PhysicalLocation(
                location_id=new_uuid(),
                site_id=site_id,
                label=kwargs.get("label", "").strip(),
                zone=kwargs.get("zone", "").strip(),
                map_x=float(kwargs["map_x"]) if kwargs.get("map_x") not in (None, "") else None,
                map_y=float(kwargs["map_y"]) if kwargs.get("map_y") not in (None, "") else None,
                direction=kwargs.get("direction", "").strip(),
            )
            self._locations.save(loc)
            location_id = loc.location_id

        if location_id and not kwargs.get("label"):
            loc = self._locations.get(location_id)
            if not loc or loc.site_id != site_id:
                raise ValueError("location not found")

        if location_id:
            asset.expected_location_id = location_id

        qr = kwargs.get("qr_code")
        if qr and not asset.qr_code:
            asset.qr_code = qr.strip()

        asset.human_confirmed = True
        asset.installed_status = "verified"
        self._assets.save(asset)

        photo_refs: List[str] = []
        for photo in kwargs.get("photos") or []:
            ref = self.store_photo(site_id, asset_id, photo)
            photo_refs.append(ref)

        detail = kwargs.get("detail", "Operator verified physical location.")
        if photo_refs:
            detail += f" Photo refs: {', '.join(photo_refs)}."

        self._obs.save(Observation(
            observation_id=new_uuid(),
            site_id=site_id,
            asset_id=asset_id,
            endpoint_id=None,
            kind="physical_verification",
            detail=detail,
            source="operator",
            weight=100,
        ))

        return {
            "asset_id": asset.asset_id,
            "location_id": asset.expected_location_id,
            "qr_code": asset.qr_code,
            "photo_refs": photo_refs,
            "installed_status": asset.installed_status,
        }

    def update_location_photo(self, site_id: str, location_id: str, image_b64: str) -> str:
        data = base64.b64decode(image_b64)
        digest = hashlib.sha256(data).hexdigest()[:16]
        loc = self._locations.get(location_id)
        if not loc or loc.site_id != site_id:
            raise ValueError("location not found")
        filename = f"loc_{location_id}_{digest}.jpg"
        path = self._photo_dir_for(site_id) / filename
        path.write_bytes(data)
        return str(path)
