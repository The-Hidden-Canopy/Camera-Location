"""Site profile service: create sites, network profiles, and physical locations.

Keeps Flask routes thin by centralizing validation and defaulting logic here.
"""

from __future__ import annotations

import uuid
from typing import Dict, List, Optional

from ..domain.models import Site, NetworkProfile, PhysicalLocation
from ..persistence.db import Database
from ..persistence.repos import SiteRepo, NetworkProfileRepo, LocationRepo


class SiteService:
    def __init__(self, db: Database):
        self._db = db
        self._sites = SiteRepo(db)
        self._profiles = NetworkProfileRepo(db)
        self._locations = LocationRepo(db)

    def create_site(self, data: Dict[str, str]) -> Site:
        site = Site(
            site_id=str(uuid.uuid4()),
            name=data.get("name", "").strip(),
            customer=data.get("customer", "").strip(),
            address=data.get("address", "").strip(),
            local_coords=data.get("local_coords", "").strip(),
            notes=data.get("notes", "").strip(),
        )
        if not site.name:
            raise ValueError("site name is required")
        self._sites.save(site)
        return site

    def get_site(self, site_id: str, include_children: bool = False) -> Dict:
        site = self._sites.get(site_id)
        if not site:
            raise KeyError("site not found")
        result = site.to_dict()
        if include_children:
            result["network_profiles"] = [p.to_dict() for p in self._profiles.list_for_site(site_id)]
            result["locations"] = [l.to_dict() for l in self._locations.list_for_site(site_id)]
        return result

    def list_sites(self) -> List[Dict]:
        return [s.to_dict() for s in self._sites.list_all()]

    def add_network_profile(self, site_id: str, data: Dict[str, str]) -> NetworkProfile:
        site = self._sites.get(site_id)
        if not site:
            raise KeyError("site not found")
        profile = NetworkProfile(
            profile_id=str(uuid.uuid4()),
            site_id=site_id,
            subnet=data.get("subnet", "").strip(),
            label=data.get("label", "").strip(),
            gateway=data.get("gateway", "").strip(),
            vlan_id=int(data.get("vlan_id", 0) or 0),
            dhcp_mode=data.get("dhcp_mode", "unknown").strip(),
            method=data.get("method", "auto").strip(),
            radio_zone=data.get("radio_zone", "").strip(),
            nvr_segment=int(data.get("nvr_segment", 0) or 0),
            internet_blocked=bool(data.get("internet_blocked", True)),
            notes=data.get("notes", "").strip(),
        )
        if not profile.subnet:
            raise ValueError("subnet is required")
        self._profiles.save(profile)
        return profile

    def add_location(self, site_id: str, data: Dict[str, str]) -> PhysicalLocation:
        site = self._sites.get(site_id)
        if not site:
            raise KeyError("site not found")
        loc = PhysicalLocation(
            location_id=str(uuid.uuid4()),
            site_id=site_id,
            label=data.get("label", "").strip(),
            zone=data.get("zone", "").strip(),
            map_x=float(data["map_x"]) if data.get("map_x") not in (None, "") else None,
            map_y=float(data["map_y"]) if data.get("map_y") not in (None, "") else None,
            map_source=data.get("map_source", "").strip(),
            direction=data.get("direction", "").strip(),
            notes=data.get("notes", "").strip(),
        )
        if not loc.label:
            raise ValueError("location label is required")
        self._locations.save(loc)
        return loc
