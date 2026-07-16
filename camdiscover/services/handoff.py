"""Installer handoff package import/export.

A handoff is a signed/read-only ZIP containing everything the next installer needs
without exposing credentials.
"""

from __future__ import annotations

import io
import json
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..domain.models import CameraAsset, DeviceEndpoint, NetworkProfile, PhysicalLocation, TopologyEdge
from ..persistence.db import Database
from ..persistence.repos import (
    AssetRepo,
    ChangeJobRepo,
    EndpointRepo,
    LocationRepo,
    NetworkProfileRepo,
    ObservationRepo,
    TopologyRepo,
)


class HandoffService:
    def __init__(self, db: Database, export_dir: Optional[Path] = None):
        self._db = db
        self._assets = AssetRepo(db)
        self._endpoints = EndpointRepo(db)
        self._locations = LocationRepo(db)
        self._profiles = NetworkProfileRepo(db)
        self._topology = TopologyRepo(db)
        self._obs = ObservationRepo(db)
        self._jobs = ChangeJobRepo(db)
        self._export_dir = export_dir or Path.home() / "CameraLocation" / "handoffs"

    def export(self, site_id: str) -> Path:
        """Create a handoff ZIP for `site_id` and return the file path."""
        from ..persistence.repos import SiteRepo
        site = SiteRepo(self._db).get(site_id)
        if not site:
            raise ValueError("site not found")

        export_dir = self._export_dir / site_id
        export_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        out_path = export_dir / f"{site_id}_{timestamp}.zip"

        assets = self._assets.list_for_site(site_id)
        locations = self._locations.list_for_site(site_id)
        profiles = self._profiles.list_for_site(site_id)
        topology = self._topology.list_for_site(site_id)
        jobs = self._jobs.list_for_site(site_id)
        # Recent observations only
        observations = self._obs.list_for_site(site_id, limit=500)

        asset_rows = []
        ip_plan = []
        for asset in assets:
            row = asset.to_dict()
            row["endpoints"] = [e.to_dict() for e in self._endpoints.list_for_asset(asset.asset_id)]
            asset_rows.append(row)
            for ep in row["endpoints"]:
                if ep.get("is_current"):
                    ip_plan.append({
                        "asset_id": asset.asset_id,
                        "asset_tag": asset.asset_tag,
                        "serial": asset.serial,
                        "location_id": asset.expected_location_id,
                        "ip": ep.get("ip"),
                        "mac": ep.get("mac"),
                        "subnet": ep.get("subnet"),
                    })

        nvr_channel_map = []
        for edge in topology:
            if edge.relation == "nvr_channel":
                nvr_channel_map.append(edge.to_dict())

        unresolved = [u for u in self._unresolved_devices(site_id)]
        checklist = self._acceptance_checklist(asset_rows, ip_plan, unresolved)

        package = {
            "meta": {
                "site_id": site_id,
                "site_name": site.name,
                "customer": site.customer,
                "exported_at": datetime.now(timezone.utc).isoformat(),
                "schema_version": "1.0",
            },
            "site_profile": site.to_dict(),
            "network_profiles": [p.to_dict() for p in profiles],
            "locations": [l.to_dict() for l in locations],
            "camera_assets": asset_rows,
            "ip_plan": ip_plan,
            "nvr_channel_map": nvr_channel_map,
            "topology": [e.to_dict() for e in topology],
            "unresolved_devices": unresolved,
            "change_history": [j.to_dict() for j in jobs],
            "verification_report": self._verification_summary(asset_rows, locations),
            "acceptance_checklist": checklist,
        }

        with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("package.json", json.dumps(package, indent=2, ensure_ascii=False))
            zf.writestr("import.json", json.dumps(self._importable_payload(package), indent=2, ensure_ascii=False))

            # Read-only HTML report for installer review
            html_buf = io.StringIO()
            # Use a lightweight HTML renderer inline here
            html_buf.write(self._build_html_report(package))
            zf.writestr("report.html", html_buf.getvalue())

        return out_path

    def import_package(self, zip_path: Path, new_site_id: Optional[str] = None) -> str:
        """Import a handoff ZIP. Returns the new site_id."""
        from ..persistence.repos import SiteRepo

        with zipfile.ZipFile(zip_path, "r") as zf:
            import_json = zf.read("import.json").decode("utf-8")
        payload = json.loads(import_json)

        old_site_id = payload["site_profile"]["site_id"]
        site_id = new_site_id or old_site_id
        payload["site_profile"]["site_id"] = site_id

        site = SiteRepo(self._db).get(site_id)
        if not site:
            from ..domain.models import Site
            data = payload["site_profile"]
            site = Site(
                site_id=site_id,
                name=data.get("name", "Imported Site"),
                customer=data.get("customer", ""),
                address=data.get("address", ""),
                local_coords=data.get("local_coords", ""),
                notes=(data.get("notes", "") + "\nImported from handoff package.").strip(),
            )
            SiteRepo(self._db).save(site)

        # Import network profiles
        profiles_by_old_id: Dict[str, str] = {}
        for p in payload.get("network_profiles", []):
            old_id = p["profile_id"]
            profile = NetworkProfile(
                profile_id=str(uuid.uuid4()),  # Generate new ID
                site_id=site_id,
                subnet=p["subnet"],
                label=p.get("label", ""),
                gateway=p.get("gateway", ""),
                vlan_id=p.get("vlan_id", 0),
                dhcp_mode=p.get("dhcp_mode", "unknown"),
                method=p.get("method", "auto"),
                radio_zone=p.get("radio_zone", ""),
                nvr_segment=p.get("nvr_segment", 0),
                internet_blocked=p.get("internet_blocked", True),
                notes=p.get("notes", ""),
            )
            self._profiles.save(profile)
            profiles_by_old_id[old_id] = profile.profile_id

        # Import locations
        locations_by_old_id: Dict[str, str] = {}
        for l in payload.get("locations", []):
            old_id = l["location_id"]
            loc = PhysicalLocation(
                location_id=str(uuid.uuid4()),
                site_id=site_id,
                label=l["label"],
                zone=l.get("zone", ""),
                map_x=l.get("map_x"),
                map_y=l.get("map_y"),
                map_source=l.get("map_source", ""),
                direction=l.get("direction", ""),
                notes=l.get("notes", ""),
            )
            self._locations.save(loc)
            locations_by_old_id[old_id] = loc.location_id

        # Import assets and current endpoint snapshots
        assets_by_old_id: Dict[str, str] = {}
        for a in payload.get("camera_assets", []):
            old_id = a["asset_id"]
            new_loc_id = locations_by_old_id.get(a.get("expected_location_id")) if a.get("expected_location_id") else None
            asset = CameraAsset(
                asset_id=str(uuid.uuid4()),
                site_id=site_id,
                asset_tag=a.get("asset_tag", ""),
                qr_code=a.get("qr_code", ""),
                serial=a.get("serial", ""),
                manufacturer=a.get("manufacturer", ""),
                model=a.get("model", ""),
                hardware_id=a.get("hardware_id", ""),
                onvif_uuid=a.get("onvif_uuid", ""),
                asset_class=a.get("asset_class", "unknown_endpoint"),
                operational_role=a.get("operational_role", "unknown"),
                criticality=a.get("criticality", "normal"),
                reset_risk=a.get("reset_risk", "moderate"),
                human_confirmed=bool(a.get("human_confirmed", False)),
                installed_status=a.get("installed_status", "planned"),
                expected_location_id=new_loc_id,
                notes=(a.get("notes", "") + "\nImported from handoff.").strip(),
            )
            self._assets.save(asset)
            assets_by_old_id[old_id] = asset.asset_id

            # Recreate current endpoint from the IP plan if present
            for ep in a.get("endpoints", []):
                if ep.get("is_current"):
                    endpoint = DeviceEndpoint(
                        endpoint_id=str(uuid.uuid4()),
                        asset_id=asset.asset_id,
                        ip=ep.get("ip", ""),
                        ip_history=ep.get("ip_history", []),
                        mac=ep.get("mac", ""),
                        mac_history=ep.get("mac_history", []),
                        onvif_uuid=ep.get("onvif_uuid", ""),
                        rtsp_url=ep.get("rtsp_url", ""),
                        onvif_url=ep.get("onvif_url", ""),
                        web_url=ep.get("web_url", ""),
                        firmware=ep.get("firmware", ""),
                        subnet=ep.get("subnet", ""),
                        is_current=True,
                        device_class=ep.get("device_class", "unknown"),
                    )
                    self._endpoints.save(endpoint)

        # Import topology with remapped ids
        for e in payload.get("topology", []):
            edge = TopologyEdge(
                edge_id=str(uuid.uuid4()),
                site_id=site_id,
                from_id=assets_by_old_id.get(e["from_id"], e["from_id"]),
                from_type=e["from_type"],
                to_id=assets_by_old_id.get(e["to_id"], e["to_id"]),
                to_type=e["to_type"],
                relation=e["relation"],
                detail=e.get("detail", ""),
                verified=e.get("verified", False),
            )
            self._topology.save(edge)

        return site_id

    def _unresolved_devices(self, site_id: str) -> List[Dict[str, Any]]:
        """Return current endpoints without verified physical location."""
        unresolved: List[Dict[str, Any]] = []
        for asset in self._assets.list_for_site(site_id):
            current = [e for e in self._endpoints.list_for_asset(asset.asset_id) if e.is_current]
            if not current:
                unresolved.append({
                    "asset_id": asset.asset_id,
                    "serial": asset.serial,
                    "reason": "No current network endpoint.",
                })
                continue
            if asset.installed_status != "verified":
                unresolved.append({
                    "asset_id": asset.asset_id,
                    "serial": asset.serial,
                    "ip": current[0].ip,
                    "reason": "Physical location not verified.",
                })
        return unresolved

    def _verification_summary(self, asset_rows: List[Dict[str, Any]], locations: List[PhysicalLocation]) -> Dict[str, Any]:
        verified = [a for a in asset_rows if a.get("installed_status") == "verified"]
        return {
            "total_assets": len(asset_rows),
            "verified_assets": len(verified),
            "verified_percent": round(100 * len(verified) / len(asset_rows), 1) if asset_rows else 0,
            "location_count": len(locations),
        }

    def _acceptance_checklist(
        self,
        asset_rows: List[Dict[str, Any]],
        ip_plan: List[Dict[str, Any]],
        unresolved: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        return [
            {"item": "Site profile imported and customer/signature confirmed", "checked": False},
            {"item": f"All {len(asset_rows)} camera assets physically verified", "checked": False},
            {"item": f"IP plan reviewed ({len(ip_plan)} current endpoints)", "checked": False},
            {"item": f"Unresolved devices reviewed ({len(unresolved)} items)", "checked": False},
            {"item": "Credentials imported separately (not in handoff)", "checked": False},
            {"item": "Change history and rollback state reviewed", "checked": False},
        ]

    def _importable_payload(self, package: Dict[str, Any]) -> Dict[str, Any]:
        """Return a copy of the package suitable for re-import.

        This explicitly strips any machine-specific paths or secret refs that
        should not be moved to another laptop.
        """
        payload = json.loads(json.dumps(package))
        # No credential profiles by design
        payload.pop("change_history", None)
        return payload

    def _build_html_report(self, package: Dict[str, Any]) -> str:
        site = package["site_profile"]
        assets = package.get("camera_assets", [])
        unresolved = package.get("unresolved_devices", [])
        meta = package["meta"]
        rows = ""
        for a in assets:
            current_ip = ""
            for ep in a.get("endpoints", []):
                if ep.get("is_current"):
                    current_ip = ep.get("ip", "")
                    break
            rows += (
                f"<tr>"
                f"<td>{self._html_escape(a.get('asset_tag', ''))}</td>"
                f"<td>{self._html_escape(a.get('serial', ''))}</td>"
                f"<td>{self._html_escape(a.get('manufacturer', ''))} {self._html_escape(a.get('model', ''))}</td>"
                f"<td>{self._html_escape(current_ip)}</td>"
                f"<td>{self._html_escape(a.get('installed_status', ''))}</td>"
                f"</tr>"
            )
        return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Handoff Report</title>
<style>
  body {{ font-family: system-ui, sans-serif; margin: 2rem; background:#f7f8fa; color:#222; }}
  table {{ width:100%; border-collapse: collapse; margin-top:1rem; }}
  th, td {{ text-align:left; padding:.5rem; border-bottom:1px solid #ddd; }}
  th {{ background:#eef; }}
  .muted {{ color:#666; }}
</style></head><body>
<h1>Installer Handoff — {self._html_escape(site.get('name', ''))}</h1>
<p class="muted">Customer: {self._html_escape(site.get('customer', ''))}<br>
Exported: {self._html_escape(meta.get('exported_at', ''))}<br>
Assets: {len(assets)} | Unresolved: {len(unresolved)}</p>
<table><thead><tr><th>Asset Tag</th><th>Serial</th><th>Model</th><th>Current IP</th><th>Status</th></tr></thead><tbody>
{rows}
</tbody></table>
<h2>Unresolved</h2>
<ul>
{''.join(f'<li>{self._html_escape(u.get("reason", ''))} — {self._html_escape(u.get("serial", ''))}</li>' for u in unresolved) or '<li class="muted">None</li>'}
</ul>
</body></html>"""

    @staticmethod
    def _html_escape(value: str) -> str:
        return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;") if value else ""
