"""Repository classes for camera-location persistence.

Each repository mirrors one logical aggregate and uses the shared Database handle.
Date/time serialization uses ISO-8601 strings in SQLite so upstream domain models
can work with datetime objects directly.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, List, Optional

from .db import Database, new_uuid
from ..domain.models import (
    Site,
    NetworkProfile,
    PhysicalLocation,
    CameraAsset,
    DeviceEndpoint,
    Observation,
    TopologyEdge,
    ChangeJob,
    CredentialProfile,
)


_DATE_FMT = "%Y-%m-%dT%H:%M:%S.%f"


def _parse_dt(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        try:
            return datetime.strptime(str(value).split("+")[0].split("Z")[0], _DATE_FMT)
        except Exception:
            return None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _json(value: Any) -> str:
    return json.dumps(value or [])


def _load_json(value: Any) -> Any:
    if not value:
        return []
    try:
        return json.loads(value)
    except Exception:
        return []


def _coalesce_dt(value: Optional[datetime], default: str) -> str:
    return value.isoformat() if value else default


class SiteRepo:
    def __init__(self, db: Database):
        self._db = db

    def save(self, site: Site) -> Site:
        now = _now()
        created = _coalesce_dt(site.created_at, now)
        updated = _now()
        with self._db.conn:
            self._db.conn.execute(
                """INSERT INTO sites(site_id, name, customer, address, local_coords, notes,
                                    created_at, updated_at)
                   VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(site_id) DO UPDATE SET
                      name=excluded.name,
                      customer=excluded.customer,
                      address=excluded.address,
                      local_coords=excluded.local_coords,
                      notes=excluded.notes,
                      updated_at=excluded.updated_at""",
                (site.site_id, site.name, site.customer, site.address,
                 site.local_coords, site.notes, created, updated)
            )
        return site

    def get(self, site_id: str) -> Optional[Site]:
        row = self._db.conn.execute(
            "SELECT * FROM sites WHERE site_id=?", (site_id,)
        ).fetchone()
        if not row:
            return None
        return Site(
            site_id=row["site_id"],
            name=row["name"],
            customer=row["customer"] or "",
            address=row["address"] or "",
            local_coords=row["local_coords"] or "",
            notes=row["notes"] or "",
            created_at=_parse_dt(row["created_at"]),
            updated_at=_parse_dt(row["updated_at"]),
        )

    def list_all(self) -> List[Site]:
        rows = self._db.conn.execute(
            "SELECT * FROM sites ORDER BY name"
        ).fetchall()
        return [
            Site(
                site_id=r["site_id"], name=r["name"], customer=r["customer"] or "",
                address=r["address"] or "", local_coords=r["local_coords"] or "",
                notes=r["notes"] or "",
                created_at=_parse_dt(r["created_at"]),
                updated_at=_parse_dt(r["updated_at"]),
            )
            for r in rows
        ]

    def delete(self, site_id: str) -> None:
        with self._db.conn:
            self._db.conn.execute("DELETE FROM sites WHERE site_id=?", (site_id,))


class NetworkProfileRepo:
    def __init__(self, db: Database):
        self._db = db

    def save(self, profile: NetworkProfile) -> NetworkProfile:
        now = _now()
        created = _coalesce_dt(profile.created_at, now)
        updated = _now()
        with self._db.conn:
            self._db.conn.execute(
                """INSERT INTO network_profiles(profile_id, site_id, subnet, label,
                                                  gateway, vlan_id, dhcp_mode, method,
                                                  radio_zone, nvr_segment, internet_blocked,
                                                  notes, created_at, updated_at)
                   VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(profile_id) DO UPDATE SET
                      subnet=excluded.subnet, label=excluded.label,
                      gateway=excluded.gateway, vlan_id=excluded.vlan_id,
                      dhcp_mode=excluded.dhcp_mode, method=excluded.method,
                      radio_zone=excluded.radio_zone, nvr_segment=excluded.nvr_segment,
                      internet_blocked=excluded.internet_blocked,
                      notes=excluded.notes, updated_at=excluded.updated_at""",
                (profile.profile_id, profile.site_id, profile.subnet, profile.label,
                 profile.gateway, profile.vlan_id, profile.dhcp_mode, profile.method,
                 profile.radio_zone, int(profile.nvr_segment), int(profile.internet_blocked),
                 profile.notes, created, updated)
            )
        return profile

    def get(self, profile_id: str) -> Optional[NetworkProfile]:
        row = self._db.conn.execute(
            "SELECT * FROM network_profiles WHERE profile_id=?", (profile_id,)
        ).fetchone()
        return self._from_row(row) if row else None

    def list_for_site(self, site_id: str) -> List[NetworkProfile]:
        rows = self._db.conn.execute(
            "SELECT * FROM network_profiles WHERE site_id=? ORDER BY subnet",
            (site_id,)
        ).fetchall()
        return [self._from_row(r) for r in rows]

    def find_by_subnet(self, site_id: str, subnet: str) -> Optional[NetworkProfile]:
        row = self._db.conn.execute(
            "SELECT * FROM network_profiles WHERE site_id=? AND subnet=?",
            (site_id, subnet)
        ).fetchone()
        return self._from_row(row) if row else None

    def _from_row(self, row: sqlite3.Row) -> NetworkProfile:
        return NetworkProfile(
            profile_id=row["profile_id"],
            site_id=row["site_id"],
            subnet=row["subnet"],
            label=row["label"] or "",
            gateway=row["gateway"] or "",
            vlan_id=row["vlan_id"] or 0,
            dhcp_mode=row["dhcp_mode"] or "unknown",
            method=row["method"] or "auto",
            radio_zone=row["radio_zone"] or "",
            nvr_segment=row["nvr_segment"] or 0,
            internet_blocked=bool(row["internet_blocked"]),
            notes=row["notes"] or "",
            created_at=_parse_dt(row["created_at"]),
            updated_at=_parse_dt(row["updated_at"]),
        )

    def delete(self, profile_id: str) -> None:
        with self._db.conn:
            self._db.conn.execute(
                "DELETE FROM network_profiles WHERE profile_id=?", (profile_id,)
            )


class LocationRepo:
    def __init__(self, db: Database):
        self._db = db

    def save(self, location: PhysicalLocation) -> PhysicalLocation:
        now = _now()
        created = _coalesce_dt(location.created_at, now)
        updated = _now()
        with self._db.conn:
            self._db.conn.execute(
                """INSERT INTO physical_locations(location_id, site_id, label, zone,
                                                   map_x, map_y, map_source, direction,
                                                   notes, created_at, updated_at)
                   VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(location_id) DO UPDATE SET
                      label=excluded.label, zone=excluded.zone,
                      map_x=excluded.map_x, map_y=excluded.map_y,
                      map_source=excluded.map_source, direction=excluded.direction,
                      notes=excluded.notes, updated_at=excluded.updated_at""",
                (location.location_id, location.site_id, location.label, location.zone,
                 location.map_x, location.map_y, location.map_source, location.direction,
                 location.notes, created, updated)
            )
        return location

    def get(self, location_id: str) -> Optional[PhysicalLocation]:
        row = self._db.conn.execute(
            "SELECT * FROM physical_locations WHERE location_id=?", (location_id,)
        ).fetchone()
        return self._from_row(row) if row else None

    def list_for_site(self, site_id: str) -> List[PhysicalLocation]:
        rows = self._db.conn.execute(
            "SELECT * FROM physical_locations WHERE site_id=? ORDER BY zone, label",
            (site_id,)
        ).fetchall()
        return [self._from_row(r) for r in rows]

    def _from_row(self, row: sqlite3.Row) -> PhysicalLocation:
        return PhysicalLocation(
            location_id=row["location_id"],
            site_id=row["site_id"],
            label=row["label"],
            zone=row["zone"] or "",
            map_x=row["map_x"],
            map_y=row["map_y"],
            map_source=row["map_source"] or "",
            direction=row["direction"] or "",
            notes=row["notes"] or "",
            created_at=_parse_dt(row["created_at"]),
            updated_at=_parse_dt(row["updated_at"]),
        )


class AssetRepo:
    def __init__(self, db: Database):
        self._db = db

    def save(self, asset: CameraAsset) -> CameraAsset:
        now = _now()
        created = _coalesce_dt(asset.created_at, now)
        updated = _now()
        with self._db.conn:
            self._db.conn.execute(
                """INSERT INTO camera_assets(asset_id, site_id, asset_tag, qr_code,
                                                serial, manufacturer, model, hardware_id,
                                                onvif_uuid, installed_status, expected_location_id,
                                                notes, created_at, updated_at)
                   VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(asset_id) DO UPDATE SET
                      site_id=excluded.site_id,
                      asset_tag=excluded.asset_tag, qr_code=excluded.qr_code,
                      serial=excluded.serial, manufacturer=excluded.manufacturer,
                      model=excluded.model, hardware_id=excluded.hardware_id,
                      onvif_uuid=excluded.onvif_uuid,
                      installed_status=excluded.installed_status,
                      expected_location_id=excluded.expected_location_id,
                      notes=excluded.notes, updated_at=excluded.updated_at""",
                (asset.asset_id, asset.site_id, asset.asset_tag, asset.qr_code,
                 asset.serial, asset.manufacturer, asset.model, asset.hardware_id,
                 asset.onvif_uuid, asset.installed_status, asset.expected_location_id,
                 asset.notes, created, updated)
            )
        return asset

    def get(self, asset_id: str) -> Optional[CameraAsset]:
        row = self._db.conn.execute(
            "SELECT * FROM camera_assets WHERE asset_id=?", (asset_id,)
        ).fetchone()
        return self._from_row(row) if row else None

    def list_for_site(self, site_id: str) -> List[CameraAsset]:
        rows = self._db.conn.execute(
            "SELECT * FROM camera_assets WHERE site_id=? ORDER BY asset_tag, serial",
            (site_id,)
        ).fetchall()
        return [self._from_row(r) for r in rows]

    def find_by_serial(self, site_id: Optional[str], serial: str) -> Optional[CameraAsset]:
        if site_id:
            row = self._db.conn.execute(
                "SELECT * FROM camera_assets WHERE site_id=? AND serial=?",
                (site_id, serial)
            ).fetchone()
        else:
            row = self._db.conn.execute(
                "SELECT * FROM camera_assets WHERE serial=?", (serial,)
            ).fetchone()
        return self._from_row(row) if row else None

    def find_by_onvif_uuid(self, site_id: Optional[str], onvif_uuid: str) -> Optional[CameraAsset]:
        if site_id:
            row = self._db.conn.execute(
                "SELECT * FROM camera_assets WHERE site_id=? AND onvif_uuid=?",
                (site_id, onvif_uuid)
            ).fetchone()
        else:
            row = self._db.conn.execute(
                "SELECT * FROM camera_assets WHERE onvif_uuid=?", (onvif_uuid,)
            ).fetchone()
        return self._from_row(row) if row else None

    def find_by_qr(self, qr: str) -> Optional[CameraAsset]:
        row = self._db.conn.execute(
            "SELECT * FROM camera_assets WHERE qr_code=?", (qr,)
        ).fetchone()
        return self._from_row(row) if row else None

    def find_by_hardware_id(self, hardware_id: str) -> Optional[CameraAsset]:
        row = self._db.conn.execute(
            "SELECT * FROM camera_assets WHERE hardware_id=?", (hardware_id,)
        ).fetchone()
        return self._from_row(row) if row else None

    def _from_row(self, row: sqlite3.Row) -> CameraAsset:
        return CameraAsset(
            asset_id=row["asset_id"],
            site_id=row["site_id"],
            asset_tag=row["asset_tag"] or "",
            qr_code=row["qr_code"] or "",
            serial=row["serial"] or "",
            manufacturer=row["manufacturer"] or "",
            model=row["model"] or "",
            hardware_id=row["hardware_id"] or "",
            onvif_uuid=row["onvif_uuid"] or "",
            installed_status=row["installed_status"] or "planned",
            expected_location_id=row["expected_location_id"],
            notes=row["notes"] or "",
            created_at=_parse_dt(row["created_at"]),
            updated_at=_parse_dt(row["updated_at"]),
        )

    def delete(self, asset_id: str) -> None:
        with self._db.conn:
            self._db.conn.execute("DELETE FROM camera_assets WHERE asset_id=?", (asset_id,))


class EndpointRepo:
    def __init__(self, db: Database):
        self._db = db

    def save(self, endpoint: DeviceEndpoint) -> DeviceEndpoint:
        now = _now()
        first = _coalesce_dt(endpoint.first_seen, now)
        last = _coalesce_dt(endpoint.last_seen, now)
        with self._db.conn:
            self._db.conn.execute(
                """INSERT INTO device_endpoints(endpoint_id, asset_id, ip, ip_history,
                                                   mac, mac_history, onvif_uuid, rtsp_url,
                                                   onvif_url, web_url, firmware,
                                                   network_profile_id, subnet,
                                                   first_seen, last_seen, is_current,
                                                   device_class)
                   VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(endpoint_id) DO UPDATE SET
                      asset_id=excluded.asset_id, ip=excluded.ip,
                      ip_history=excluded.ip_history, mac=excluded.mac,
                      mac_history=excluded.mac_history, onvif_uuid=excluded.onvif_uuid,
                      rtsp_url=excluded.rtsp_url, onvif_url=excluded.onvif_url,
                      web_url=excluded.web_url, firmware=excluded.firmware,
                      network_profile_id=excluded.network_profile_id,
                      subnet=excluded.subnet,
                      last_seen=excluded.last_seen, is_current=excluded.is_current,
                      device_class=excluded.device_class""",
                (endpoint.endpoint_id, endpoint.asset_id, endpoint.ip,
                 _json(endpoint.ip_history), _normalise_mac(endpoint.mac), _json(endpoint.mac_history),
                 endpoint.onvif_uuid, endpoint.rtsp_url, endpoint.onvif_url,
                 endpoint.web_url, endpoint.firmware, endpoint.network_profile_id,
                 endpoint.subnet, first, last,
                 int(endpoint.is_current), endpoint.device_class)
            )
        return endpoint

    def get(self, endpoint_id: str) -> Optional[DeviceEndpoint]:
        row = self._db.conn.execute(
            "SELECT * FROM device_endpoints WHERE endpoint_id=?", (endpoint_id,)
        ).fetchone()
        return self._from_row(row) if row else None

    def list_for_asset(self, asset_id: str) -> List[DeviceEndpoint]:
        rows = self._db.conn.execute(
            """SELECT * FROM device_endpoints
               WHERE asset_id=? ORDER BY is_current DESC, last_seen DESC""",
            (asset_id,)
        ).fetchall()
        return [self._from_row(r) for r in rows]

    def list_current(self, site_id: Optional[str] = None) -> List[DeviceEndpoint]:
        if site_id:
            rows = self._db.conn.execute(
                """SELECT e.* FROM device_endpoints e
                   JOIN camera_assets a ON e.asset_id = a.asset_id
                   WHERE e.is_current=1 AND a.site_id=? ORDER BY e.last_seen DESC""",
                (site_id,)
            ).fetchall()
        else:
            rows = self._db.conn.execute(
                "SELECT * FROM device_endpoints WHERE is_current=1 ORDER BY last_seen DESC"
            ).fetchall()
        return [self._from_row(r) for r in rows]

    def find_by_ip(self, ip: str) -> Optional[DeviceEndpoint]:
        row = self._db.conn.execute(
            """SELECT * FROM device_endpoints
               WHERE ip=? ORDER BY is_current DESC, last_seen DESC LIMIT 1""",
            (ip,)
        ).fetchone()
        return self._from_row(row) if row else None

    def find_by_mac(self, mac: str) -> Optional[DeviceEndpoint]:
        norm = _normalise_mac(mac)
        row = self._db.conn.execute(
            """SELECT * FROM device_endpoints
               WHERE mac=? ORDER BY is_current DESC, last_seen DESC LIMIT 1""",
            (norm,)
        ).fetchone()
        return self._from_row(row) if row else None

    def find_current_by_asset_or_mac(
        self,
        asset_id: Optional[str] = None,
        onvif_uuid: Optional[str] = None,
        serial: Optional[str] = None,
        mac: Optional[str] = None,
        ip: Optional[str] = None,
    ) -> List[DeviceEndpoint]:
        """Find candidate current endpoints matching supplied durable identity hints.

        Returns all matches so the caller can reconcile ties, never silently merge.
        """
        conditions = ["is_current=1"]
        params: List[Any] = []
        if asset_id:
            conditions.append("asset_id=?")
            params.append(asset_id)
        if onvif_uuid:
            conditions.append("onvif_uuid=?")
            params.append(onvif_uuid)
        if mac:
            conditions.append("mac=?")
            params.append(_normalise_mac(mac))
        if ip:
            conditions.append("ip=?")
            params.append(ip)

        sql = "SELECT * FROM device_endpoints WHERE " + " AND ".join(conditions)
        rows = self._db.conn.execute(sql, params).fetchall()
        return [self._from_row(r) for r in rows]

    def mark_not_current(self, endpoint_id: str) -> None:
        now = _now()
        with self._db.conn:
            self._db.conn.execute(
                "UPDATE device_endpoints SET is_current=0, last_seen=? WHERE endpoint_id=?",
                (now, endpoint_id)
            )

    def deprecate_by_asset(self, asset_id: str, keep_endpoint_id: Optional[str] = None) -> None:
        with self._db.conn:
            if keep_endpoint_id:
                self._db.conn.execute(
                    "UPDATE device_endpoints SET is_current=0 WHERE asset_id=? AND endpoint_id!=?",
                    (asset_id, keep_endpoint_id)
                )
            else:
                self._db.conn.execute(
                    "UPDATE device_endpoints SET is_current=0 WHERE asset_id=?",
                    (asset_id,)
                )

    def _from_row(self, row: sqlite3.Row) -> DeviceEndpoint:
        return DeviceEndpoint(
            endpoint_id=row["endpoint_id"],
            asset_id=row["asset_id"],
            ip=row["ip"] or "",
            ip_history=_load_json(row["ip_history"]),
            mac=row["mac"] or "",
            mac_history=_load_json(row["mac_history"]),
            onvif_uuid=row["onvif_uuid"] or "",
            rtsp_url=row["rtsp_url"] or "",
            onvif_url=row["onvif_url"] or "",
            web_url=row["web_url"] or "",
            firmware=row["firmware"] or "",
            network_profile_id=row["network_profile_id"],
            subnet=row["subnet"] or "",
            first_seen=_parse_dt(row["first_seen"]),
            last_seen=_parse_dt(row["last_seen"]),
            is_current=bool(row["is_current"]),
            device_class=row["device_class"] or "unknown",
        )

    def delete(self, endpoint_id: str) -> None:
        with self._db.conn:
            self._db.conn.execute(
                "DELETE FROM device_endpoints WHERE endpoint_id=?", (endpoint_id,)
            )


class ObservationRepo:
    def __init__(self, db: Database):
        self._db = db

    def save(self, observation: Observation) -> Observation:
        now = _now()
        observed = _coalesce_dt(observation.observed_at, now)
        with self._db.conn:
            self._db.conn.execute(
                """INSERT INTO observations(observation_id, site_id, endpoint_id, asset_id,
                                             kind, detail, source, sensor_id, interface,
                                             capture_position, visibility_limit, weight,
                                             raw, observed_at, session_id)
                   VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (observation.observation_id, observation.site_id,
                 observation.endpoint_id, observation.asset_id, observation.kind,
                 observation.detail, observation.source, observation.sensor_id,
                 observation.interface, observation.capture_position,
                 observation.visibility_limit, observation.weight, observation.raw,
                 observed, observation.session_id)
            )
        return observation

    def list_for_endpoint(self, endpoint_id: str, limit: int = 500) -> List[Observation]:
        rows = self._db.conn.execute(
            """SELECT * FROM observations WHERE endpoint_id=?
               ORDER BY observed_at DESC LIMIT ?""",
            (endpoint_id, limit)
        ).fetchall()
        return [self._from_row(r) for r in rows]

    def list_for_asset(self, asset_id: str, limit: int = 500) -> List[Observation]:
        rows = self._db.conn.execute(
            """SELECT * FROM observations WHERE asset_id=?
               ORDER BY observed_at DESC LIMIT ?""",
            (asset_id, limit)
        ).fetchall()
        return [self._from_row(r) for r in rows]

    def list_for_site(self, site_id: str, limit: int = 1000) -> List[Observation]:
        rows = self._db.conn.execute(
            """SELECT * FROM observations WHERE site_id=?
               ORDER BY observed_at DESC LIMIT ?""",
            (site_id, limit)
        ).fetchall()
        return [self._from_row(r) for r in rows]

    def latest_by_kind(self, endpoint_id: str, kind: str) -> Optional[Observation]:
        row = self._db.conn.execute(
            """SELECT * FROM observations
               WHERE endpoint_id=? AND kind=? ORDER BY observed_at DESC LIMIT 1""",
            (endpoint_id, kind)
        ).fetchone()
        return self._from_row(row) if row else None

    def _from_row(self, row: sqlite3.Row) -> Observation:
        return Observation(
            observation_id=row["observation_id"],
            kind=row["kind"],
            observed_at=_parse_dt(row["observed_at"]),
            site_id=row["site_id"],
            endpoint_id=row["endpoint_id"],
            asset_id=row["asset_id"],
            detail=row["detail"] or "",
            source=row["source"] or "",
            sensor_id=row["sensor_id"] or "",
            interface=row["interface"] or "",
            capture_position=row["capture_position"] or "",
            visibility_limit=row["visibility_limit"] or "",
            weight=row["weight"] or 0,
            raw=row["raw"] or "",
            session_id=row["session_id"] or "",
        )


class TopologyRepo:
    def __init__(self, db: Database):
        self._db = db

    def save(self, edge: TopologyEdge) -> TopologyEdge:
        now = _now()
        since = _coalesce_dt(edge.since, now)
        until = edge.until.isoformat() if edge.until else None
        with self._db.conn:
            self._db.conn.execute(
                """INSERT INTO topology_edges(edge_id, site_id, from_id, from_type,
                                                to_id, to_type, relation, detail,
                                                since, until, verified)
                   VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(edge_id) DO UPDATE SET
                      relation=excluded.relation, detail=excluded.detail,
                      since=excluded.since, until=excluded.until,
                      verified=excluded.verified""",
                (edge.edge_id, edge.site_id, edge.from_id, edge.from_type,
                 edge.to_id, edge.to_type, edge.relation, edge.detail,
                 since, until, int(edge.verified))
            )
        return edge

    def list_for_site(self, site_id: str) -> List[TopologyEdge]:
        rows = self._db.conn.execute(
            "SELECT * FROM topology_edges WHERE site_id=? ORDER BY since DESC",
            (site_id,)
        ).fetchall()
        return [self._from_row(r) for r in rows]

    def list_for_node(self, node_id: str) -> List[TopologyEdge]:
        rows = self._db.conn.execute(
            "SELECT * FROM topology_edges WHERE from_id=? OR to_id=? ORDER BY since DESC",
            (node_id, node_id)
        ).fetchall()
        return [self._from_row(r) for r in rows]

    def _from_row(self, row: sqlite3.Row) -> TopologyEdge:
        return TopologyEdge(
            edge_id=row["edge_id"],
            site_id=row["site_id"],
            from_id=row["from_id"],
            from_type=row["from_type"],
            to_id=row["to_id"],
            to_type=row["to_type"],
            relation=row["relation"],
            detail=row["detail"] or "",
            since=_parse_dt(row["since"]),
            until=_parse_dt(row["until"]),
            verified=bool(row["verified"]),
        )

    def delete(self, edge_id: str) -> None:
        with self._db.conn:
            self._db.conn.execute("DELETE FROM topology_edges WHERE edge_id=?", (edge_id,))


class ChangeJobRepo:
    def __init__(self, db: Database):
        self._db = db

    def save(self, job: ChangeJob) -> ChangeJob:
        now = _now()
        created = _coalesce_dt(job.created_at, now)
        approved = job.approved_at.isoformat() if job.approved_at else None
        executed = job.executed_at.isoformat() if job.executed_at else None
        verified = job.verified_at.isoformat() if job.verified_at else None
        with self._db.conn:
            self._db.conn.execute(
                """INSERT INTO change_jobs(job_id, site_id, endpoint_id, asset_id, kind,
                                            proposed, prior, status, approval_phrase,
                                            created_at, approved_at, executed_at,
                                            verified_at, result, rollback_state)
                   VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(job_id) DO UPDATE SET
                      proposed=excluded.proposed, prior=excluded.prior,
                      status=excluded.status, approval_phrase=excluded.approval_phrase,
                      approved_at=excluded.approved_at, executed_at=excluded.executed_at,
                      verified_at=excluded.verified_at, result=excluded.result,
                      rollback_state=excluded.rollback_state""",
                (job.job_id, job.site_id, job.endpoint_id, job.asset_id, job.kind,
                 json.dumps(job.proposed), json.dumps(job.prior), job.status,
                 job.approval_phrase, created, approved, executed, verified,
                 job.result, json.dumps(job.rollback_state))
            )
        return job

    def get(self, job_id: str) -> Optional[ChangeJob]:
        row = self._db.conn.execute(
            "SELECT * FROM change_jobs WHERE job_id=?", (job_id,)
        ).fetchone()
        return self._from_row(row) if row else None

    def list_for_site(self, site_id: str) -> List[ChangeJob]:
        rows = self._db.conn.execute(
            "SELECT * FROM change_jobs WHERE site_id=? ORDER BY created_at DESC",
            (site_id,)
        ).fetchall()
        return [self._from_row(r) for r in rows]

    def _from_row(self, row: sqlite3.Row) -> ChangeJob:
        return ChangeJob(
            job_id=row["job_id"],
            site_id=row["site_id"],
            endpoint_id=row["endpoint_id"],
            asset_id=row["asset_id"],
            kind=row["kind"],
            proposed=_load_json(row["proposed"]),
            prior=_load_json(row["prior"]),
            status=row["status"] or "draft",
            approval_phrase=row["approval_phrase"] or "",
            created_at=_parse_dt(row["created_at"]),
            approved_at=_parse_dt(row["approved_at"]),
            executed_at=_parse_dt(row["executed_at"]),
            verified_at=_parse_dt(row["verified_at"]),
            result=row["result"] or "",
            rollback_state=_load_json(row["rollback_state"]),
        )


class CredentialProfileRepo:
    def __init__(self, db: Database):
        self._db = db

    def save(self, profile: CredentialProfile) -> CredentialProfile:
        now = _now()
        created = _coalesce_dt(profile.created_at, now)
        updated = _now()
        with self._db.conn:
            self._db.conn.execute(
                """INSERT INTO credential_profiles(profile_id, site_id, label, username,
                                                     secret_ref, scope, vendor_hint,
                                                     created_at, updated_at)
                   VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(profile_id) DO UPDATE SET
                      label=excluded.label, username=excluded.username,
                      secret_ref=excluded.secret_ref, scope=excluded.scope,
                      vendor_hint=excluded.vendor_hint, updated_at=excluded.updated_at""",
                (profile.profile_id, profile.site_id, profile.label, profile.username,
                 profile.secret_ref, _json(profile.scope), profile.vendor_hint,
                 created, updated)
            )
        return profile

    def get(self, profile_id: str) -> Optional[CredentialProfile]:
        row = self._db.conn.execute(
            "SELECT * FROM credential_profiles WHERE profile_id=?", (profile_id,)
        ).fetchone()
        return self._from_row(row) if row else None

    def list_for_site(self, site_id: str) -> List[CredentialProfile]:
        rows = self._db.conn.execute(
            "SELECT * FROM credential_profiles WHERE site_id=? ORDER BY label",
            (site_id,)
        ).fetchall()
        return [self._from_row(r) for r in rows]

    def _from_row(self, row: sqlite3.Row) -> CredentialProfile:
        return CredentialProfile(
            profile_id=row["profile_id"],
            site_id=row["site_id"],
            label=row["label"] or "",
            username=row["username"] or "",
            secret_ref=row["secret_ref"] or "",
            scope=_load_json(row["scope"]),
            vendor_hint=row["vendor_hint"] or "",
            created_at=_parse_dt(row["created_at"]),
            updated_at=_parse_dt(row["updated_at"]),
        )


class NetworkChangeJournalRepo:
    def __init__(self, db: Database):
        self._db = db

    def add(self, **fields) -> str:
        journal_id = new_uuid()
        now = _now()
        with self._db.conn:
            self._db.conn.execute(
                """INSERT INTO network_change_journal(
                       journal_id, operation_id, session_id, interface_name,
                       ip, prefix_len, action, completed, user_id,
                       created_at, completed_at)
                   VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (journal_id, fields.get("operation_id"), fields.get("session_id"),
                 fields.get("interface_name"), fields.get("ip"), fields.get("prefix_len"),
                 fields.get("action"), 0, fields.get("user_id"), now, None)
            )
        return journal_id

    def mark_complete(self, journal_id: str) -> None:
        now = _now()
        with self._db.conn:
            self._db.conn.execute(
                "UPDATE network_change_journal SET completed=1, completed_at=? WHERE journal_id=?",
                (now, journal_id)
            )

    def incomplete(self) -> List[Dict[str, Any]]:
        rows = self._db.conn.execute(
            "SELECT * FROM network_change_journal WHERE completed=0 ORDER BY created_at"
        ).fetchall()
        return [dict(r) for r in rows]

    def count_incomplete(self) -> int:
        row = self._db.conn.execute(
            "SELECT COUNT(*) AS c FROM network_change_journal WHERE completed=0"
        ).fetchone()
        return row["c"] if row else 0


def _normalise_mac(mac: str) -> str:
    return mac.lower().replace("-", ":").replace(".", ":").strip() if mac else ""


__all__ = [
    "SiteRepo",
    "NetworkProfileRepo",
    "LocationRepo",
    "AssetRepo",
    "EndpointRepo",
    "ObservationRepo",
    "TopologyRepo",
    "ChangeJobRepo",
    "CredentialProfileRepo",
    "NetworkChangeJournalRepo",
]
