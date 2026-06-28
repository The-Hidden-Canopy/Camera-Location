"""Reconciliation service: map discovered network evidence to durable assets.

The reconciliation rules are intentionally conservative.  A discovered endpoint
is matched to an existing asset only when at least one durable identity key
agrees: ONVIF UUID, serial number, MAC address, or (last resort) exact current
IP if we are certain it is the same lease.  When identity moves from one IP to
another, we preserve the asset and append endpoint history.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from ..domain.models import CameraAsset, DeviceEndpoint, Observation
from ..models import DiscoveredDevice, Evidence
from ..persistence.db import Database, new_uuid
from ..persistence.repos import (
    AssetRepo,
    EndpointRepo,
    ObservationRepo,
)


_MATCH_BY_UUID = 1
_MATCH_BY_SERIAL = 2
_MATCH_BY_MAC = 3
_MATCH_BY_IP = 4
_MATCH_BY_HARDWARE_ID = 5


class ReconciliationService:
    """Persists discovery events and reconciles them to durable camera assets."""

    def __init__(self, db: Database):
        self._db = db
        self._assets = AssetRepo(db)
        self._endpoints = EndpointRepo(db)
        self._obs = ObservationRepo(db)
        self._session_id = str(uuid.uuid4())

    @property
    def session_id(self) -> str:
        return self._session_id

    def new_session(self) -> str:
        self._session_id = str(uuid.uuid4())
        return self._session_id

    # ─── Public reconcile entry point ────────────────────────────────────────

    def reconcile_device(
        self,
        device: DiscoveredDevice,
        site_id: Optional[str] = None,
        evidence: Optional[List[Evidence]] = None,
    ) -> Tuple[DeviceEndpoint, Optional[CameraAsset], str]:
        """Return (endpoint, asset_or_none, outcome).

        outcome is one of:
          matched_uuid, matched_serial, matched_mac, matched_ip,
          moved_new_ip, replaced_or_spoofed_mac, new_asset_created,
          new_unknown_device, merged_endpoint
        """
        serial = (device.serial or "").strip()
        onvif_uuid = (device.onvif_uuid or "").strip()
        mac = _normalise_mac(device.mac)
        ip = (device.ip or "").strip()

        match_kind, asset = self._find_asset(site_id, serial, onvif_uuid, mac)

        if not asset and mac:
            # MAC is durable-ish; create a placeholder asset so the
            # network has a camera-level identity even before serial is known.
            asset = self._create_asset_from_device(device, site_id)
            match_kind = "new_asset_created"

        if not asset:
            # Truly unknown device. Persist an endpoint without an asset.
            endpoint = self._ensure_endpoint(
                asset_id=None,
                ip=ip,
                mac=mac,
                onvif_uuid=onvif_uuid,
                device=device,
                site_id=site_id,
            )
            self._record_observations(
                endpoint=endpoint,
                asset=None,
                site_id=site_id,
                device=device,
                evidence=evidence,
            )
            return endpoint, None, "new_unknown_device"

        # We have an asset. Resolve or create the current endpoint.
        asset = self._update_asset_from_device(asset, device, site_id)
        existing_current: List[DeviceEndpoint] = []
        if asset.asset_id:
            for ep in self._endpoints.list_for_asset(asset.asset_id):
                if ep.is_current and (ep.ip == ip or (mac and ep.mac == mac)):
                    existing_current.append(ep)
                    break
        if not existing_current and mac:
            by_mac = self._endpoints.find_by_mac(mac)
            if by_mac and by_mac.is_current and by_mac.asset_id == asset.asset_id:
                existing_current.append(by_mac)

        outcome = match_kind
        if existing_current:
            endpoint = existing_current[0]
            if ip and endpoint.ip and ip != endpoint.ip:
                # Same asset, new IP — this is the network-reformat case.
                endpoint = self._ensure_endpoint(
                    asset_id=asset.asset_id,
                    ip=ip,
                    mac=mac,
                    onvif_uuid=onvif_uuid,
                    device=device,
                    site_id=site_id,
                    force_new=True,
                    move_kind="ip",
                )
                outcome = "moved_new_ip"
            elif mac and endpoint.mac and mac != endpoint.mac:
                # Same asset, different MAC — possible replacement/spoof.
                endpoint = self._ensure_endpoint(
                    asset_id=asset.asset_id,
                    ip=ip,
                    mac=mac,
                    onvif_uuid=onvif_uuid,
                    device=device,
                    site_id=site_id,
                    force_new=True,
                    move_kind="mac",
                )
                outcome = "replaced_or_spoofed_mac"
            else:
                endpoint = self._update_endpoint(endpoint, device)
                outcome = match_kind
        else:
            endpoint = self._ensure_endpoint(
                asset_id=asset.asset_id,
                ip=ip,
                mac=mac,
                onvif_uuid=onvif_uuid,
                device=device,
                site_id=site_id,
            )
            outcome = match_kind if match_kind != "new_asset_created" else "new_asset_created"

        self._record_observations(
            endpoint=endpoint,
            asset=asset,
            site_id=site_id,
            device=device,
            evidence=evidence,
        )
        return endpoint, asset, outcome

    # ─── Internal lookups ───────────────────────────────────────────────────

    def _find_asset(
        self,
        site_id: Optional[str],
        serial: str,
        onvif_uuid: str,
        mac: str,
    ) -> Tuple[str, Optional[CameraAsset]]:
        if onvif_uuid:
            asset = self._assets.find_by_onvif_uuid(site_id, onvif_uuid)
            if asset:
                return "matched_uuid", asset
        if serial:
            asset = self._assets.find_by_serial(site_id, serial)
            if asset:
                return "matched_serial", asset
        if mac:
            endpoint = self._endpoints.find_by_mac(mac)
            if endpoint and endpoint.asset_id:
                asset = self._assets.get(endpoint.asset_id)
                if asset and (not site_id or asset.site_id == site_id):
                    return "matched_mac", asset
        if mac:
            endpoint = self._endpoints.find_by_ip(mac)
            # IP field here is intentionally not mac; we already searched mac column.
            # Hardware-ID lookup goes via asset table if we ever have one.
            pass
        return "", None

    # ─── Endpoint helpers ────────────────────────────────────────────────────

    def _ensure_endpoint(
        self,
        asset_id: Optional[str],
        ip: str,
        mac: str,
        onvif_uuid: str,
        device: DiscoveredDevice,
        site_id: Optional[str],
        force_new: bool = False,
        move_kind: str = "",
    ) -> DeviceEndpoint:
        """Create or update a current endpoint. If the IP has changed for the same
        asset, deprecate the previous endpoint and create a new one."""
        old_by_ip = self._endpoints.find_by_ip(ip)
        old_by_mac = self._endpoints.find_by_mac(mac) if mac else None

        # Prefer an existing current record attached to the asset unless this is a
        # deliberate move.
        existing: Optional[DeviceEndpoint] = None
        if not force_new and asset_id:
            current = self._endpoints.list_for_asset(asset_id)
            for ep in current:
                if ep.is_current and (ep.ip == ip or (mac and ep.mac == mac)):
                    existing = ep
                    break
        if not existing and not force_new and old_by_ip and old_by_ip.asset_id == asset_id:
            existing = old_by_ip

        if existing:
            return self._update_endpoint(existing, device)

        # Same asset, new IP or MAC — create a new current endpoint and mark
        # older current endpoints for this asset as historical.
        if asset_id:
            self._endpoints.deprecate_by_asset(asset_id)

        ip_history = []
        mac_history = []
        if old_by_ip and old_by_ip.ip and old_by_ip.ip != ip:
            ip_history.append(old_by_ip.ip)
        if old_by_mac and old_by_mac.mac and old_by_mac.mac != mac:
            mac_history.append(old_by_mac.mac)
        # When deliberately moving same MAC to new IP, old_by_mac is the prior endpoint.
        if move_kind == "ip" and old_by_mac and old_by_mac.ip and old_by_mac.ip not in ip_history:
            ip_history.append(old_by_mac.ip)

        new_endpoint = DeviceEndpoint(
            endpoint_id=new_uuid(),
            asset_id=asset_id,
            ip=ip,
            ip_history=ip_history,
            mac=mac,
            mac_history=mac_history,
            onvif_uuid=onvif_uuid,
            rtsp_url=device.rtsp_url,
            onvif_url=device.onvif_url,
            web_url=device.web_url,
            firmware=device.firmware,
            subnet=device.subnet,
            last_seen=datetime.now(timezone.utc),
            is_current=True,
            device_class=device.device_class,
        )
        self._endpoints.save(new_endpoint)

        # Record a move observation if prior endpoints for this asset exist.
        if asset_id and (old_by_ip or old_by_mac):
            prior_ip = old_by_ip.ip if old_by_ip else (old_by_mac.ip if old_by_mac else "")
            self._obs.save(Observation(
                observation_id=new_uuid(),
                site_id=site_id,
                endpoint_id=new_endpoint.endpoint_id,
                asset_id=asset_id,
                kind="network_move",
                detail=f"Asset appeared at {ip} (MAC {mac}) after previously being seen "
                       f"at {prior_ip}",
                source="reconciliation",
                weight=0,
                session_id=self._session_id,
            ))

        return new_endpoint

    def _update_endpoint(self, endpoint: DeviceEndpoint, device: DiscoveredDevice) -> DeviceEndpoint:
        if device.ip and endpoint.ip != device.ip:
            endpoint.ip_history = _append_history(endpoint.ip_history, device.ip)
            endpoint.ip = device.ip
        if device.mac and endpoint.mac != _normalise_mac(device.mac):
            endpoint.mac_history = _append_history(endpoint.mac_history, device.mac)
            endpoint.mac = _normalise_mac(device.mac)
        if device.onvif_uuid and not endpoint.onvif_uuid:
            endpoint.onvif_uuid = device.onvif_uuid
        if device.rtsp_url and not endpoint.rtsp_url:
            endpoint.rtsp_url = device.rtsp_url
        if device.onvif_url and not endpoint.onvif_url:
            endpoint.onvif_url = device.onvif_url
        if device.web_url and not endpoint.web_url:
            endpoint.web_url = device.web_url
        if device.firmware and not endpoint.firmware:
            endpoint.firmware = device.firmware
        if device.subnet and not endpoint.subnet:
            endpoint.subnet = device.subnet
        endpoint.last_seen = datetime.now(timezone.utc)
        endpoint.is_current = True
        endpoint.device_class = device.device_class or endpoint.device_class
        self._endpoints.save(endpoint)
        return endpoint

    # ─── Asset helpers ───────────────────────────────────────────────────────

    def _create_asset_from_device(
        self,
        device: DiscoveredDevice,
        site_id: Optional[str],
    ) -> CameraAsset:
        asset = CameraAsset(
            asset_id=new_uuid(),
            site_id=site_id,
            serial=(device.serial or "").strip(),
            manufacturer=device.vendor if device.vendor != "Unknown" else "",
            model=device.model,
            onvif_uuid=(device.onvif_uuid or "").strip(),
            installed_status="unverified",
            notes="Created automatically from discovery evidence.",
        )
        self._assets.save(asset)
        return asset

    def _update_asset_from_device(
        self,
        asset: CameraAsset,
        device: DiscoveredDevice,
        site_id: Optional[str],
    ) -> CameraAsset:
        changed = False
        if site_id and not asset.site_id:
            asset.site_id = site_id
            changed = True
        if device.serial and not asset.serial:
            asset.serial = device.serial.strip()
            changed = True
        if device.onvif_uuid and not asset.onvif_uuid:
            asset.onvif_uuid = device.onvif_uuid.strip()
            changed = True
        if device.vendor and device.vendor != "Unknown" and not asset.manufacturer:
            asset.manufacturer = device.vendor
            changed = True
        if device.model and not asset.model:
            asset.model = device.model
            changed = True
        if changed:
            self._assets.save(asset)
        return asset

    # ─── Observation helpers ───────────────────────────────────────────────────

    def _record_observations(
        self,
        endpoint: DeviceEndpoint,
        asset: Optional[CameraAsset],
        site_id: Optional[str],
        device: DiscoveredDevice,
        evidence: Optional[List[Evidence]],
    ) -> None:
        for ev in evidence or device.evidence:
            latest = self._obs.latest_by_kind(endpoint.endpoint_id, ev.kind)
            if latest and latest.session_id == self._session_id:
                same_detail = (latest.detail or "") == (ev.detail or "")
                same_source = (latest.source or "") == (ev.source or "")
                same_raw = (latest.raw or "") == ((ev.raw or "")[:2000])
                if same_detail and same_source and same_raw:
                    continue
            obs = Observation(
                observation_id=new_uuid(),
                site_id=site_id,
                endpoint_id=endpoint.endpoint_id,
                asset_id=asset.asset_id if asset else None,
                kind=ev.kind,
                detail=ev.detail,
                source=ev.source,
                sensor_id=ev.sensor_id,
                interface=ev.interface,
                capture_position=ev.capture_position,
                visibility_limit=ev.visibility_limit,
                weight=ev.weight,
                raw=(ev.raw or "")[:2000],
                session_id=self._session_id,
            )
            self._obs.save(obs)

    # ─── Reconciliation queues for UI ────────────────────────────────────────

    def reconciliation_queues(
        self,
        site_id: Optional[str],
        current_device_ips: List[str],
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Compare discovered devices to persisted site inventory.

        Returns four queues:
          matched_auto        — asset found via durable identity
          likely_match        — asset found but with tension (different MAC/IP)
          new_unknown         — no durable identity match
          missing             — known asset with no current endpoint
        """
        matched_auto: List[Dict[str, Any]] = []
        likely_match: List[Dict[str, Any]] = []
        new_unknown: List[Dict[str, Any]] = []

        known_endpoints = self._endpoints.list_current(site_id)
        known_ips = {e.ip for e in known_endpoints if e.ip}

        for ip in current_device_ips:
            endpoint = self._endpoints.find_by_ip(ip)
            if endpoint and endpoint.asset_id:
                asset = self._assets.get(endpoint.asset_id)
                if asset:
                    matched_auto.append({
                        "ip": ip,
                        "asset_id": asset.asset_id,
                        "asset_tag": asset.asset_tag,
                        "outcome": "matched_ip",
                    })
                    continue
            new_unknown.append({"ip": ip, "reason": "no durable identity match"})

        # Known assets with no current endpoint (offline / missing / not scanned yet)
        missing: List[Dict[str, Any]] = []
        if site_id:
            for asset in self._assets.list_for_site(site_id):
                current_eps = [e for e in self._endpoints.list_for_asset(asset.asset_id) if e.is_current]
                if not current_eps:
                    missing.append({
                        "asset_id": asset.asset_id,
                        "asset_tag": asset.asset_tag,
                        "serial": asset.serial,
                        "expected_location_id": asset.expected_location_id,
                    })

        return {
            "matched_auto": matched_auto,
            "likely_match": likely_match,
            "new_unknown": new_unknown,
            "missing": missing,
        }


def _normalise_mac(mac: str) -> str:
    return mac.lower().replace("-", ":").replace(".", ":").strip() if mac else ""


def _append_history(history: List[str], value: str) -> List[str]:
    value = (value or "").strip()
    if not value:
        return history
    if value not in history:
        history = list(history)
        history.append(value)
    return history
