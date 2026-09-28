"""Network rebuild reconciliation service.

This is the operator-facing workflow that makes Camera-Location useful after a
site has been reformatted: load the previous inventory, run a new discovery
session, match durable identity keys, and present four queues for operator
confirmation where certainty is low.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

from ..domain.models import CameraAsset, DeviceEndpoint
from ..models import DiscoveredDevice
from ..persistence.db import Database
from ..persistence.repos import AssetRepo, EndpointRepo, ObservationRepo
from ..services.reconciliation import ReconciliationService, _normalise_mac


class MatchConfidence(Enum):
    EXACT = "exact"           # ONVIF UUID or serial
    STRONG = "strong"         # MAC address
    MODERATE = "moderate"     # NVR channel or model + location hint
    WEAK = "weak"             # Same IP or historical location only
    NONE = "none"             # Unknown device


@dataclass
class ReconciliationMatch:
    asset_id: str
    endpoint_id: Optional[str]
    discovered_ip: str
    match_type: str
    confidence: str
    prior_ip: Optional[str] = None
    prior_mac: Optional[str] = None
    location_hint: Optional[str] = None
    needs_confirmation: bool = False
    reason: str = ""


@dataclass
class ReconciliationReport:
    site_id: str
    session_id: str
    matched_auto: List[ReconciliationMatch] = field(default_factory=list)
    likely_match: List[ReconciliationMatch] = field(default_factory=list)
    new_unknown: List[Dict[str, str]] = field(default_factory=list)
    missing: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "site_id": self.site_id,
            "session_id": self.session_id,
            "matched_auto": [
                {
                    "asset_id": m.asset_id,
                    "endpoint_id": m.endpoint_id,
                    "discovered_ip": m.discovered_ip,
                    "match_type": m.match_type,
                    "confidence": m.confidence,
                    "prior_ip": m.prior_ip,
                    "prior_mac": m.prior_mac,
                    "location_hint": m.location_hint,
                    "needs_confirmation": m.needs_confirmation,
                    "reason": m.reason,
                }
                for m in self.matched_auto
            ],
            "likely_match": [
                {
                    "asset_id": m.asset_id,
                    "endpoint_id": m.endpoint_id,
                    "discovered_ip": m.discovered_ip,
                    "match_type": m.match_type,
                    "confidence": m.confidence,
                    "prior_ip": m.prior_ip,
                    "prior_mac": m.prior_mac,
                    "location_hint": m.location_hint,
                    "needs_confirmation": m.needs_confirmation,
                    "reason": m.reason,
                }
                for m in self.likely_match
            ],
            "new_unknown": self.new_unknown,
            "missing": self.missing,
        }


class NetworkRebuildService:
    """Reconcile a fresh discovery session against a persisted site inventory."""

    def __init__(self, db: Database):
        self._db = db
        self._assets = AssetRepo(db)
        self._endpoints = EndpointRepo(db)
        self._obs = ObservationRepo(db)
        self._reconciler = ReconciliationService(db)

    def reconcile_session(
        self,
        site_id: str,
        discovered_devices: List[DiscoveredDevice],
    ) -> ReconciliationReport:
        """Run the full four-queue reconciliation workflow."""
        report = ReconciliationReport(site_id=site_id, session_id=self._reconciler.session_id)

        previous_current = self._endpoints.list_current(site_id)
        previous_by_asset: Dict[str, DeviceEndpoint] = {
            e.asset_id: e for e in previous_current if e.asset_id
        }
        seen_asset_ids: set = set()

        for device in discovered_devices:
            ip = (device.ip or "").strip()
            mac = _normalise_mac(device.mac)
            serial = (device.serial or "").strip()
            onvif_uuid = (device.onvif_uuid or "").strip()

            match_type, confidence, asset = self._best_match(
                site_id, serial, onvif_uuid, mac, ip
            )

            if asset:
                seen_asset_ids.add(asset.asset_id)
                prior = previous_by_asset.get(asset.asset_id)
                match = ReconciliationMatch(
                    asset_id=asset.asset_id,
                    endpoint_id=prior.endpoint_id if prior else None,
                    discovered_ip=ip,
                    match_type=match_type,
                    confidence=confidence.value,
                    prior_ip=prior.ip if prior else None,
                    prior_mac=prior.mac if prior else None,
                    location_hint=prior.location_hint if hasattr(prior, "location_hint") else None,
                )

                if confidence in (MatchConfidence.EXACT, MatchConfidence.STRONG):
                    match.needs_confirmation = False
                    report.matched_auto.append(match)
                else:
                    match.needs_confirmation = True
                    match.reason = (
                        f"Only matched by {match_type}; verify this is the expected camera."
                    )
                    report.likely_match.append(match)
                continue

            # No durable match — could be a brand-new camera or foreign device.
            report.new_unknown.append({
                "ip": ip,
                "mac": mac,
                "vendor": device.vendor,
                "model": device.model,
                "reason": "No matching ONVIF UUID, serial, or MAC in the site inventory.",
            })

        # Known assets with no current endpoint.
        for asset in self._assets.list_for_site(site_id):
            if asset.asset_id not in seen_asset_ids:
                location = None
                # Optional: look up expected location label if a location_repo is available
                report.missing.append({
                    "asset_id": asset.asset_id,
                    "asset_tag": asset.asset_tag,
                    "serial": asset.serial,
                    "manufacturer": asset.manufacturer,
                    "model": asset.model,
                    "expected_location_id": asset.expected_location_id,
                    "reason": "Asset expected at this site but not seen in the latest scan.",
                })

        return report

    def persist_report(self, report: ReconciliationReport) -> None:
        """Append a reconciliation_report observation to the site."""
        from ..persistence.db import new_uuid
        from ..domain.models import Observation
        self._obs.save(Observation(
            observation_id=new_uuid(),
            site_id=report.site_id,
            kind="reconciliation_report",
            detail=f"Reconciliation session {report.session_id}: "
                   f"{len(report.matched_auto)} auto, "
                   f"{len(report.likely_match)} likely, "
                   f"{len(report.new_unknown)} unknown, "
                   f"{len(report.missing)} missing",
            source="network_rebuild_service",
            weight=0,
            session_id=report.session_id,
        ))

    def _best_match(
        self,
        site_id: str,
        serial: str,
        onvif_uuid: str,
        mac: str,
        ip: str,
    ) -> Tuple[str, MatchConfidence, Optional[CameraAsset]]:
        if onvif_uuid:
            asset = self._assets.find_by_onvif_uuid(site_id, onvif_uuid)
            if asset:
                return "onvif_uuid", MatchConfidence.EXACT, asset
        if serial:
            asset = self._assets.find_by_serial(site_id, serial)
            if asset:
                return "serial", MatchConfidence.EXACT, asset
        if mac:
            endpoint = self._endpoints.find_by_mac(mac)
            if endpoint and endpoint.asset_id:
                asset = self._assets.get(endpoint.asset_id)
                if asset and asset.site_id == site_id:
                    return "mac_address", MatchConfidence.STRONG, asset
        # NVR channel relationships are stored as topology edges and would be
        # consulted here once topology import is wired.
        if ip:
            endpoint = self._endpoints.find_by_ip(ip)
            if endpoint and endpoint.asset_id:
                asset = self._assets.get(endpoint.asset_id)
                if asset and asset.site_id == site_id:
                    return "historical_ip", MatchConfidence.WEAK, asset
        return "", MatchConfidence.NONE, None
