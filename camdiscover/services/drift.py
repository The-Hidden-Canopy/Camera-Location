"""Baseline-aware network drift detection."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..domain.models import CameraAsset, DeviceEndpoint, Observation, Site
from ..models import DiscoveredDevice
from ..persistence.db import Database, new_uuid
from ..persistence.repos import AssetRepo, EndpointRepo, ObservationRepo, SiteRepo
from ..seeds import is_apipa
from .reconciliation import _normalise_mac


@dataclass
class DriftFinding:
    finding_type: str
    severity: str
    reason: str
    asset_id: str = ""
    endpoint_id: str = ""
    ip: str = ""
    mac: str = ""
    asset_class: str = ""
    observed_asset_class: str = ""
    subnet: str = ""

    def to_dict(self) -> dict:
        return {
            "finding_type": self.finding_type,
            "severity": self.severity,
            "reason": self.reason,
            "asset_id": self.asset_id,
            "endpoint_id": self.endpoint_id,
            "ip": self.ip,
            "mac": self.mac,
            "asset_class": self.asset_class,
            "observed_asset_class": self.observed_asset_class,
            "subnet": self.subnet,
        }


@dataclass
class DriftReport:
    site_id: str
    findings: List[DriftFinding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "site_id": self.site_id,
            "findings": [item.to_dict() for item in self.findings],
        }


class DriftService:
    """Compare current discovery against persisted inventory and site baseline."""

    def __init__(self, db: Database):
        self._db = db
        self._sites = SiteRepo(db)
        self._assets = AssetRepo(db)
        self._endpoints = EndpointRepo(db)
        self._obs = ObservationRepo(db)

    def analyze(self, site_id: str, discovered_devices: List[DiscoveredDevice]) -> DriftReport:
        site = self._sites.get(site_id)
        if not site:
            raise ValueError("site not found")

        report = DriftReport(site_id=site_id)
        current_endpoints = self._endpoints.list_current(site_id)
        current_by_asset = {endpoint.asset_id: endpoint for endpoint in current_endpoints if endpoint.asset_id}
        matched_asset_ids: set[str] = set()

        for device in discovered_devices:
            asset = self._match_asset(site_id, device)
            endpoint = current_by_asset.get(asset.asset_id) if asset else None
            asset_class = device.asset_class
            subnet = (device.subnet or "").strip()
            ip = (device.ip or "").strip()
            mac = _normalise_mac(device.mac)

            if asset:
                matched_asset_ids.add(asset.asset_id)
                if endpoint and ip and endpoint.ip and endpoint.ip != ip:
                    report.findings.append(
                        DriftFinding(
                            finding_type="known_device_new_ip",
                            severity="warning",
                            reason=f"Known asset moved from {endpoint.ip} to {ip}.",
                            asset_id=asset.asset_id,
                            endpoint_id=endpoint.endpoint_id,
                            ip=ip,
                            mac=mac,
                            asset_class=asset.asset_class,
                            observed_asset_class=asset_class,
                            subnet=subnet,
                        )
                    )
                if endpoint and mac and endpoint.mac and _normalise_mac(endpoint.mac) != mac:
                    report.findings.append(
                        DriftFinding(
                            finding_type="known_device_new_mac",
                            severity="warning",
                            reason=f"Known asset MAC changed from {endpoint.mac} to {mac}.",
                            asset_id=asset.asset_id,
                            endpoint_id=endpoint.endpoint_id,
                            ip=ip,
                            mac=mac,
                            asset_class=asset.asset_class,
                            observed_asset_class=asset_class,
                            subnet=subnet,
                        )
                    )
                if (
                    asset.asset_class
                    and asset.asset_class != "unknown_endpoint"
                    and asset_class
                    and asset_class != "unknown_endpoint"
                    and asset.asset_class != asset_class
                ):
                    report.findings.append(
                        DriftFinding(
                            finding_type="device_class_changed",
                            severity="warning",
                            reason=f"Asset was recorded as {asset.asset_class} but now looks like {asset_class}.",
                            asset_id=asset.asset_id,
                            endpoint_id=endpoint.endpoint_id if endpoint else "",
                            ip=ip,
                            mac=mac,
                            asset_class=asset.asset_class,
                            observed_asset_class=asset_class,
                            subnet=subnet,
                        )
                    )
            elif subnet and subnet in site.expected_subnets:
                report.findings.append(
                    DriftFinding(
                        finding_type="unknown_device_on_expected_subnet",
                        severity="warning",
                        reason="Unknown device appeared on an expected site subnet.",
                        ip=ip,
                        mac=mac,
                        observed_asset_class=asset_class,
                        subnet=subnet,
                    )
                )

            if (device.apipa_seen or is_apipa(ip)) and ip:
                report.findings.append(
                    DriftFinding(
                        finding_type="apipa_recovery_mode_device_seen",
                        severity="warning",
                        reason="Observed an APIPA address; device likely lost DHCP or network path.",
                        asset_id=asset.asset_id if asset else "",
                        endpoint_id=endpoint.endpoint_id if endpoint else "",
                        ip=ip,
                        mac=mac,
                        asset_class=asset.asset_class if asset else "",
                        observed_asset_class=asset_class,
                        subnet=subnet,
                    )
                )

            if subnet and subnet in site.known_old_subnets:
                report.findings.append(
                    DriftFinding(
                        finding_type="device_on_old_subnet",
                        severity="warning",
                        reason="Observed device on a subnet marked as legacy for this site.",
                        asset_id=asset.asset_id if asset else "",
                        endpoint_id=endpoint.endpoint_id if endpoint else "",
                        ip=ip,
                        mac=mac,
                        asset_class=asset.asset_class if asset else "",
                        observed_asset_class=asset_class,
                        subnet=subnet,
                    )
                )

            if (
                site.unauthorized_device_alerts
                and site.authorized_classes
                and asset_class
                and asset_class not in site.authorized_classes
                and (not site.expected_subnets or subnet in site.expected_subnets or is_apipa(ip))
            ):
                report.findings.append(
                    DriftFinding(
                        finding_type="unauthorized_device_class",
                        severity="warning",
                        reason=f"Observed class {asset_class} is outside the authorized site baseline.",
                        asset_id=asset.asset_id if asset else "",
                        endpoint_id=endpoint.endpoint_id if endpoint else "",
                        ip=ip,
                        mac=mac,
                        asset_class=asset.asset_class if asset else "",
                        observed_asset_class=asset_class,
                        subnet=subnet,
                    )
                )

        for asset in self._assets.list_for_site(site_id):
            if asset.installed_status == "retired":
                continue
            if asset.asset_id in matched_asset_ids:
                continue
            report.findings.append(
                DriftFinding(
                    finding_type="known_camera_missing" if asset.asset_class == "camera" else "infrastructure_missing",
                    severity="critical" if asset.asset_class in ("camera", "nvr", "access_point", "wireless_bridge") else "warning",
                    reason="Persisted asset was not seen in the latest discovery set.",
                    asset_id=asset.asset_id,
                    asset_class=asset.asset_class,
                )
            )

        return report

    def persist_report(self, report: DriftReport) -> None:
        self._obs.save(
            Observation(
                observation_id=new_uuid(),
                site_id=report.site_id,
                kind="network_drift_report",
                detail=f"Generated drift report with {len(report.findings)} findings.",
                source="drift_service",
                weight=0,
            )
        )

    def _match_asset(self, site_id: str, device: DiscoveredDevice) -> Optional[CameraAsset]:
        onvif_uuid = (device.onvif_uuid or "").strip()
        if onvif_uuid:
            asset = self._assets.find_by_onvif_uuid(site_id, onvif_uuid)
            if asset:
                return asset

        serial = (device.serial or "").strip()
        if serial:
            asset = self._assets.find_by_serial(site_id, serial)
            if asset:
                return asset

        mac = _normalise_mac(device.mac)
        if mac:
            endpoint = self._endpoints.find_by_mac(mac)
            if endpoint and endpoint.asset_id:
                asset = self._assets.get(endpoint.asset_id)
                if asset and asset.site_id == site_id:
                    return asset

        ip = (device.ip or "").strip()
        if ip:
            endpoint = self._endpoints.find_by_ip(ip)
            if endpoint and endpoint.asset_id:
                asset = self._assets.get(endpoint.asset_id)
                if asset and asset.site_id == site_id:
                    return asset

        return None
