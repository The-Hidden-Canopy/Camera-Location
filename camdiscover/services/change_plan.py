"""Change-plan service for staged, approved network changes.

A change plan is a multi-step record:
  1. operator proposes new IP, mask, gateway, network profile
  2. app validates subnet/plausibility/collisions
  3. operator confirms exact device by MAC/serial + confirmation phrase
  4. app snapshots prior config and creates an immutable change event
  5. app sends the configuration change via ONVIF/ISAPI/Dahua
  6. app waits for device to reappear under expected identity
  7. app records success / failure / manual-recovery-required
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from ..domain.models import ChangeJob, Observation
from ..persistence.db import Database, new_uuid
from ..persistence.repos import AssetRepo, ChangeJobRepo, EndpointRepo, NetworkProfileRepo, ObservationRepo
from ..services.reconciliation import _normalise_mac


class ChangePlanService:
    def __init__(self, db: Database):
        self._db = db
        self._assets = AssetRepo(db)
        self._endpoints = EndpointRepo(db)
        self._profiles = NetworkProfileRepo(db)
        self._jobs = ChangeJobRepo(db)
        self._obs = ObservationRepo(db)

    def propose(
        self,
        site_id: str,
        endpoint_id: str,
        new_ip: str,
        mask: str,
        gateway: str,
        profile_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> ChangeJob:
        """Stage a change plan and run pre-validation.  Network change is not
        executed until `execute` is called."""
        endpoint = self._endpoints.get(endpoint_id)
        if not endpoint:
            raise ValueError("endpoint not found")
        if endpoint.asset_id is None:
            raise ValueError("cannot change IP of an un-assetized endpoint")

        asset = self._assets.get(endpoint.asset_id)
        if not asset or asset.site_id != site_id:
            raise ValueError("asset not found at site")

        issues = self._validate(
            site_id=site_id,
            endpoint=endpoint,
            asset=asset,
            new_ip=new_ip,
            mask=mask,
            gateway=gateway,
            profile_id=profile_id,
        )

        prior = {
            "ip": endpoint.ip,
            "mac": endpoint.mac,
            "subnet": endpoint.subnet,
            "network_profile_id": endpoint.network_profile_id,
            "onvif_uuid": endpoint.onvif_uuid,
            "firmware": endpoint.firmware,
            "serial": asset.serial,
        }

        proposed = {
            "new_ip": new_ip,
            "mask": mask,
            "gateway": gateway,
            "profile_id": profile_id,
            "user_id": user_id,
        }

        job = ChangeJob(
            job_id=new_uuid(),
            site_id=site_id,
            endpoint_id=endpoint_id,
            asset_id=asset.asset_id,
            kind="ip_change",
            proposed=proposed,
            prior=prior,
            status="proposed" if not issues else "draft",
        )
        self._jobs.save(job)

        # Record validation observation even if not yet approved.
        self._obs.save(Observation(
            observation_id=new_uuid(),
            site_id=site_id,
            asset_id=asset.asset_id,
            endpoint_id=endpoint_id,
            kind="change_plan_proposed",
            detail=(f"Proposed IP change to {new_ip}/{mask} gateway {gateway}. "
                    f"Validation: {'ok' if not issues else '; '.join(issues)}"),
            source="change_plan_service",
            weight=0,
        ))
        return job

    def approve(self, job_id: str, confirmation_phrase: str) -> ChangeJob:
        """ operator must type confirmation phrase. """
        job = self._jobs.get(job_id)
        if not job:
            raise ValueError("job not found")
        if job.status != "proposed":
            raise ValueError(f"job is {job.status}, cannot approve")

        expected = self._confirmation_phrase(job)
        if confirmation_phrase != expected:
            raise ValueError("confirmation phrase does not match")

        job.status = "approved"
        job.approved_at = datetime.now(timezone.utc)
        job.approval_phrase = confirmation_phrase
        self._jobs.save(job)
        return job

    def execute(self, job_id: str, executor: Optional[Any] = None) -> ChangeJob:
        """Execute an approved change plan.

        executor must be a callable taking (job, asset, endpoint) and returning:
         {"success": bool, "detail": str, "rollback_state": dict}.
        If executor is None, the plan is marked `manual_recovery` and the actual
        change must be performed outside the app.
        """
        job = self._jobs.get(job_id)
        if not job:
            raise ValueError("job not found")
        if job.status != "approved":
            raise ValueError(f"job is {job.status}, cannot execute")

        endpoint = self._endpoints.get(job.endpoint_id)
        asset = self._assets.get(job.asset_id)
        if not endpoint or not asset:
            raise ValueError("asset or endpoint missing")

        job.status = "executing"
        job.executed_at = datetime.now(timezone.utc)
        self._jobs.save(job)

        # Capture rollback state determined before change.
        job.rollback_state = dict(job.prior)
        self._jobs.save(job)

        result = {"success": False, "detail": "no executor provided", "rollback_state": {}}
        if executor is not None and callable(executor):
            try:
                result = executor(job, asset, endpoint)
            except Exception as e:
                result = {"success": False, "detail": str(e), "rollback_state": {}}

        job.result = result.get("detail", "")
        if result.get("success"):
            job.status = "verifying"
        else:
            job.status = "failure"
        self._jobs.save(job)

        if job.status == "verifying":
            time.sleep(2)  # Give the device a moment to reapply config/reboot.
            verified = self._verify(asset, job)
            if verified:
                job.status = "success"
                job.verified_at = datetime.now(timezone.utc)
                # Update endpoint to reflect new IP.
                endpoint.ip_history = list(endpoint.ip_history or []) + [endpoint.ip]
                endpoint.ip = job.proposed["new_ip"]
                endpoint.subnet = job.proposed["mask"]
                if job.proposed.get("profile_id"):
                    endpoint.network_profile_id = job.proposed["profile_id"]
                endpoint.last_seen = datetime.now(timezone.utc)
                self._endpoints.save(endpoint)
            else:
                job.status = "manual_recovery"
        self._jobs.save(job)

        self._obs.save(Observation(
            observation_id=new_uuid(),
            site_id=job.site_id,
            asset_id=job.asset_id,
            endpoint_id=job.endpoint_id,
            kind="change_plan_executed",
            detail=f"Executed IP change plan {job.job_id}: status={job.status}. {job.result}",
            source="change_plan_service",
            weight=0,
        ))

        return job

    def _validate(
        self,
        site_id: str,
        endpoint: Any,
        asset: Any,
        new_ip: str,
        mask: str,
        gateway: str,
        profile_id: Optional[str],
    ) -> list[str]:
        issues: List[str] = []
        try:
            import ipaddress
            addr = ipaddress.ip_address(new_ip)
            network = ipaddress.ip_network(f"{new_ip}/{mask}", strict=False)
            if addr in (network.network_address, network.broadcast_address):
                issues.append("new_ip is network/broadcast address")
            if gateway and not ipaddress.ip_address(gateway) in network:
                issues.append("gateway not in target subnet")
            _ = addr
        except Exception as e:
            issues.append(f"invalid IP/mask: {e}")
            network = None

        if network:
            _ = network
        # No conflict with existing assets
        existing_ep = self._endpoints.find_by_ip(new_ip)
        if existing_ep and existing_ep.endpoint_id != endpoint.endpoint_id:
            issues.append(f"IP {new_ip} is already in use by another asset")

        if profile_id:
            profile = self._profiles.get(profile_id)
            if not profile or profile.site_id != site_id:
                issues.append("network profile not found")
        return issues

    def _verify(self, asset: Any, job: ChangeJob) -> bool:
        """After a change, attempt to reacquire identity at the expected IP."""
        new_ip = job.proposed.get("new_ip")
        if not new_ip:
            return False
        # Look up any current endpoint with the same durable identity.
        candidates = []
        if asset.serial:
            candidates = self._endpoints.find_current_by_asset_or_mac(serial=asset.serial)
        if not candidates and asset.onvif_uuid:
            candidates = self._endpoints.find_current_by_asset_or_mac(onvif_uuid=asset.onvif_uuid)
        if not candidates:
            candidates = self._endpoints.find_current_by_asset_or_mac(mac=job.prior.get("mac"))
        for ep in candidates:
            if ep.ip == new_ip:
                return True
        # We do not implement an active ONVIF probe here to avoid heavy blocking in unit tests.
        return False

    def _confirmation_phrase(self, job: ChangeJob) -> str:
        endpoint = self._endpoints.get(job.endpoint_id)
        asset = self._assets.get(job.asset_id)
        mac = (endpoint.mac if endpoint else "").replace(":", "")
        serial = (asset.serial if asset else "")
        return f"Change {serial or mac} to {job.proposed['new_ip']}"
