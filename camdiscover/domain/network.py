"""Generic network-mapping records.

These records deliberately do not imply trust or authorization.  They are
local, evidence-bearing observations; RegOS is the authority for governed
corporate projections.
"""
from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


def require_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("network timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


ASSET_TYPES = {"workstation", "server", "switch", "router", "firewall",
               "access_point", "printer", "iot", "camera", "nvr", "unknown"}
EVIDENCE_STATES = {"declared", "observed", "verified", "authorized"}


@dataclass
class NetworkAsset:
    asset_id: str
    site_id: str
    asset_type: str = "unknown"
    manufacturer: str = ""
    model: str = ""
    display_name: str = ""
    evidence_state: str = "observed"
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    freshness_seconds: Optional[int] = None
    ambiguity: list[str] = field(default_factory=list)

    def __post_init__(self):
        if self.asset_type not in ASSET_TYPES:
            raise ValueError(f"unsupported network asset type: {self.asset_type}")
        if self.evidence_state not in EVIDENCE_STATES:
            raise ValueError(f"unsupported network evidence state: {self.evidence_state}")
        if self.first_seen:
            self.first_seen = require_aware(self.first_seen)
        if self.last_seen:
            self.last_seen = require_aware(self.last_seen)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        for key in ("first_seen", "last_seen"):
            if result[key]:
                result[key] = result[key].isoformat()
        return result


@dataclass
class NetworkInterface:
    interface_id: str
    asset_id: str
    name: str = ""
    mac: str = ""
    source: str = ""
    observed_at: Optional[datetime] = None
    freshness_seconds: Optional[int] = None

    def __post_init__(self):
        if self.observed_at:
            self.observed_at = require_aware(self.observed_at)

    def to_dict(self):
        d = asdict(self)
        d["observed_at"] = self.observed_at.isoformat() if self.observed_at else None
        return d


@dataclass
class AddressObservation:
    observation_id: str
    asset_id: str
    interface_id: Optional[str]
    address: str
    address_family: str
    hostname: str = ""
    dhcp_name: str = ""
    dns_name: str = ""
    source: str = ""
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    freshness_seconds: Optional[int] = None

    def __post_init__(self):
        parsed = ipaddress.ip_address(self.address)
        if self.address_family not in {"ipv4", "ipv6"}:
            self.address_family = "ipv4" if parsed.version == 4 else "ipv6"
        if (self.address_family == "ipv4" and parsed.version != 4) or (self.address_family == "ipv6" and parsed.version != 6):
            raise ValueError("address family does not match address")
        if self.first_seen:
            self.first_seen = require_aware(self.first_seen)
        if self.last_seen:
            self.last_seen = require_aware(self.last_seen)

    def to_dict(self):
        d = asdict(self)
        for key in ("first_seen", "last_seen"):
            if d[key]:
                d[key] = d[key].isoformat()
        return d


@dataclass
class ServiceObservation:
    observation_id: str
    asset_id: str
    transport: str
    port: int
    service_family: str = "unknown"
    limited_fingerprint: str = ""
    source: str = ""
    observed_at: Optional[datetime] = None
    freshness_seconds: Optional[int] = None

    def __post_init__(self):
        if self.transport.lower() not in {"tcp", "udp"}:
            raise ValueError("transport must be tcp or udp")
        if not 1 <= int(self.port) <= 65535:
            raise ValueError("service port out of range")
        if self.observed_at:
            self.observed_at = require_aware(self.observed_at)

    def to_dict(self):
        d = asdict(self)
        d["observed_at"] = self.observed_at.isoformat() if self.observed_at else None
        return d


@dataclass
class NetworkScopeGrant:
    scope_id: str
    site_id: str
    cidrs: list[str]
    purpose: str
    actor: str
    expires_at: datetime
    authorization_state: str = "draft"
    authorization_reference: str = ""
    justification: str = ""

    def __post_init__(self):
        if not self.cidrs:
            raise ValueError("at least one approved CIDR is required")
        for cidr in self.cidrs:
            network = ipaddress.ip_network(cidr, strict=False)
            if network.prefixlen == 0:
                raise ValueError("default-route scopes are not allowed")
            if not (network.is_private or network.is_link_local):
                raise ValueError("corporate scopes must be private or link-local")
        self.expires_at = require_aware(self.expires_at)
        if self.authorization_state not in {"draft", "approved", "expired", "revoked"}:
            raise ValueError("invalid scope authorization state")

    def contains(self, address: str) -> bool:
        ip = ipaddress.ip_address(address)
        return any(ip in ipaddress.ip_network(c, strict=False) for c in self.cidrs)

    def to_dict(self):
        d = asdict(self)
        d["expires_at"] = self.expires_at.isoformat()
        return d


@dataclass
class NetworkObservationSession:
    session_id: str
    collector_id: str
    collector_type: str
    scope_id: str
    observation_methods: list[str]
    authorization_reference: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    coverage_state: str = "in_progress"
    failure_state: Optional[str] = None
    resume_cursor: Optional[str] = None

    def __post_init__(self):
        self.started_at = require_aware(self.started_at)
        if self.completed_at:
            self.completed_at = require_aware(self.completed_at)
        if self.coverage_state not in {"in_progress", "complete", "partial", "cancelled", "unavailable", "unsupported"}:
            raise ValueError("invalid coverage state")

    def to_dict(self):
        d = asdict(self)
        for key in ("started_at", "completed_at"):
            if d[key]:
                d[key] = d[key].isoformat()
        return d
