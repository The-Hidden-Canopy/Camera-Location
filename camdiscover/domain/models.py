"""Domain models for durable camera asset / endpoint / location records.

These classes are the persisted counterparts to the in-flight
DiscoveredDevice dataclass in camdiscover.models.  They separate:

  CameraAsset      — the durable thing (serial, MAC, model, QR/asset tag)
  DeviceEndpoint   — a network sighting of that thing (current IP, subnet, URLs)
  PhysicalLocation — where it physically belongs
  Site             — the scoped place of work
  NetworkProfile   — a VLAN/subnet/DHCP definition
  Observation      — one piece of evidence
  TopologyEdge     — camera <=> switch/radio/PoE/NVR relationship
  ChangeJob        — proposed / approved network change
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any


@dataclass
class Site:
    site_id: str
    name: str
    customer: str = ""
    address: str = ""
    local_coords: str = ""
    authorized_classes: List[str] = field(default_factory=list)
    expected_camera_count: int = 0
    expected_nvr_channels: int = 0
    expected_subnets: List[str] = field(default_factory=list)
    expected_gateways: List[str] = field(default_factory=list)
    known_old_subnets: List[str] = field(default_factory=list)
    unauthorized_device_alerts: bool = True
    notes: str = ""
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    def to_dict(self) -> dict:
        return {
            "site_id":    self.site_id,
            "name":       self.name,
            "customer":   self.customer,
            "address":    self.address,
            "local_coords": self.local_coords,
            "authorized_classes": self.authorized_classes,
            "expected_camera_count": self.expected_camera_count,
            "expected_nvr_channels": self.expected_nvr_channels,
            "expected_subnets": self.expected_subnets,
            "expected_gateways": self.expected_gateways,
            "known_old_subnets": self.known_old_subnets,
            "unauthorized_device_alerts": self.unauthorized_device_alerts,
            "notes":      self.notes,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


@dataclass
class NetworkProfile:
    profile_id: str
    site_id: str
    subnet: str
    label: str = ""
    gateway: str = ""
    vlan_id: int = 0
    dhcp_mode: str = "unknown"
    method: str = "auto"
    radio_zone: str = ""
    nvr_segment: int = 0
    internet_blocked: bool = True
    notes: str = ""
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    def to_dict(self) -> dict:
        return {
            "profile_id":      self.profile_id,
            "site_id":         self.site_id,
            "subnet":          self.subnet,
            "label":           self.label,
            "gateway":         self.gateway,
            "vlan_id":         self.vlan_id,
            "dhcp_mode":       self.dhcp_mode,
            "method":          self.method,
            "radio_zone":      self.radio_zone,
            "nvr_segment":     self.nvr_segment,
            "internet_blocked": self.internet_blocked,
            "notes":           self.notes,
            "created_at":      self.created_at.isoformat() if self.created_at else None,
            "updated_at":      self.updated_at.isoformat() if self.updated_at else None,
        }


@dataclass
class PhysicalLocation:
    location_id: str
    site_id: str
    label: str
    zone: str = ""
    map_x: Optional[float] = None
    map_y: Optional[float] = None
    map_source: str = ""
    direction: str = ""
    notes: str = ""
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    def to_dict(self) -> dict:
        return {
            "location_id": self.location_id,
            "site_id":     self.site_id,
            "label":       self.label,
            "zone":        self.zone,
            "map_x":       self.map_x,
            "map_y":       self.map_y,
            "map_source":  self.map_source,
            "direction":   self.direction,
            "notes":       self.notes,
            "created_at":  self.created_at.isoformat() if self.created_at else None,
            "updated_at":  self.updated_at.isoformat() if self.updated_at else None,
        }


@dataclass
class CameraAsset:
    asset_id: str
    site_id: Optional[str] = None
    asset_tag: str = ""
    qr_code: str = ""
    serial: str = ""
    manufacturer: str = ""
    model: str = ""
    hardware_id: str = ""
    onvif_uuid: str = ""
    asset_class: str = "unknown_endpoint"
    operational_role: str = "unknown"
    criticality: str = "normal"
    reset_risk: str = "moderate"
    human_confirmed: bool = False
    installed_status: str = "planned"
    expected_location_id: Optional[str] = None
    notes: str = ""
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    def to_dict(self) -> dict:
        return {
            "asset_id":         self.asset_id,
            "site_id":          self.site_id,
            "asset_tag":        self.asset_tag,
            "qr_code":          self.qr_code,
            "serial":           self.serial,
            "manufacturer":     self.manufacturer,
            "model":            self.model,
            "hardware_id":      self.hardware_id,
            "onvif_uuid":       self.onvif_uuid,
            "asset_class":      self.asset_class,
            "operational_role": self.operational_role,
            "criticality":      self.criticality,
            "reset_risk":       self.reset_risk,
            "human_confirmed":  self.human_confirmed,
            "installed_status": self.installed_status,
            "expected_location_id": self.expected_location_id,
            "notes":            self.notes,
            "created_at":       self.created_at.isoformat() if self.created_at else None,
            "updated_at":       self.updated_at.isoformat() if self.updated_at else None,
        }


@dataclass
class DeviceEndpoint:
    endpoint_id: str
    asset_id: Optional[str] = None
    ip: str = ""
    ip_history: List[str] = field(default_factory=list)
    mac: str = ""
    mac_history: List[str] = field(default_factory=list)
    onvif_uuid: str = ""
    rtsp_url: str = ""
    onvif_url: str = ""
    web_url: str = ""
    firmware: str = ""
    network_profile_id: Optional[str] = None
    subnet: str = ""
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    is_current: bool = True
    device_class: str = "unknown"

    def to_dict(self) -> dict:
        return {
            "endpoint_id":        self.endpoint_id,
            "asset_id":           self.asset_id,
            "ip":                 self.ip,
            "ip_history":         self.ip_history,
            "mac":                self.mac,
            "mac_history":        self.mac_history,
            "onvif_uuid":         self.onvif_uuid,
            "rtsp_url":           self.rtsp_url,
            "onvif_url":          self.onvif_url,
            "web_url":            self.web_url,
            "firmware":           self.firmware,
            "network_profile_id": self.network_profile_id,
            "subnet":             self.subnet,
            "first_seen":         self.first_seen.isoformat() if self.first_seen else None,
            "last_seen":          self.last_seen.isoformat() if self.last_seen else None,
            "is_current":         self.is_current,
            "device_class":       self.device_class,
        }


@dataclass
class Observation:
    observation_id: str
    kind: str
    observed_at: Optional[datetime] = None
    site_id: Optional[str] = None
    endpoint_id: Optional[str] = None
    asset_id: Optional[str] = None
    detail: str = ""
    source: str = ""
    sensor_id: str = ""
    interface: str = ""
    capture_position: str = ""
    visibility_limit: str = ""
    weight: int = 0
    raw: str = ""
    session_id: str = ""

    def to_dict(self) -> dict:
        return {
            "observation_id":   self.observation_id,
            "kind":             self.kind,
            "observed_at":      self.observed_at.isoformat() if self.observed_at else None,
            "site_id":          self.site_id,
            "endpoint_id":      self.endpoint_id,
            "asset_id":         self.asset_id,
            "detail":           self.detail,
            "source":           self.source,
            "sensor_id":        self.sensor_id,
            "interface":        self.interface,
            "capture_position": self.capture_position,
            "visibility_limit": self.visibility_limit,
            "weight":           self.weight,
            "raw":              self.raw,
            "session_id":       self.session_id,
        }


@dataclass
class TopologyEdge:
    edge_id: str
    site_id: Optional[str]
    from_id: str
    from_type: str
    to_id: str
    to_type: str
    relation: str
    detail: str = ""
    since: Optional[datetime] = None
    until: Optional[datetime] = None
    verified: bool = False

    def to_dict(self) -> dict:
        return {
            "edge_id":   self.edge_id,
            "site_id":   self.site_id,
            "from_id":   self.from_id,
            "from_type": self.from_type,
            "to_id":     self.to_id,
            "to_type":   self.to_type,
            "relation":  self.relation,
            "detail":    self.detail,
            "since":     self.since.isoformat() if self.since else None,
            "until":     self.until.isoformat() if self.until else None,
            "verified":  self.verified,
        }


@dataclass
class ChangeJob:
    job_id: str
    kind: str
    proposed: Dict[str, Any]
    site_id: Optional[str] = None
    endpoint_id: Optional[str] = None
    asset_id: Optional[str] = None
    prior: Dict[str, Any] = field(default_factory=dict)
    status: str = "draft"
    approval_phrase: str = ""
    created_at: Optional[datetime] = None
    approved_at: Optional[datetime] = None
    executed_at: Optional[datetime] = None
    verified_at: Optional[datetime] = None
    result: str = ""
    rollback_state: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "job_id":          self.job_id,
            "site_id":         self.site_id,
            "endpoint_id":     self.endpoint_id,
            "asset_id":        self.asset_id,
            "kind":            self.kind,
            "proposed":        self.proposed,
            "prior":           self.prior,
            "status":          self.status,
            "approval_phrase": self.approval_phrase,
            "created_at":      self.created_at.isoformat() if self.created_at else None,
            "approved_at":     self.approved_at.isoformat() if self.approved_at else None,
            "executed_at":     self.executed_at.isoformat() if self.executed_at else None,
            "verified_at":     self.verified_at.isoformat() if self.verified_at else None,
            "result":          self.result,
            "rollback_state":  self.rollback_state,
        }


@dataclass
class CredentialProfile:
    profile_id: str
    site_id: Optional[str] = None
    label: str = ""
    username: str = ""
    secret_ref: str = ""
    scope: List[str] = field(default_factory=list)
    vendor_hint: str = ""
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    def to_dict(self) -> dict:
        return {
            "profile_id":  self.profile_id,
            "site_id":     self.site_id,
            "label":       self.label,
            "username":    self.username,
            "secret_ref":  self.secret_ref,
            "scope":       self.scope,
            "vendor_hint": self.vendor_hint,
            "created_at":  self.created_at.isoformat() if self.created_at else None,
            "updated_at":  self.updated_at.isoformat() if self.updated_at else None,
        }
