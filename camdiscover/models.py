"""Discovered device data model + DPI evidence + subnet zone models"""

from __future__ import annotations
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional


# ─── Evidence ─────────────────────────────────────────────────────────────────
#
# Each signal captured — whether from a passive listener, active probe, or ARP
# table — becomes an Evidence object and is appended to the ledger permanently.
#
# The ledger is append-only: evidence is never deleted between scans.
# Each item carries full provenance so conclusions can be traced back to the
# exact sensor, interface position, and observation that produced them.
#
# Evidence is DEDUPED by kind: only the first occurrence per kind is retained.
# Repeated observations update last_seen on the existing item rather than
# inflating the score.

@dataclass
class Evidence:
    kind: str        # key into EVIDENCE_WEIGHTS (e.g. "onvif_probe_match_nvt")
    detail: str      # human-readable description of what was observed
    source: str      # "passive_wsdiscovery" | "active_onvif" | "arp" | "active_rtsp" …
    weight: int      # contribution to camera_confidence (can be negative)
    timestamp: datetime = field(default_factory=datetime.now)
    raw: str = ""    # raw snippet (first 500 chars of packet / response)

    # ── Provenance ──────────────────────────────────────────────────────
    # Every evidence item records exactly where it came from so the UI can
    # explain why a conclusion was reached and flag coverage gaps.
    sensor_id: str = ""          # which arm produced this: "dpi_onvif", "passive_sadp", "active_rtsp", …
    interface: str = ""          # NIC name (e.g. "Ethernet 3")
    capture_position: str = ""   # "wifi" | "ethernet_same" | "span_port" | "unknown" …
    visibility_limit: str = ""   # what this sensor position can/cannot see

    def to_dict(self) -> dict:
        return {
            "kind":             self.kind,
            "detail":           self.detail,
            "source":           self.source,
            "weight":           self.weight,
            "timestamp":        self.timestamp.isoformat(),
            "sensor_id":        self.sensor_id,
            "interface":        self.interface,
            "capture_position": self.capture_position,
            "visibility_limit": self.visibility_limit,
        }


# ─── DPI Protocol Stages ──────────────────────────────────────────────────────
#
# Kept for backward-compat display in the DPI stage dot-bar.
# These are now populated from Evidence rather than being the primary model.

DPI_STAGES = [
    "link",          # Layer-2 reachability (ARP/ping)
    "dhcp",          # DHCP assignment or static IP confirmed
    "discovery",     # ONVIF/SSDP/mDNS discovery response seen
    "auth",          # Authentication reachable (HTTP/HTTPS login page)
    "rtsp",          # RTSP session can be negotiated
    "onvif_ctrl",    # ONVIF control endpoint reachable
    "ntp",           # NTP time sync port reachable
    "dns",           # DNS resolution working
    "cloud",         # Cloud/P2P egress detected or absent
    "recording",     # Storage/export path reachable (NVR/SMB/FTP)
]

DPI_STAGE_LABELS = {
    "link":       "L2 Reachable",
    "dhcp":       "DHCP/IP Assign",
    "discovery":  "Discovery",
    "auth":       "Auth Reachable",
    "rtsp":       "RTSP Stream",
    "onvif_ctrl": "ONVIF Control",
    "ntp":        "NTP Sync",
    "dns":        "DNS",
    "cloud":      "Cloud Egress",
    "recording":  "Recording Path",
}


@dataclass
class DPIStageResult:
    stage: str
    status: str   # pass | fail | unchecked | na
    detail: str = ""
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        return {
            "stage": self.stage,
            "status": self.status,
            "detail": self.detail,
            "timestamp": self.timestamp.isoformat(),
        }


# ─── Subnet Zone ──────────────────────────────────────────────────────────────

@dataclass
class SubnetZone:
    subnet: str               # e.g. "192.168.1.0/24"
    label: str = ""
    gateway: str = ""
    vlan_id: int = 0
    method: str = "auto"      # auto | route | secondary_ip | vlan | direct_nic | manual
    discoverable: bool = True
    dhcp_mode: str = "unknown"
    nvr_access: bool = True
    internet_blocked: bool = True
    credential_profile: str = ""
    notes: str = ""
    added_ips: List[str] = field(default_factory=list)
    routes_added: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "subnet": self.subnet,
            "label": self.label,
            "gateway": self.gateway,
            "vlan_id": self.vlan_id,
            "method": self.method,
            "discoverable": self.discoverable,
            "dhcp_mode": self.dhcp_mode,
            "nvr_access": self.nvr_access,
            "internet_blocked": self.internet_blocked,
            "credential_profile": self.credential_profile,
            "notes": self.notes,
        }


# ─── Triage engine entities ───────────────────────────────────────────────────
#
# The scanner is a triage engine, not a fan-out scanner.  Passive listening
# runs continuously and feeds an evidence store; a SINGLE sequential probe
# worker drains four priority queues in strict order:
#
#   P1 known scope walk   →  P2 mismatch IPs  →  P3 candidate subnets  →  P4 orphans
#
# No thread-per-subnet, no /16 blast.  Candidate subnets are built ONLY from
# real evidence and must be validated (a few evidence IPs + suspected gateway)
# before they are promoted to a known scope and scanned sequentially.

@dataclass
class ScopeCursor:
    """A known network being walked one host at a time.  next_host lets the
    walk resume exactly where it left off instead of restarting."""
    cidr: str
    source: str = "interface"           # interface | manual | promoted
    next_host: int = 1                  # 1..254, the host octet to probe next
    completed: bool = False
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    def to_dict(self) -> dict:
        return {
            "cidr": self.cidr, "source": self.source,
            "next_host": self.next_host, "completed": self.completed,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


@dataclass
class MismatchEntry:
    """A device alive on the wire whose IP/subnet/gateway does not match the
    network it is physically on.  Verified ONE at a time, never by scanning
    the whole suspected subnet."""
    ip: str
    mac: str = ""
    suspected_gateway: str = ""
    suspected_cidr: str = ""
    reason: str = ""
    # observed|route_check|arp_check|sadp_check|rtsp_check|
    # alive_wrong_subnet|alive_unreachable_by_route|seen_only_passively|
    # same_mac_new_ip|dead_or_stale|needs_gateway_route|needs_ip_repair
    status: str = "observed"
    priority: int = 50                  # lower = more urgent
    attempts: int = 0
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    last_checked: Optional[datetime] = None

    def to_dict(self) -> dict:
        return {
            "ip": self.ip, "mac": self.mac,
            "suspected_gateway": self.suspected_gateway,
            "suspected_cidr": self.suspected_cidr,
            "reason": self.reason, "status": self.status,
            "priority": self.priority, "attempts": self.attempts,
            "last_checked": self.last_checked.isoformat() if self.last_checked else None,
        }


@dataclass
class CandidateSubnet:
    """A subnet INFERRED from evidence (observed talker, SADP report, ARP for
    a foreign gateway).  Never scanned wholesale until validated + promoted."""
    cidr: str
    source: str = ""                    # observed_ip | sadp | arp_gateway | dhcp
    confidence: int = 0                 # 0-100 (SADP mask = high, lone IP = low)
    # observed|inferred|validating|gateway_check|route_missing|
    # partially_validated|promoted|rejected|monitor_only
    status: str = "observed"
    observed_ips: List[str] = field(default_factory=list)
    suspected_gateway: str = ""
    attempts: int = 0
    promoted: bool = False
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        return {
            "cidr": self.cidr, "source": self.source,
            "confidence": self.confidence, "status": self.status,
            "observed_ips": self.observed_ips,
            "suspected_gateway": self.suspected_gateway,
            "attempts": self.attempts, "promoted": self.promoted,
        }


@dataclass
class OrphanEntry:
    """A device that is connected/visible but not normally reachable — wrong
    subnet, no gateway, DHCP failed, multicast-only, or seen only on a switch/
    NVR table.  Passive-first; active checks only if IP/MAC evidence exists."""
    ip: str = ""
    mac: str = ""
    hostname: str = ""
    vendor_guess: str = ""
    # passive_seen|switch_seen|dhcp_seen|nvr_seen|random_packets|
    # silent_connected|wrong_subnet|unreachable|needs_manual_check|resolved
    status: str = "passive_seen"
    reason: str = ""
    camera_confidence: int = 0
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    last_checked: Optional[datetime] = None

    def to_dict(self) -> dict:
        return {
            "ip": self.ip, "mac": self.mac, "hostname": self.hostname,
            "vendor_guess": self.vendor_guess, "status": self.status,
            "reason": self.reason, "camera_confidence": self.camera_confidence,
            "last_checked": self.last_checked.isoformat() if self.last_checked else None,
        }


# ─── Camera Validation Queue entry (P5) ──────────────────────────────────────
#
# Devices promoted here when: alive + camera-candidate ports/evidence, or
# listed on an NVR/switch but not yet deep-validated.  The P5 worker runs
# only when P1-P4 are all idle so it never pre-empts higher-priority probing.

@dataclass
class CameraValidationEntry:
    ip: str
    reason: str = ""          # why it was promoted to P5
    priority: int = 50        # lower = more urgent; seed hosts get 20
    attempts: int = 0
    # pending | validating | pass | fail | skip
    status: str = "pending"
    # Arm 7 stage results (filled by _tick_camera_validation)
    onvif_ok:   bool = False
    rtsp_ok:    bool = False
    http_ok:    bool = False
    nvr_match:  bool = False
    stream_ok:  bool = False
    first_queued: datetime = field(default_factory=datetime.now)
    last_checked: Optional[datetime] = None

    def to_dict(self) -> dict:
        return {
            "ip":           self.ip,
            "reason":       self.reason,
            "priority":     self.priority,
            "attempts":     self.attempts,
            "status":       self.status,
            "onvif_ok":     self.onvif_ok,
            "rtsp_ok":      self.rtsp_ok,
            "http_ok":      self.http_ok,
            "nvr_match":    self.nvr_match,
            "stream_ok":    self.stream_ok,
            "first_queued": self.first_queued.isoformat(),
            "last_checked": self.last_checked.isoformat() if self.last_checked else None,
        }


# ─── Capture Position ─────────────────────────────────────────────────────────

CAPTURE_POSITIONS = {
    "wifi":           "Wi-Fi adapter (limited — broadcast/multicast only)",
    "ethernet_same":  "Ethernet same VLAN (unicast + broadcast)",
    "span_port":      "Switch SPAN/mirror port (full visibility)",
    "inline_tap":     "Inline tap between switch and NVR",
    "nvr_capture":    "Capture on NVR interface",
    "unknown":        "Unknown capture position",
}

SENSOR_QUALITY: dict = {
    "wifi":          {"label": "Limited",  "colour": "warn",  "note": "Wi-Fi — wired camera unicast traffic may not be visible."},
    "ethernet_same": {"label": "Good",     "colour": "ok",    "note": "Ethernet same VLAN — unicast + broadcast visible."},
    "span_port":     {"label": "Full",     "colour": "ok",    "note": "Switch mirror — full wire visibility."},
    "inline_tap":    {"label": "Full",     "colour": "ok",    "note": "Inline tap — full wire visibility."},
    "nvr_capture":   {"label": "Partial",  "colour": "warn",  "note": "Capture on NVR side — camera→NVR traffic only."},
    "unknown":       {"label": "Unknown",  "colour": "warn",  "note": "Sensor position unknown — results may be incomplete."},
}


# ─── Multicast group ──────────────────────────────────────────────────────────

@dataclass
class MulticastGroup:
    """A multicast group observed on the wire — tracked but never scanned."""
    group: str                          # e.g. "234.5.6.7"
    sources: List[str] = field(default_factory=list)   # sender IPs seen
    listeners: List[str] = field(default_factory=list) # recipient IPs (IGMP)
    related_ips: List[str] = field(default_factory=list)
    protocol_hint: str = ""             # e.g. "camera_stream" | "ssdp" | "mdns"
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    packet_count: int = 0

    def to_dict(self) -> dict:
        return {
            "group":        self.group,
            "sources":      self.sources,
            "listeners":    self.listeners,
            "related_ips":  self.related_ips,
            "protocol_hint":self.protocol_hint,
            "first_seen":   self.first_seen.isoformat(),
            "last_seen":    self.last_seen.isoformat(),
            "packet_count": self.packet_count,
        }


# ─── Gateway mismatch ─────────────────────────────────────────────────────────

@dataclass
class GatewayMismatch:
    """
    A device whose traffic suggests it is configured for a gateway / subnet
    that does not match its current network placement.

    Example: device at 192.168.1.199 sending ARP for 192.168.88.1 — its
    static config still points at the old segment.
    """
    ip: str
    # Gateway the device is TRYING to reach (observed in ARP/traffic)
    observed_target_gateway: str = ""
    # What we believe the correct gateway should be
    current_gateway: str = ""
    # The subnet implied by the device's apparent old config
    suspected_old_subnet: str = ""
    reason: str = ""
    evidence_type: str = ""     # arp_for_gateway | dhcp_relay | sadp | prior_session | manual
    next_action: str = ""
    status: str = "observed"    # observed | checking | confirmed | resolved
    priority: int = 30
    attempts: int = 0
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    last_checked: Optional[datetime] = None

    def to_dict(self) -> dict:
        return {
            "ip":                    self.ip,
            "observed_target_gateway": self.observed_target_gateway,
            "current_gateway":       self.current_gateway,
            "suspected_old_subnet":  self.suspected_old_subnet,
            "reason":                self.reason,
            "evidence_type":         self.evidence_type,
            "next_action":           self.next_action,
            "status":                self.status,
            "priority":              self.priority,
            "attempts":              self.attempts,
            "first_seen":            self.first_seen.isoformat(),
            "last_seen":             self.last_seen.isoformat(),
            "last_checked":          self.last_checked.isoformat() if self.last_checked else None,
        }


@dataclass
class CapturePosition:
    position: str = "unknown"
    can_see_unicast: bool = False
    can_see_broadcast: bool = True
    can_see_multicast: bool = True
    can_see_rtsp: bool = False
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "position": self.position,
            "label": CAPTURE_POSITIONS.get(self.position, self.position),
            "can_see_unicast": self.can_see_unicast,
            "can_see_broadcast": self.can_see_broadcast,
            "can_see_multicast": self.can_see_multicast,
            "can_see_rtsp": self.can_see_rtsp,
            "notes": self.notes,
        }


# ─── Discovered Device ────────────────────────────────────────────────────────

@dataclass
class DiscoveredDevice:
    # ── Primary identity ────────────────────────────────────────────────
    # device_id is the stable internal key.  IP is a current observation,
    # not a permanent identity — devices move, DHCP reassigns, APIPA
    # addresses appear before recovery.  Never use IP as a join key across
    # scan sessions; use device_id, mac, onvif_uuid, or serial instead.
    device_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    asset_id: str = ""
    endpoint_id: str = ""
    ip: str = ""
    ip_history: List[str] = field(default_factory=list)   # all IPs ever seen for this device

    mac: str = ""
    mac_history: List[str] = field(default_factory=list)  # in case MAC changes (spoofing / NIC swap)
    serial: str = ""        # from ONVIF GetDeviceInformation or SADP
    onvif_uuid: str = ""    # from WS-Discovery MessageID or ONVIF endpoint UUID

    vendor: str = "Unknown"
    hostname: str = ""
    model: str = ""
    firmware: str = ""

    open_ports: List[int] = field(default_factory=list)
    protocols: List[str] = field(default_factory=list)
    onvif_status: str = "not-checked"   # found | error | not-checked
    rtsp_status:  str = "not-checked"
    web_url:    str = ""
    rtsp_url:   str = ""
    onvif_url:  str = ""
    subnet:     str = ""
    confidence: int = 0                  # legacy fingerprint score (keep for compat)
    discovery_methods: List[str] = field(default_factory=list)
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    raw_responses: Dict[str, str] = field(default_factory=dict)

    # ── Append-only evidence ledger ─────────────────────────────────────
    # All signals (passive + active) collected as Evidence objects with
    # full provenance.  The ledger survives mode switches and scan restarts
    # — only an explicit operator Clear wipes it.
    # Deduped by kind: only the first occurrence of each kind is recorded;
    # subsequent observations of the same kind update last_seen.
    evidence: List[Evidence] = field(default_factory=list)

    # Subnet mismatch: non-empty string = problem description
    subnet_mismatch: str = ""

    # Legacy DPI stage results (kept for the dot-bar display)
    dpi_stages: Dict[str, DPIStageResult] = field(default_factory=dict)
    subnet_zone: str = ""

    # ── Classification ──────────────────────────────────────────────────
    # camera | nvr | server | bridge | router | switch | printer | unknown
    device_class: str = "unknown"

    # True → show "do not reset" warning (bridges, routers, NVRs)
    warn_reset: bool = False

    # reset_risk: none | low | moderate | high | critical
    # Set by the classifier; unknown infrastructure defaults to "high"
    # until a safe role is confirmed.
    reset_risk: str = "unknown"

    # If the device appears to be targeting a gateway from a different
    # subnet (old static config), record that here.
    suspected_old_gateway: str = ""

    # Physical/PoE state from switch/NVR data
    poe_state: str = ""

    # Human note from manual entry
    notes: str = ""

    # APIPA flag — set True if this device was seen with a 169.254.x.x address
    apipa_seen: bool = False

    # Staged camera validation (beyond basic port scan)
    # Each key maps to "pass" | "fail" | "unknown"
    validation: Dict[str, str] = field(default_factory=dict)

    # Human-readable explanation of why this classification was chosen
    classification_rationale: str = ""

    def __post_init__(self):
        # Per-device lock so concurrent fingerprint threads don't corrupt evidence list
        object.__setattr__(self, '_evidence_lock', threading.Lock())
        # Record the initial IP in history if present
        if self.ip and self.ip not in self.ip_history:
            self.ip_history.append(self.ip)

    def record_ip(self, ip: str):
        """Record a new current IP, preserving history."""
        if not ip:
            return
        self.ip = ip
        if ip not in self.ip_history:
            self.ip_history.append(ip)

    # ── Multi-dimensional confidence lanes ──────────────────────────────
    # Each lane is computed from a specific subset of evidence kinds so
    # contradictory signals are preserved as tension rather than collapsed
    # into a single number.

    _PRESENCE_KINDS = frozenset({
        "arp_seen", "router_arp_seen", "switch_mac_seen", "dhcp_lease_seen",
        "dhcp_request", "dhcp_hostname_camera", "lldp_neighbor",
        "ping_responded", "tcp_port_open",
    })
    _CAMERA_ROLE_KINDS = frozenset({
        "onvif_probe_match_nvt", "onvif_probe_match_generic",
        "onvif_device_service_url", "onvif_device_info", "onvif_port_responding",
        "sadp_response", "dahua_udp_response",
        "rtsp_describe_response", "rtsp_setup_play", "rtsp_port_open",
        "http_camera_banner", "mac_oui_camera",
        "nvr_channel_match", "nvr_channel_listed",
        "igmp_multicast_stream", "rtp_flow", "rtp_media_flow",
        "ssdp_camera_service", "mdns_camera_service",
        "fingerprint_match",
    })
    _INFRA_ROLE_KINDS = frozenset({
        "snmp_infra_hint", "wsd_non_camera", "windows_wsd_host",
        "lldp_neighbor",
    })
    _REACHABILITY_KINDS = frozenset({
        "ping_responded", "tcp_port_open", "rtsp_port_open",
        "onvif_port_responding", "http_camera_banner",
    })
    _STREAM_KINDS = frozenset({
        "rtsp_describe_response", "rtsp_setup_play", "rtp_flow",
        "rtp_media_flow", "igmp_multicast_stream",
    })
    _MISMATCH_KINDS = frozenset({
        "subnet_mismatch_visible", "gateway_mismatch",
    })

    @property
    def physical_presence_confidence(self) -> int:
        """How certain are we this device is physically connected right now?"""
        total = sum(e.weight for e in self.evidence
                    if e.kind in self._PRESENCE_KINDS and e.weight > 0)
        # Ping and active TCP checks are strong presence signals
        if any(e.kind == "ping_responded" for e in self.evidence):
            total = max(total, 60)
        return min(100, total)

    @property
    def camera_role_confidence(self) -> int:
        """How strong is the evidence this device is a camera or NVR?"""
        if not self.evidence:
            return self.confidence
        total = sum(e.weight for e in self.evidence
                    if e.kind in self._CAMERA_ROLE_KINDS)
        return max(0, min(100, total))

    @property
    def infrastructure_role_confidence(self) -> int:
        """How strong is the evidence this device is network infrastructure?"""
        total = sum(abs(e.weight) for e in self.evidence
                    if e.kind in self._INFRA_ROLE_KINDS and e.weight < 0)
        if self.device_class in ("bridge", "router", "switch"):
            total = max(total, 70)
        return min(100, total)

    @property
    def route_reachability_confidence(self) -> int:
        """Can we actively reach this device from our current position?"""
        if any(e.kind == "ping_responded" for e in self.evidence):
            return 90
        total = sum(e.weight for e in self.evidence
                    if e.kind in self._REACHABILITY_KINDS and e.weight > 0)
        return min(100, total)

    @property
    def stream_validation_confidence(self) -> int:
        """Have we confirmed an actual media stream from this device?"""
        total = sum(e.weight for e in self.evidence
                    if e.kind in self._STREAM_KINDS and e.weight > 0)
        return min(100, total)

    @property
    def configuration_mismatch_confidence(self) -> int:
        """How strong is the evidence this device is misconfigured?"""
        total = sum(abs(e.weight) for e in self.evidence
                    if e.kind in self._MISMATCH_KINDS)
        if self.subnet_mismatch:
            total = max(total, 50)
        if self.suspected_old_gateway:
            total = max(total, 40)
        return min(100, total)

    @property
    def camera_confidence(self) -> int:
        """Primary camera score — alias of camera_role_confidence.
        Falls back to legacy fingerprint score when no evidence yet."""
        return self.camera_role_confidence if self.evidence else self.confidence

    @property
    def effective_reset_risk(self) -> str:
        """Derive reset risk from classification if not explicitly set."""
        if self.reset_risk not in ("unknown", ""):
            return self.reset_risk
        if self.device_class in ("bridge", "router", "switch", "nvr", "server"):
            return "high"
        if self.warn_reset:
            return "high"
        if self.camera_role_confidence >= 70:
            return "moderate"
        return "low"

    @property
    def device_type(self) -> str:
        return self.device_class or "unknown"

    @property
    def device_type_confidence(self) -> int:
        if self.device_type == "camera":
            return self.camera_confidence
        if self.device_type == "unknown":
            return 15
        if self.warn_reset:
            return 80
        if self.vendor and self.vendor != "Unknown":
            return 55
        return 35

    def add_evidence(self, ev: Evidence) -> bool:
        """Append to the evidence ledger. Returns True if the kind was new.
        Duplicate kinds are not re-added — the ledger is append-only per kind.
        Thread-safe: protected by the per-device lock."""
        lock = getattr(self, '_evidence_lock', None)
        if lock:
            with lock:
                if any(e.kind == ev.kind for e in self.evidence):
                    return False
                self.evidence.append(ev)
                return True
        if any(e.kind == ev.kind for e in self.evidence):
            return False
        self.evidence.append(ev)
        return True

    @property
    def dpi_score(self) -> int:
        """Legacy: 0-100 based on how many stage-results pass."""
        if not self.dpi_stages:
            return 0
        applicable = {k: v for k, v in self.dpi_stages.items() if v.status != "na"}
        if not applicable:
            return 0
        passed = sum(1 for v in applicable.values() if v.status == "pass")
        return round((passed / len(applicable)) * 100)

    @property
    def dpi_summary(self) -> str:
        if not self.dpi_stages:
            return "No DPI validation performed"
        parts = []
        for stage in DPI_STAGES:
            result = self.dpi_stages.get(stage)
            if result and result.status != "na":
                icon = "+" if result.status == "pass" else ("-" if result.status == "fail" else "?")
                parts.append(f"{icon}{stage}")
        return " ".join(parts) if parts else "No DPI stages checked"

    def to_dict(self) -> dict:
        return {
            # ── Identity ──────────────────────────────────────────────
            "device_id":         self.device_id,
            "asset_id":          self.asset_id,
            "endpoint_id":       self.endpoint_id,
            "ip":                self.ip,
            "ip_history":        self.ip_history,
            "mac":               self.mac,
            "mac_history":       self.mac_history,
            "serial":            self.serial,
            "onvif_uuid":        self.onvif_uuid,
            # ── Descriptive ───────────────────────────────────────────
            "vendor":            self.vendor,
            "hostname":          self.hostname,
            "model":             self.model,
            "firmware":          self.firmware,
            "open_ports":        self.open_ports,
            "protocols":         self.protocols,
            "onvif_status":      self.onvif_status,
            "rtsp_status":       self.rtsp_status,
            "web_url":           self.web_url,
            "rtsp_url":          self.rtsp_url,
            "onvif_url":         self.onvif_url,
            "subnet":            self.subnet,
            "discovery_methods": self.discovery_methods,
            "first_seen":        self.first_seen.isoformat(),
            "last_seen":         self.last_seen.isoformat(),
            # ── Multi-dimensional confidence ──────────────────────────
            "confidence":                    self.camera_confidence,   # primary (backward compat)
            "camera_role_confidence":        self.camera_role_confidence,
            "physical_presence_confidence":  self.physical_presence_confidence,
            "infrastructure_role_confidence":self.infrastructure_role_confidence,
            "route_reachability_confidence": self.route_reachability_confidence,
            "stream_validation_confidence":  self.stream_validation_confidence,
            "configuration_mismatch_confidence": self.configuration_mismatch_confidence,
            "fingerprint_score":             self.confidence,          # legacy heuristic
            # ── Evidence ledger ───────────────────────────────────────
            "evidence":          [e.to_dict() for e in self.evidence],
            # ── Classification ────────────────────────────────────────
            "device_class":      self.device_class,
            "device_type":       self.device_type,
            "device_type_confidence": self.device_type_confidence,
            "warn_reset":        self.warn_reset,
            "reset_risk":        self.effective_reset_risk,
            "suspected_old_gateway": self.suspected_old_gateway,
            "poe_state":         self.poe_state,
            "notes":             self.notes,
            "apipa_seen":        self.apipa_seen,
            "validation":        self.validation,
            "classification_rationale": self.classification_rationale,
            # ── DPI ───────────────────────────────────────────────────
            "subnet_mismatch":   self.subnet_mismatch,
            "dpi_stages":        {k: v.to_dict() for k, v in self.dpi_stages.items()},
            "dpi_score":         self.dpi_score,
            "dpi_summary":       self.dpi_summary,
            "subnet_zone":       self.subnet_zone,
        }
