"""Passive-first, bounded local network mapping service."""
from __future__ import annotations
import ipaddress
import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from typing import Optional
from ..contracts.network_packets import NetworkPacket, OBSERVATION_KINDS, PACKET_TYPES
from ..domain.events import DomainEvent, append_domain_event
from ..domain.network import NetworkAsset, NetworkScopeGrant, NetworkObservationSession, ASSET_TYPES
from ..persistence.db import Database, new_uuid
from ..persistence.network_repos import NetworkPacketQueueRepo, NetworkScopeRepo, NetworkSessionRepo

DEFAULT_ALLOWLISTED_PORTS = (22, 53, 80, 443, 445, 631, 9100, 3389, 554, 8000, 8080)
IMPORT_KINDS = {"dhcp", "dns", "route", "lldp", "cdp", "switch_mac_port", "wireless_controller", "nvr_controller"}
IMPORT_RELATIONS = {
    "lldp": ("connected_to", "asset"),
    "cdp": ("connected_to", "asset"),
    "switch_mac_port": ("attached_to_port", "switch_port"),
    "wireless_controller": ("wireless_associated_with", "asset"),
    "route": ("routes_through", "gateway"),
    "nvr_controller": ("nvr_channel", "asset"),
}
FORBIDDEN_IMPORT_KEYS = {"password", "secret", "credential", "token", "community", "private_key", "passphrase"}
TOPOLOGY_NODE_TYPES = {"asset", "interface", "address", "service", "segment", "switch_port", "wireless_association", "gateway", "route_boundary"}
TOPOLOGY_RELATIONS = {"connected_to", "attached_to_port", "uplink_to", "member_of_segment", "routes_through", "wireless_associated_with", "hosts_service", "powered_by", "observed_near"}
ALLOWED_FRESHNESS = {"declared", "observed", "verified", "stale", "partial", "unavailable"}


def _flag_enabled(name: str) -> bool:
    return os.environ.get(name, "0").strip().lower() in {"1", "true", "yes"}


def _secret_from_ref(ref_name: str) -> Optional[bytes]:
    ref = os.environ.get(ref_name, "").strip()
    if not ref:
        return None
    try:
        from ..persistence.secrets import retrieve
        value = retrieve(ref)
    except Exception:
        value = None
    return value.encode("utf-8") if value else None


def configured_collector_signing_key() -> Optional[bytes]:
    """Resolve the local collector credential without putting it in SQLite."""
    return _secret_from_ref("CAM_NETWORK_COLLECTOR_SECRET_REF") or (
        os.environ["CAM_NETWORK_PACKET_SIGNING_KEY"].encode("utf-8")
        if os.environ.get("CAM_NETWORK_PACKET_SIGNING_KEY") else None
    )


def configured_regos_signing_key() -> Optional[bytes]:
    """Resolve the separate RegOS-to-local projection verification key."""
    explicit_key = _secret_from_ref("CAM_NETWORK_REGOS_SIGNING_KEY_REF") or (
        os.environ["CAM_NETWORK_REGOS_SIGNING_KEY"].encode("utf-8")
        if os.environ.get("CAM_NETWORK_REGOS_SIGNING_KEY")
        else None
    )
    if explicit_key:
        return explicit_key
    # Corporate mode has two product boundaries: the local collector signs
    # outbound observations, while RegOS signs inbound expectations. Reusing
    # the collector key here would let a collector credential impersonate a
    # RegOS projection, so fail closed unless a distinct key is configured.
    if _flag_enabled("CORPORATE_COLLECTOR_MODE"):
        return None
    # Standalone/local compatibility may continue to use the legacy single
    # key until a separate RegOS projection credential is configured.
    return configured_collector_signing_key()


def _validate_topology_node_scope(grant, node_id, node_type):
    """Reject address-like topology identifiers outside the approved CIDRs."""
    if node_type == "address":
        try:
            address = ipaddress.ip_address(str(node_id))
        except ValueError as exc:
            raise ValueError("address topology identifiers must be IP addresses") from exc
        if not grant.contains(str(address)):
            raise ValueError("topology node is outside the approved scope")
    elif node_type == "gateway":
        # A gateway may be represented by an IP or by an infrastructure
        # identifier.  Enforce the CIDR boundary when it is an IP, while
        # preserving opaque identifiers for imported controller evidence.
        try:
            address = ipaddress.ip_address(str(node_id))
        except ValueError:
            return
        if not grant.contains(str(address)):
            raise ValueError("topology node is outside the approved scope")
    elif node_type in {"segment", "route_boundary"}:
        try:
            network = ipaddress.ip_network(str(node_id), strict=False)
        except ValueError:
            return
        if not any(network.subnet_of(ipaddress.ip_network(cidr, strict=False)) for cidr in grant.cidrs):
            raise ValueError("topology segment is outside the approved scope")


def _topology_node_from_other_site(db, site_id, node_id, node_type):
    """Return a known node from another site, if one exists."""
    if node_type == "asset":
        return db.conn.execute(
            "SELECT site_id FROM network_assets WHERE asset_id=? AND site_id!=? "
            "UNION ALL "
            "SELECT site_id FROM camera_assets WHERE asset_id=? AND site_id!=? LIMIT 1",
            (str(node_id), site_id, str(node_id), site_id),
        ).fetchone()
    if node_type == "interface":
        return db.conn.execute(
            "SELECT a.site_id FROM network_interfaces i "
            "JOIN network_assets a ON a.asset_id=i.asset_id "
            "WHERE i.interface_id=? AND a.site_id!=? LIMIT 1",
            (str(node_id), site_id),
        ).fetchone()
    if node_type == "address":
        current = db.conn.execute(
            "SELECT a.site_id FROM network_addresses n "
            "JOIN network_assets a ON a.asset_id=n.asset_id "
            "WHERE n.address=? AND a.site_id!=? LIMIT 1",
            (str(node_id), site_id),
        ).fetchone()
        if current:
            return current
        current = db.conn.execute(
            "SELECT a.site_id FROM device_endpoints e "
            "JOIN camera_assets a ON a.asset_id=e.asset_id "
            "WHERE e.ip=? AND a.site_id!=? LIMIT 1",
            (str(node_id), site_id),
        ).fetchone()
        if current:
            return current
        for row in db.conn.execute(
            "SELECT a.site_id,e.ip_history FROM device_endpoints e "
            "JOIN camera_assets a ON a.asset_id=e.asset_id "
            "WHERE a.site_id!=?",
            (site_id,),
        ):
            try:
                history = json.loads(row["ip_history"] or "[]")
            except (TypeError, ValueError, json.JSONDecodeError):
                history = []
            if isinstance(history, list) and str(node_id) in {str(value) for value in history}:
                return row
    return None


def _contains_forbidden_key(value) -> bool:
    if isinstance(value, dict):
        if any(token in str(key).lower() for key in value for token in FORBIDDEN_IMPORT_KEYS):
            return True
        return any(_contains_forbidden_key(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_forbidden_key(item) for item in value)
    return False


class NetworkMappingService:
    def __init__(self, db: Database, *, now: Optional[datetime] = None):
        self.db = db
        self.now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)

    def create_scope(self, *, site_id, cidrs, purpose, actor, expires_at, authorization_reference, justification):
        if not isinstance(justification, str) or not justification.strip(): raise ValueError("scope justification is required")
        if not isinstance(purpose, str) or not purpose.strip(): raise ValueError("scope purpose is required")
        if not isinstance(cidrs, list) or not cidrs: raise ValueError("at least one approved CIDR is required")
        if not isinstance(expires_at, datetime): raise ValueError("scope expiration is required")
        if not self.db.execute("SELECT 1 FROM sites WHERE site_id=?", (site_id,)).fetchone(): raise ValueError("site not found")
        grant = NetworkScopeGrant(new_uuid(), site_id, list(cidrs), purpose, actor, expires_at, "draft", authorization_reference, justification)
        with self.db.conn:
            NetworkScopeRepo(self.db).save(grant, commit=False)
            append_domain_event(self.db, DomainEvent("network_scope", grant.scope_id, "network_scope.created", actor, justification, site_id=site_id, from_state="new", to_state="draft", payload=grant.to_dict()), commit=False)
        return grant

    def approve_scope(self, scope_id, *, actor, justification, site_id=None):
        if not isinstance(justification, str) or not justification.strip(): raise ValueError("scope approval justification is required")
        repo = NetworkScopeRepo(self.db); grant = repo.get(scope_id)
        if not grant: raise KeyError(scope_id)
        if site_id is not None and grant.site_id != site_id: raise ValueError("scope does not belong to site")
        if grant.authorization_state != "draft": raise ValueError("only draft scopes can be approved")
        if grant.expires_at <= self.now: raise ValueError("scope grant is expired")
        grant.authorization_state = "approved"; grant.actor = actor; grant.justification = justification
        with self.db.conn:
            repo.save(grant, commit=False)
            append_domain_event(self.db, DomainEvent("network_scope", scope_id, "network_scope.approved", actor, justification, site_id=grant.site_id, from_state="draft", to_state="approved", payload=grant.to_dict()), commit=False)
        return grant

    def _approved_scope(self, scope_id):
        grant = NetworkScopeRepo(self.db).get(scope_id)
        if not grant: raise ValueError("scope grant not found")
        if grant.authorization_state != "approved": raise ValueError("scope grant is not approved")
        if grant.expires_at <= self.now: raise ValueError("scope grant is expired")
        return grant

    def start_session(self, *, scope_id, collector_id, collector_type="electron", methods=None, authorization_reference="", resume_cursor=None):
        grant = self._approved_scope(scope_id)
        if not isinstance(collector_id, str) or not collector_id.strip():
            raise ValueError("collector_id is required")
        if not isinstance(collector_type, str) or not collector_type.strip():
            raise ValueError("collector_type is required")
        if methods is not None and (not isinstance(methods, list) or not methods or any(not isinstance(method, str) or not method.strip() for method in methods)):
            raise ValueError("observation methods must be a non-empty array of strings")
        if resume_cursor is not None and (not isinstance(resume_cursor, str) or not resume_cursor.strip()):
            raise ValueError("resume_cursor must be a non-empty string when supplied")
        active = self.db.execute(
            "SELECT session_id FROM network_observation_sessions "
            "WHERE scope_id=? AND completed_at IS NULL AND coverage_state='in_progress' LIMIT 1",
            (scope_id,),
        ).fetchone()
        if active:
            raise ValueError("scope already has an active observation session")
        session = NetworkObservationSession(new_uuid(), collector_id, collector_type, scope_id, methods or ["passive_arp"], authorization_reference or grant.authorization_reference, self.now)
        session.resume_cursor = resume_cursor
        with self.db.conn:
            NetworkSessionRepo(self.db).save(session, commit=False)
            append_domain_event(self.db, DomainEvent("network_session", session.session_id, "network_session.started", collector_id, "approved network scope", site_id=grant.site_id, payload=session.to_dict()), commit=False)
        return session

    def validate_observation_target(self, *, scope_id, site_id, address):
        """Validate a target before any active probe is attempted."""
        grant = self._approved_scope(scope_id)
        if grant.site_id != site_id:
            raise ValueError("observation site does not match approved scope")
        try:
            allowed = grant.contains(address)
        except ValueError as exc:
            raise ValueError("observation address is invalid") from exc
        if not allowed:
            raise ValueError("observation is outside the approved scope")
        return True

    def finish_session(self, session_id, *, coverage_state, failure_state=None, resume_cursor=None, justification="collector finished"):
        row = self.db.execute("SELECT * FROM network_observation_sessions WHERE session_id=?", (session_id,)).fetchone()
        if not row: raise KeyError(session_id)
        if row["completed_at"] is not None or row["coverage_state"] != "in_progress":
            raise ValueError("observation session is already finished")
        if coverage_state not in {"complete", "partial", "cancelled", "unavailable", "unsupported"}: raise ValueError("invalid final coverage state")
        session = NetworkObservationSession(row["session_id"], row["collector_id"], row["collector_type"], row["scope_id"], json.loads(row["observation_methods"]), row["authorization_reference"], datetime.fromisoformat(row["started_at"]), self.now, coverage_state, failure_state, resume_cursor)
        with self.db.conn:
            NetworkSessionRepo(self.db).save(session, commit=False)
            append_domain_event(self.db, DomainEvent("network_session", session_id, "network_session.finished", session.collector_id, justification, payload=session.to_dict()), commit=False)
        return session

    def record_observation(self, *, scope_id, asset_id, site_id, ip, mac="", asset_type="unknown", hostname="", open_ports=(), source="passive", collector_id="local", reachability=None):
        grant = self._approved_scope(scope_id)
        if grant.site_id != site_id or not grant.contains(ip): raise ValueError("observation is outside the approved scope")
        if not isinstance(asset_id, str) or not asset_id.strip():
            raise ValueError("observation asset_id is required")
        if not isinstance(open_ports, (list, tuple, set)):
            raise ValueError("open_ports must be an array")
        if not isinstance(source, str) or not source.strip():
            raise ValueError("observation source is required")
        if not isinstance(collector_id, str) or not collector_id.strip():
            raise ValueError("collector_id is required")
        if reachability not in {None, "icmp_reachable", "icmp_unreachable", "not_attempted"}:
            raise ValueError("unsupported reachability state")
        normalized_mac = str(mac or "").strip().lower()[:32]
        normalized_ip = str(ipaddress.ip_address(ip))
        normalized_ports = []
        for raw_port in open_ports:
            try:
                port = int(raw_port)
            except (TypeError, ValueError) as exc:
                raise ValueError("observation port is invalid") from exc
            if port not in DEFAULT_ALLOWLISTED_PORTS:
                raise ValueError(f"port {port} is not allowlisted")
            normalized_ports.append(port)
        existing_asset = self.db.execute("SELECT site_id FROM network_assets WHERE asset_id=?", (asset_id,)).fetchone()
        if not existing_asset:
            existing_asset = self.db.execute("SELECT site_id FROM camera_assets WHERE asset_id=?", (asset_id,)).fetchone()
        if existing_asset and existing_asset["site_id"] != site_id:
            raise ValueError("observation asset identity crosses site scope")
        parsed = ipaddress.ip_address(normalized_ip)
        if asset_type not in {"workstation", "server", "switch", "router", "firewall", "access_point", "printer", "iot", "camera", "nvr", "unknown"}: asset_type = "unknown"
        now = self.now.isoformat()
        asset = NetworkAsset(asset_id, site_id, asset_type, display_name=hostname, first_seen=self.now, last_seen=self.now)
        with self.db.conn:
            self.db.conn.execute("""INSERT INTO network_assets(asset_id,site_id,asset_type,manufacturer,model,display_name,evidence_state,ambiguity,first_seen,last_seen,freshness_seconds) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(asset_id) DO UPDATE SET last_seen=excluded.last_seen,display_name=CASE WHEN excluded.display_name!='' THEN excluded.display_name ELSE network_assets.display_name END,asset_type=CASE WHEN excluded.asset_type!='unknown' THEN excluded.asset_type ELSE network_assets.asset_type END""", (asset.asset_id, asset.site_id, asset.asset_type, asset.manufacturer, asset.model, asset.display_name, asset.evidence_state, "[]", now, now, 0))
            compact_mac = normalized_mac.replace(":", "").replace("-", "").replace(".", "")
            interface_id = f"{asset_id}:mac:{compact_mac}" if compact_mac else f"{asset_id}:primary"
            self.db.conn.execute("""INSERT INTO network_interfaces(interface_id,asset_id,name,mac,source,observed_at,freshness_seconds) VALUES(?,?,?,?,?,?,?) ON CONFLICT(interface_id) DO UPDATE SET mac=excluded.mac,source=excluded.source,observed_at=excluded.observed_at,freshness_seconds=excluded.freshness_seconds""", (interface_id, asset_id, "primary", normalized_mac, source, now, 0))
            self.db.conn.execute("""INSERT INTO network_addresses(observation_id,asset_id,interface_id,address,address_family,hostname,source,first_seen,last_seen,freshness_seconds) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(asset_id,address) DO UPDATE SET interface_id=excluded.interface_id,hostname=excluded.hostname,source=excluded.source,last_seen=excluded.last_seen,freshness_seconds=excluded.freshness_seconds""", (new_uuid(), asset_id, interface_id, normalized_ip, "ipv4" if parsed.version == 4 else "ipv6", hostname, source, now, now, 0))
            conflicts = []
            if normalized_mac:
                conflict = self.db.conn.execute("SELECT i.asset_id FROM network_interfaces i JOIN network_assets a ON a.asset_id=i.asset_id WHERE a.site_id=? AND i.mac=? AND i.asset_id!=? LIMIT 1", (site_id, normalized_mac, asset_id)).fetchone()
                if conflict:
                    conflicts.append(("mac_seen_on_multiple_assets", normalized_mac, conflict["asset_id"]))
            conflict = self.db.conn.execute("SELECT n.asset_id FROM network_addresses n JOIN network_assets a ON a.asset_id=n.asset_id WHERE a.site_id=? AND n.address=? AND n.asset_id!=? LIMIT 1", (site_id, normalized_ip, asset_id)).fetchone()
            if conflict:
                conflicts.append(("address_seen_on_multiple_assets", normalized_ip, conflict["asset_id"]))
            if len(compact_mac) == 12:
                try:
                    if int(compact_mac[0:2], 16) & 2:
                        self._append_ambiguity(site_id, asset_id, "locally_administered_or_randomized_mac")
                except ValueError:
                    pass
            for conflict_kind, identity_value, existing_asset_id in conflicts:
                self._append_ambiguity(site_id, asset_id, conflict_kind)
                self._append_ambiguity(site_id, existing_asset_id, conflict_kind)
                self.db.conn.execute("INSERT INTO network_identity_conflicts(conflict_id,site_id,scope_id,conflict_kind,identity_value,existing_asset_id,reported_asset_id,source,detail,observed_at) VALUES(?,?,?,?,?,?,?,?,?,?)", (new_uuid(), site_id, scope_id, conflict_kind, identity_value, existing_asset_id, asset_id, source, "identity preserved; no automatic merge", now))
            for port in sorted(set(normalized_ports)):
                self.db.conn.execute("INSERT OR IGNORE INTO network_services(observation_id,asset_id,transport,port,service_family,source,observed_at,freshness_seconds) VALUES(?,?,?,?,?,?,?,?)", (new_uuid(), asset_id, "tcp", port, "unknown", source, now, 0))
            append_domain_event(self.db, DomainEvent("network_asset", asset_id, "network_asset.observed", collector_id, "approved network observation", site_id=site_id, payload={"scope_id": scope_id, "ip": ip, "source": source, "reachability": reachability or "not_attempted"}), commit=False)
        return asset

    def _append_ambiguity(self, site_id, asset_id, value):
        row = self.db.conn.execute("SELECT ambiguity FROM network_assets WHERE asset_id=? AND site_id=?", (asset_id, site_id)).fetchone()
        if not row:
            return
        try:
            values = json.loads(row["ambiguity"] or "[]")
        except (TypeError, ValueError):
            values = []
        if value not in values:
            values.append(value)
            self.db.conn.execute("UPDATE network_assets SET ambiguity=? WHERE asset_id=? AND site_id=?", (json.dumps(values, ensure_ascii=False), asset_id, site_id))

    def import_evidence(self, *, scope_id, site_id, import_id, kind, records, source=None, collector_id="local", justification=""):
        """Import bounded infrastructure evidence without collecting secrets.

        Each record needs a caller-supplied ``record_id``.  If it has no
        durable asset identity, the derived candidate ID remains explicitly
        ambiguous and is never merged solely on MAC or IP.
        """
        if kind not in IMPORT_KINDS:
            raise ValueError("unsupported network evidence import kind")
        if not import_id or not str(import_id).strip():
            raise ValueError("import_id is required")
        if not justification or not justification.strip():
            raise ValueError("import justification is required")
        if not isinstance(records, list):
            raise ValueError("records must be an array")
        for record in records:
            if not isinstance(record, dict):
                raise ValueError("import records must contain objects")
            if _contains_forbidden_key(record):
                raise ValueError("import contains a prohibited credential or secret field")
            if not str(record.get("record_id") or "").strip():
                raise ValueError("each imported record requires record_id")
            if record.get("site_id") and str(record["site_id"]) != str(site_id):
                raise ValueError("import record crosses site scope")
        try:
            records_hash = hashlib.sha256(
                json.dumps(records, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
        except (TypeError, ValueError) as exc:
            raise ValueError("import records must be JSON serializable") from exc
        grant = self._approved_scope(scope_id)
        if grant.site_id != site_id:
            raise ValueError("import site does not match approved scope")
        existing_receipt = self.db.execute("SELECT * FROM network_import_receipts WHERE import_id=?", (str(import_id),)).fetchone()
        if existing_receipt:
            if existing_receipt["site_id"] != site_id or existing_receipt["scope_id"] != scope_id:
                raise ValueError("import replay is outside the original scope")
            prior_hash = existing_receipt["records_hash"] if "records_hash" in existing_receipt.keys() else None
            if not prior_hash:
                raise ValueError("legacy import replay cannot be validated")
            if not hmac.compare_digest(str(prior_hash), records_hash):
                raise ValueError("import replay has different evidence")
            return dict(existing_receipt)

        if source is not None and not isinstance(source, str):
            raise ValueError("import source must be a string")
        source_name = (source or f"{kind}_import").strip()[:120]
        session_id = f"import:{import_id}"
        session = NetworkObservationSession(
            session_id=session_id, collector_id=collector_id, collector_type="import",
            scope_id=scope_id, observation_methods=[f"import:{kind}"],
            authorization_reference=grant.authorization_reference, started_at=self.now,
            completed_at=self.now, coverage_state="complete",
        )
        contradictions = []
        normalized_count = 0
        with self.db.conn:
            NetworkSessionRepo(self.db).save(session, commit=False)
            self.db.conn.execute("INSERT INTO network_import_receipts(import_id,site_id,scope_id,import_kind,source,record_count,status,justification,received_at,records_hash) VALUES(?,?,?,?,?,?,?,?,?,?)", (str(import_id), site_id, scope_id, kind, source_name, 0, "processing", justification, self.now.isoformat(), records_hash))
            for record in records:
                if not isinstance(record, dict):
                    raise ValueError("import records must contain objects")
                record_id = str(record.get("record_id") or "").strip()
                if not record_id:
                    raise ValueError("each imported record requires record_id")
                if record.get("site_id") and str(record["site_id"]) != str(site_id):
                    raise ValueError("import record crosses site scope")
                asset_id = str(record.get("asset_id") or f"import:{kind}:{record_id}").strip()
                existing_asset = self.db.conn.execute("SELECT site_id FROM network_assets WHERE asset_id=?", (asset_id,)).fetchone()
                if not existing_asset:
                    existing_asset = self.db.conn.execute("SELECT site_id FROM camera_assets WHERE asset_id=?", (asset_id,)).fetchone()
                if existing_asset and existing_asset["site_id"] != site_id:
                    raise ValueError("import asset identity crosses site scope")
                asset_type = record.get("asset_type", "unknown")
                if asset_type not in ASSET_TYPES:
                    asset_type = "unknown"
                ambiguity = [] if record.get("asset_id") else ["identity_derived_from_import_record"]
                now = self.now.isoformat()
                display_name = str(record.get("display_name") or record.get("hostname") or record.get("dns_name") or record.get("dhcp_name") or "")[:255]
                self.db.conn.execute("""INSERT INTO network_assets(asset_id,site_id,asset_type,manufacturer,model,display_name,evidence_state,ambiguity,first_seen,last_seen,freshness_seconds) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(asset_id) DO UPDATE SET last_seen=excluded.last_seen,display_name=CASE WHEN excluded.display_name!='' THEN excluded.display_name ELSE network_assets.display_name END,asset_type=CASE WHEN network_assets.asset_type='unknown' THEN excluded.asset_type ELSE network_assets.asset_type END,ambiguity=excluded.ambiguity""", (asset_id, site_id, asset_type, str(record.get("manufacturer") or "")[:120], str(record.get("model") or "")[:120], display_name, "observed", json.dumps(ambiguity), now, now, None))
                interface_id = str(record.get("interface_id") or f"{asset_id}:primary")[:160]
                mac = str(record.get("mac") or "")[:32]
                existing_interface = self.db.conn.execute("SELECT asset_id FROM network_interfaces WHERE interface_id=?", (interface_id,)).fetchone()
                if existing_interface and existing_interface["asset_id"] != asset_id:
                    contradictions.append({"kind": "interface_reassigned", "interface_id": interface_id, "existing_asset_id": existing_interface["asset_id"], "reported_asset_id": asset_id, "record_id": record_id})
                elif not existing_interface:
                    same_mac = self.db.conn.execute("SELECT i.asset_id,i.interface_id FROM network_interfaces i JOIN network_assets a ON a.asset_id=i.asset_id WHERE a.site_id=? AND i.mac=? AND i.mac!='' AND i.asset_id!=? LIMIT 1", (site_id, mac, asset_id)).fetchone() if mac else None
                    if same_mac:
                        contradictions.append({"kind": "mac_seen_on_multiple_assets", "mac": mac, "existing_asset_id": same_mac["asset_id"], "reported_asset_id": asset_id, "record_id": record_id})
                    self.db.conn.execute("INSERT INTO network_interfaces(interface_id,asset_id,name,mac,source,observed_at,freshness_seconds) VALUES(?,?,?,?,?,?,?)", (interface_id, asset_id, str(record.get("interface_name") or "primary")[:120], mac, source_name, now, None))
                address = record.get("address") or record.get("ip") or record.get("ipv4") or record.get("ipv6")
                if address:
                    parsed = ipaddress.ip_address(str(address))
                    if not grant.contains(str(parsed)):
                        raise ValueError("import address is outside the approved scope")
                    existing_address = self.db.conn.execute("SELECT n.asset_id FROM network_addresses n JOIN network_assets a ON a.asset_id=n.asset_id WHERE a.site_id=? AND n.address=? AND n.asset_id!=? LIMIT 1", (site_id, str(parsed), asset_id)).fetchone()
                    if existing_address:
                        contradictions.append({"kind": "address_seen_on_multiple_assets", "address": str(parsed), "existing_asset_id": existing_address["asset_id"], "reported_asset_id": asset_id, "record_id": record_id})
                    self.db.conn.execute("""INSERT INTO network_addresses(observation_id,asset_id,interface_id,address,address_family,hostname,dhcp_name,dns_name,source,first_seen,last_seen,freshness_seconds) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(asset_id,address) DO UPDATE SET interface_id=excluded.interface_id,hostname=excluded.hostname,dhcp_name=excluded.dhcp_name,dns_name=excluded.dns_name,source=excluded.source,last_seen=excluded.last_seen,freshness_seconds=excluded.freshness_seconds""", (new_uuid(), asset_id, interface_id, str(parsed), "ipv4" if parsed.version == 4 else "ipv6", display_name, str(record.get("dhcp_name") or "")[:255], str(record.get("dns_name") or "")[:255], source_name, now, now, None))
                services = record.get("services", [])
                if record.get("port") is not None:
                    services = list(services) + [{"transport": record.get("transport", "tcp"), "port": record.get("port"), "service_family": record.get("service_family", "unknown"), "limited_fingerprint": record.get("limited_fingerprint", "")}]
                if not isinstance(services, list):
                    raise ValueError("import services must be an array")
                for service in services:
                    if not isinstance(service, dict) or str(service.get("transport", "")).lower() not in {"tcp", "udp"}:
                        raise ValueError("import service transport must be tcp or udp")
                    port = int(service.get("port", 0))
                    if port not in DEFAULT_ALLOWLISTED_PORTS:
                        raise ValueError(f"port {port} is not allowlisted")
                    self.db.conn.execute("""INSERT INTO network_services(observation_id,asset_id,transport,port,service_family,limited_fingerprint,source,observed_at,freshness_seconds) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(asset_id,transport,port) DO UPDATE SET service_family=excluded.service_family,limited_fingerprint=excluded.limited_fingerprint,source=excluded.source,observed_at=excluded.observed_at""", (new_uuid(), asset_id, str(service["transport"]).lower(), port, str(service.get("service_family") or "unknown")[:80], str(service.get("limited_fingerprint") or "")[:255], source_name, now, None))
                if kind in IMPORT_RELATIONS:
                    relation, peer_type = IMPORT_RELATIONS[kind]
                    peer_id = record.get("peer_id") or record.get("gateway") or record.get("switch_port")
                    if peer_id:
                        if _topology_node_from_other_site(self.db, site_id, peer_id, peer_type):
                            raise ValueError("import topology edge references a node from another site")
                        _validate_topology_node_scope(grant, peer_id, peer_type)
                        edge_id = f"import:{import_id}:{record_id}"
                        source_observation_id = new_uuid()
                        self.db.conn.execute("INSERT INTO observations(observation_id,site_id,kind,detail,source,observed_at,session_id) VALUES(?,?,?,?,?,?,?)", (source_observation_id, site_id, f"import:{kind}", str(record.get("detail") or f"{kind} evidence")[:255], source_name, now, session_id))
                        self.db.conn.execute("""INSERT OR IGNORE INTO topology_edges(edge_id,site_id,from_id,from_type,to_id,to_type,relation,detail,since,verified,source_observation_id,source_session_id,observed_at,validity_start,confidence,evidence_state,contradiction_status,evidence_refs) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (edge_id, site_id, asset_id, "asset", str(peer_id)[:160], peer_type, relation, str(record.get("detail") or f"{kind} evidence")[:255], now, 0, source_observation_id, session_id, now, now, "observed", "observed", "none", json.dumps([source_observation_id])))
                normalized_count += 1
            failure_state = json.dumps({"contradictions": contradictions}, ensure_ascii=False) if contradictions else None
            self.db.conn.execute("UPDATE network_import_receipts SET record_count=?,status='complete',failure_state=? WHERE import_id=?", (normalized_count, failure_state, str(import_id)))
            append_domain_event(self.db, DomainEvent("network_import", str(import_id), "network_import.completed", collector_id, justification, site_id=site_id, from_state="processing", to_state="complete", payload={"kind": kind, "scope_id": scope_id, "session_id": session_id, "record_count": normalized_count, "contradictions": contradictions}), commit=False)
        return dict(self.db.conn.execute("SELECT * FROM network_import_receipts WHERE import_id=?", (str(import_id),)).fetchone())

    def add_scoped_topology_edge(self, *, scope_id, site_id, from_id, from_type, to_id, to_type, relation, justification, detail="", actor="operator"):
        """Record an observed generic edge only inside an approved scope."""
        if not justification or not justification.strip():
            raise ValueError("topology justification is required")
        if not str(from_id).strip() or not str(to_id).strip():
            raise ValueError("topology identifiers are required")
        if from_type not in TOPOLOGY_NODE_TYPES or to_type not in TOPOLOGY_NODE_TYPES:
            raise ValueError("unsupported topology node type")
        if relation not in TOPOLOGY_RELATIONS:
            raise ValueError("unsupported topology relation")
        if str(from_id) == str(to_id) and from_type == to_type:
            raise ValueError("self-referential topology edge is not supported")
        grant = self._approved_scope(scope_id)
        if grant.site_id != site_id:
            raise ValueError("topology site does not match approved scope")
        for node_id, node_type in ((from_id, from_type), (to_id, to_type)):
            if _topology_node_from_other_site(self.db, site_id, node_id, node_type):
                raise ValueError("topology edge references a node from another site")
            _validate_topology_node_scope(grant, node_id, node_type)
        edge_id = new_uuid()
        now = self.now.isoformat()
        observation_id = new_uuid()
        with self.db.conn:
            self.db.conn.execute("INSERT INTO observations(observation_id,site_id,kind,detail,source,observed_at,session_id) VALUES(?,?,?,?,?,?,?)", (observation_id, site_id, "topology_edge_observed", f"{from_type} {from_id} {relation} {to_type} {to_id}", "network_scope", now, scope_id))
            self.db.conn.execute("INSERT INTO topology_edges(edge_id,site_id,from_id,from_type,to_id,to_type,relation,detail,since,verified,source_observation_id,source_session_id,observed_at,validity_start,confidence,evidence_state,contradiction_status,evidence_refs) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (edge_id, site_id, str(from_id), from_type, str(to_id), to_type, relation, str(detail or "")[:255], now, 0, observation_id, scope_id, now, now, "observed", "observed", "none", json.dumps([observation_id])))
            append_domain_event(self.db, DomainEvent("topology_edge", edge_id, "topology.edge_observed", actor, justification, site_id=site_id, payload={"scope_id": scope_id, "from_id": str(from_id), "from_type": from_type, "to_id": str(to_id), "to_type": to_type, "relation": relation, "verified": False}), commit=False)
        return {"edge_id": edge_id, "site_id": site_id, "from_id": str(from_id), "from_type": from_type, "to_id": str(to_id), "to_type": to_type, "relation": relation, "detail": str(detail or ""), "since": now, "until": None, "verified": False, "source_observation_id": observation_id, "source_session_id": scope_id, "observed_at": now, "validity_start": now, "validity_end": None, "confidence": "observed", "evidence_state": "observed", "contradiction_status": "none", "evidence_refs": [observation_id], "source_state": "observed", "authorization_state": "observed"}

    def apply_authorized_snapshot(self, *, site_id, envelope):
        """Accept a signed RegOS expectation without granting local authority."""
        packet = NetworkPacket.from_dict(envelope)
        if packet.envelope["event_type"] not in {"FacilityRegistryProjection", "AuthorizedDeviceSnapshot"}:
            raise ValueError("authorized snapshot packet type required")
        if str(packet.envelope["facility_id"]) != str(site_id):
            raise ValueError("authorized snapshot site mismatch")
        if packet.envelope.get("source_system") != "RegOS":
            raise PermissionError("authorized snapshots must originate from RegOS")
        if not isinstance(packet.envelope.get("authority_context"), dict):
            raise ValueError("authorized snapshot authority context must be an object")
        if packet.envelope.get("freshness") not in ALLOWED_FRESHNESS:
            raise ValueError("unsupported snapshot freshness state")
        timestamps = []
        for field in ("occurred_at", "recorded_at"):
            raw_timestamp = packet.envelope.get(field)
            if not isinstance(raw_timestamp, str):
                raise ValueError("snapshot timestamp is required")
            timestamp = datetime.fromisoformat(raw_timestamp.replace("Z", "+00:00"))
            if timestamp.tzinfo is None or timestamp.utcoffset() is None:
                raise ValueError("snapshot timestamp must be timezone-aware")
            timestamps.append(timestamp.astimezone(timezone.utc))
        expiration = packet.envelope.get("expires_at") or packet.envelope["authority_context"].get("expires_at")
        if expiration is not None:
            if not isinstance(expiration, str):
                raise ValueError("snapshot expiration must be a timestamp")
            expires_at = datetime.fromisoformat(expiration.replace("Z", "+00:00"))
            if expires_at.tzinfo is None or expires_at.utcoffset() is None:
                raise ValueError("snapshot expiration must be timezone-aware")
            if expires_at.astimezone(timezone.utc) <= self.now:
                raise ValueError("authorized snapshot has expired")
        signing_key = configured_regos_signing_key()
        if not signing_key or not packet.verify(signing_key, require_signature=True):
            raise PermissionError("valid RegOS snapshot signature required")
        payload = packet.envelope["payload"]
        if not isinstance(payload, dict):
            raise ValueError("authorized snapshot payload must be an object")
        if _contains_forbidden_key(payload):
            raise ValueError("authorized snapshot contains a prohibited credential or secret field")
        snapshot_id = str(payload.get("snapshot_id") or payload.get("authorized_snapshot_id") or "").strip()
        if not snapshot_id:
            raise ValueError("authorized snapshot requires snapshot_id")
        existing = self.db.execute("SELECT * FROM network_projection_receipts WHERE event_id=? OR packet_hash=?", (packet.envelope["event_id"], packet.envelope["packet_hash"])).fetchone()
        if existing:
            if existing["packet_hash"] != packet.envelope["packet_hash"]:
                raise ValueError("authorized snapshot replay with different packet")
            return dict(existing)
        assets = payload.get("assets", payload.get("expected_assets", []))
        scopes = payload.get("scopes", [])
        if not isinstance(assets, list) or not isinstance(scopes, list):
            raise ValueError("authorized snapshot assets and scopes must be arrays")
        now = datetime.now(timezone.utc).isoformat()
        with self.db.conn:
            self.db.conn.execute("INSERT INTO network_projection_receipts(projection_id,event_id,packet_hash,site_id,snapshot_id,event_type,status,packet,received_at) VALUES(?,?,?,?,?,?,?,?,?)", (new_uuid(), packet.envelope["event_id"], packet.envelope["packet_hash"], site_id, snapshot_id, packet.envelope["event_type"], "accepted", json.dumps(packet.to_dict(), ensure_ascii=False, sort_keys=True), now))
            for item in assets:
                if not isinstance(item, dict) or not str(item.get("asset_id") or item.get("device_id") or "").strip():
                    raise ValueError("authorized snapshot asset identity is required")
                if str(item.get("authorization_state", "")).lower() in {"authorized", "trusted"}:
                    raise ValueError("authorized snapshot cannot assign local authorization or trust")
                asset_type = item.get("asset_type", "unknown") if item.get("asset_type", "unknown") in ASSET_TYPES else "unknown"
                self.db.conn.execute("""INSERT INTO network_expected_assets(expected_id,site_id,snapshot_id,asset_id,asset_type,display_name,expected_state,scope_id,ambiguity,received_at) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(site_id,snapshot_id,asset_id) DO UPDATE SET asset_type=excluded.asset_type,display_name=excluded.display_name,expected_state=excluded.expected_state,scope_id=excluded.scope_id,ambiguity=excluded.ambiguity,received_at=excluded.received_at""", (new_uuid(), site_id, snapshot_id, str(item.get("asset_id") or item.get("device_id")), asset_type, str(item.get("display_name") or "")[:255], item.get("expected_state", "expected") if item.get("expected_state", "expected") in {"expected", "required", "retired", "reference_only"} else "expected", item.get("scope_id") or packet.envelope["authority_context"].get("scope_id"), json.dumps(packet.envelope.get("ambiguity", [])), now))
            for expected_scope in scopes:
                if not isinstance(expected_scope, dict) or not str(expected_scope.get("scope_id") or "").strip():
                    raise ValueError("authorized snapshot scope identity is required")
                if not isinstance(expected_scope.get("cidrs"), list) or not expected_scope["cidrs"]:
                    raise ValueError("authorized snapshot scope requires at least one CIDR")
                if expected_scope.get("expected_state", "reference_only") != "reference_only":
                    raise ValueError("authorized snapshot scope state must remain reference_only")
                cidrs = []
                for raw in expected_scope.get("cidrs", []):
                    if not isinstance(raw, str) or not raw.strip():
                        raise ValueError("authorized snapshot scope CIDR values must be non-empty strings")
                    network = ipaddress.ip_network(raw, strict=False)
                    if network.prefixlen == 0 or not (network.is_private or network.is_link_local):
                        raise ValueError("authorized snapshot contains a non-corporate CIDR")
                    cidrs.append(str(network))
                self.db.conn.execute("""INSERT INTO network_expected_scopes(expected_scope_id,site_id,snapshot_id,scope_id,cidrs,purpose,expected_state,received_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(site_id,snapshot_id,scope_id) DO UPDATE SET cidrs=excluded.cidrs,purpose=excluded.purpose,expected_state='reference_only',received_at=excluded.received_at""", (new_uuid(), site_id, snapshot_id, str(expected_scope["scope_id"]), json.dumps(cidrs), str(expected_scope.get("purpose") or "")[:255], "reference_only", now))
            append_domain_event(self.db, DomainEvent("network_projection", snapshot_id, "network_projection.accepted", "RegOS", "signed authorized snapshot received", site_id=site_id, payload={"event_id": packet.envelope["event_id"], "packet_hash": packet.envelope["packet_hash"], "trust_assignment": "not_performed", "asset_count": len(assets), "scope_count": len(scopes)}), commit=False)
        return dict(self.db.execute("SELECT * FROM network_projection_receipts WHERE event_id=?", (packet.envelope["event_id"],)).fetchone())

    def expected_snapshots(self, site_id):
        return [dict(row) for row in self.db.conn.execute("SELECT * FROM network_expected_assets WHERE site_id=? ORDER BY received_at DESC", (site_id,))]

    def drift(self, site_id):
        expected = self.expected_snapshots(site_id)
        if not expected:
            return {"items": [], "source_state": "not_available", "coverage": "baseline_not_configured", "freshness": None, "evidence_refs": [], "authorization_state": "observed", "trust_assignment": "not_performed"}
        observed = [dict(row) for row in self.db.conn.execute("SELECT * FROM network_assets WHERE site_id=? ORDER BY last_seen DESC", (site_id,))]
        expected_keys = {(row["site_id"], row["asset_id"]) for row in expected if row["expected_state"] != "retired"}
        observed_keys = {(row["site_id"], row["asset_id"]) for row in observed}
        items = []
        for row in expected:
            key = (row["site_id"], row["asset_id"])
            if row["expected_state"] != "retired" and key not in observed_keys:
                items.append({"kind": "missing_asset", "asset_id": row["asset_id"], "site_id": site_id, "expected_state": row["expected_state"], "freshness": "declared"})
        for row in observed:
            if (row["site_id"], row["asset_id"]) not in expected_keys:
                items.append({"kind": "unexpected_asset", "asset_id": row["asset_id"], "site_id": site_id, "evidence_state": row["evidence_state"], "last_seen": row["last_seen"], "freshness": "observed"})
        return {
            "items": items,
            "source_state": "projected",
            "coverage": "expected_vs_observed",
            "freshness": "per_record",
            "evidence_refs": [str(item.get("source_packet_id") or item.get("asset_id")) for item in items if item.get("source_packet_id") or item.get("asset_id")],
            "authorization_state": "observed",
            "trust_assignment": "not_performed",
        }

    def retry_packet(self, *, site_id, packet_id, justification, actor="operator", error=None):
        if not justification or not justification.strip():
            raise ValueError("packet retry justification is required")
        packet = NetworkPacketQueueRepo(self.db).get(packet_id)
        if not packet:
            raise KeyError(packet_id)
        scope = NetworkScopeRepo(self.db).get(packet["scope_id"])
        if not scope or scope.site_id != site_id:
            raise ValueError("packet is not in the requested site scope")
        with self.db.conn:
            result = NetworkPacketQueueRepo(self.db).retry(packet_id, error=error, commit=False)
            append_domain_event(self.db, DomainEvent("network_packet", packet_id, "network_packet.retry_requested", actor, justification, site_id=site_id, payload={"attempt": result["attempts"], "scope_id": packet["scope_id"], "transport": "not_performed"}), commit=False)
        return result

    def export_packet(self, *, scope_id, site_id, collector_id, payload, signature_key=None, tenant_id=None, event_type="NetworkObservationEvent"):
        grant = self._approved_scope(scope_id)
        if grant.site_id != site_id:
            raise ValueError("packet site does not match approved scope")
        if not isinstance(collector_id, str) or not collector_id.strip():
            raise ValueError("collector_id is required")
        if not isinstance(payload, dict):
            raise ValueError("packet payload must be an object")
        if _contains_forbidden_key(payload):
            raise ValueError("packet payload contains a prohibited credential or secret field")
        assets = payload.get("assets", [])
        if isinstance(payload.get("asset"), dict):
            assets = [payload["asset"]] + list(assets) if isinstance(assets, list) else None
        if not isinstance(assets, list) or any(not isinstance(item, dict) for item in assets):
            raise ValueError("packet assets must be an array of objects")
        for item in assets:
            if item.get("observation_kind", "asset_seen") not in OBSERVATION_KINDS:
                raise ValueError("unsupported network observation kind")
        if event_type not in PACKET_TYPES:
            raise ValueError("unsupported network packet type")
        evidence_refs = payload.get("evidence_refs", [])
        ambiguity = payload.get("ambiguity", [])
        if not isinstance(evidence_refs, list) or not evidence_refs or any(not isinstance(ref, str) or not ref.strip() for ref in evidence_refs):
            raise ValueError("packet evidence_refs must be a non-empty array of strings")
        if not isinstance(ambiguity, list):
            raise ValueError("packet ambiguity must be an array")
        freshness = payload.get("freshness", "observed")
        if freshness not in ALLOWED_FRESHNESS:
            raise ValueError("unsupported packet freshness state")
        if signature_key is None:
            signature_key = configured_collector_signing_key()
        elif isinstance(signature_key, str):
            signature_key = signature_key.encode("utf-8")
        elif not isinstance(signature_key, (bytes, bytearray)):
            raise ValueError("packet signing key must be bytes")
        if _flag_enabled("CORPORATE_COLLECTOR_MODE") and not signature_key:
            raise PermissionError("corporate collector signing credential is not configured")
        packet_tenant_id = tenant_id or payload.get("tenant_id")
        if _flag_enabled("CORPORATE_COLLECTOR_MODE") and not str(packet_tenant_id or "").strip():
            raise ValueError("corporate packet tenant_id is required")
        packet = NetworkPacket.create(event_type=event_type, payload=payload, source_system="Camera-Location", source_surface="electron", tenant_id=packet_tenant_id or site_id, facility_id=site_id, collector_id=collector_id, scope_id=scope_id, evidence_refs=evidence_refs, ambiguity=ambiguity, freshness=freshness, signature_key=signature_key, authorization_reference=grant.authorization_reference)
        with self.db.conn:
            result = NetworkPacketQueueRepo(self.db).enqueue(packet, scope_id, commit=False)
            append_domain_event(self.db, DomainEvent("network_packet", packet.envelope["event_id"], "network_packet.queued", collector_id, "offline evidence queued", site_id=site_id, payload={"scope_id": scope_id, "packet_hash": packet.envelope["packet_hash"]}), commit=False)
        return result
