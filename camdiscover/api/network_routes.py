from __future__ import annotations
import json
from datetime import datetime, timezone
from flask import Blueprint, current_app, jsonify, request
from ..persistence.db import get_database, new_uuid
from ..persistence.network_repos import NetworkScopeRepo, NetworkPacketQueueRepo
from ..services.network_mapping import NetworkMappingService, configured_collector_signing_key

network_api = Blueprint("network_mapping_api", __name__, url_prefix="/api/network-mapping")

def _db(): return current_app.config.get("CAMDISCOVER_DB") or get_database()


def _with_metadata(payload, *, source_state, freshness=None, coverage=None,
                   evidence_refs=None, authorization_state="observed"):
    result = dict(payload)
    result.update({
        "source_state": source_state,
        "freshness": freshness,
        "coverage": coverage,
        "evidence_refs": list(evidence_refs or []),
        "authorization_state": authorization_state,
        "trust_assignment": "not_performed",
    })
    return result


def _generic_asset(row):
    item = dict(row)
    try:
        item["ambiguity"] = json.loads(item.get("ambiguity") or "[]")
    except (TypeError, ValueError):
        item["ambiguity"] = ["malformed_ambiguity_evidence"]
    item.update({
        "source_state": "projected", "authorization_state": "observed",
        "trust_assignment": "not_performed",
        "freshness": "observed" if item.get("freshness_seconds") is not None else "unavailable",
    })
    return item


def _queued_packet(row):
    item = dict(row)
    try:
        envelope = json.loads(item.pop("payload"))
    except (TypeError, ValueError, json.JSONDecodeError):
        envelope = None
    item.update({
        "packet": envelope,
        "source_state": "queued",
        "sync_state": item.get("status", "queued"),
        "freshness": envelope.get("freshness") if isinstance(envelope, dict) else "unavailable",
        "coverage": envelope.get("payload", {}).get("coverage", "queued") if isinstance(envelope, dict) and isinstance(envelope.get("payload"), dict) else "unavailable",
        "evidence_refs": envelope.get("evidence_refs", []) if isinstance(envelope, dict) else [],
        "authorization_state": "observed",
        "trust_assignment": "not_performed",
    })
    return item

@network_api.post("/sites/<site_id>/scopes")
def create_scope(site_id):
    b = request.json or {}
    try:
        expires_at = b["expires_at"]
        if not isinstance(expires_at, str):
            raise ValueError("expires_at must be an ISO-8601 string")
        grant = NetworkMappingService(_db()).create_scope(site_id=site_id, cidrs=b.get("cidrs", []), purpose=b.get("purpose", ""), actor=b.get("actor", "operator"), expires_at=datetime.fromisoformat(expires_at.replace("Z", "+00:00")), authorization_reference=b.get("authorization_reference", ""), justification=b.get("justification", ""))
    except (ValueError, KeyError, TypeError) as exc: return jsonify({"error": str(exc)}), 400
    return jsonify(_with_metadata(grant.to_dict(), source_state="governed", freshness="authorization_state", coverage="scope_grant", evidence_refs=[f"scope:{grant.scope_id}"], authorization_state=grant.authorization_state)), 201

@network_api.post("/sites/<site_id>/scopes/<scope_id>/approve")
def approve_scope(site_id, scope_id):
    try:
        grant = NetworkMappingService(_db()).approve_scope(scope_id, site_id=site_id, actor=(request.json or {}).get("actor", "operator"), justification=(request.json or {}).get("justification", ""))
        return jsonify(_with_metadata(grant.to_dict(), source_state="governed", freshness="authorization_state", coverage="scope_grant", evidence_refs=[f"scope:{grant.scope_id}"], authorization_state=grant.authorization_state))
    except KeyError: return jsonify({"error": "scope not found"}), 404
    except ValueError as exc: return jsonify({"error": str(exc)}), 400

@network_api.get("/sites/<site_id>/scopes")
def list_scopes(site_id):
    result = []
    for scope in NetworkScopeRepo(_db()).list_for_site(site_id):
        item = scope.to_dict()
        if scope.authorization_state == "approved" and scope.expires_at <= datetime.now(timezone.utc): item["authorization_state"] = "expired"
        result.append(item)
    return jsonify(_with_metadata({"scopes": result}, source_state="governed" if result else "empty", freshness="authorization_state" if result else None, coverage="scope_grants" if result else "no_scope_grants", evidence_refs=[f"scope:{item['scope_id']}" for item in result], authorization_state="mixed" if result else "none"))

@network_api.get("/sites/<site_id>/assets")
def inventory(site_id):
    db = _db()
    generic = [_generic_asset(row) for row in db.conn.execute("SELECT * FROM network_assets WHERE site_id=? ORDER BY last_seen DESC", (site_id,))]
    # camera_assets remains compatibility storage in V1; expose it as legacy
    # evidence without changing its authorization semantics.
    legacy = [dict(row) for row in db.conn.execute("SELECT asset_id,site_id,asset_class AS asset_type,manufacturer,model,installed_status,human_confirmed,updated_at FROM camera_assets WHERE site_id=?", (site_id,))]
    for row in legacy:
        row["source_state"] = "legacy_camera_storage"
        row["authorization_state"] = "verified" if row.pop("human_confirmed", 0) else "observed"
        row["trust_assignment"] = "not_performed"
        row["freshness"] = row.get("updated_at") or "unavailable"
        row["ambiguity"] = []
    assets = generic + legacy
    return jsonify(_with_metadata({"assets": assets}, source_state="projected" if assets else "empty", freshness="per_record" if assets else None, coverage="local_evidence" if assets else "no_observations", evidence_refs=[f"asset:{item['asset_id']}" for item in assets if item.get("asset_id")], authorization_state="observed"))

@network_api.get("/sites/<site_id>/services")
def services(site_id):
    rows = [dict(row) for row in _db().conn.execute("""SELECT s.* FROM network_services s JOIN network_assets a ON a.asset_id=s.asset_id WHERE a.site_id=? ORDER BY a.last_seen DESC,s.port""", (site_id,))]
    for row in rows:
        row.update({"source_state": "projected", "authorization_state": "observed", "trust_assignment": "not_performed", "freshness": row.get("freshness_seconds") if row.get("freshness_seconds") is not None else "unavailable"})
    return jsonify(_with_metadata({"services": rows}, source_state="projected" if rows else "empty", freshness="per_observation" if rows else None, coverage="allowlisted_service_observations" if rows else "no_service_observations", evidence_refs=[f"service:{row['observation_id']}" for row in rows if row.get("observation_id")]))


@network_api.get("/sites/<site_id>/interfaces")
def interfaces(site_id):
    rows = [dict(row) for row in _db().conn.execute("""SELECT i.* FROM network_interfaces i JOIN network_assets a ON a.asset_id=i.asset_id WHERE a.site_id=? ORDER BY i.observed_at DESC""", (site_id,))]
    for row in rows:
        row.update({"source_state": "projected", "authorization_state": "observed", "trust_assignment": "not_performed", "freshness": row.get("freshness_seconds") if row.get("freshness_seconds") is not None else "unavailable"})
    return jsonify(_with_metadata({"interfaces": rows}, source_state="projected" if rows else "empty", freshness="per_interface" if rows else None, coverage="local_interface_observations" if rows else "no_interface_observations", evidence_refs=[f"interface:{row['interface_id']}" for row in rows if row.get("interface_id")]))


@network_api.get("/sites/<site_id>/addresses")
def addresses(site_id):
    rows = [dict(row) for row in _db().conn.execute("""SELECT n.* FROM network_addresses n JOIN network_assets a ON a.asset_id=n.asset_id WHERE a.site_id=? ORDER BY n.last_seen DESC""", (site_id,))]
    for row in rows:
        row.update({"source_state": "projected", "authorization_state": "observed", "trust_assignment": "not_performed", "freshness": row.get("freshness_seconds") if row.get("freshness_seconds") is not None else "unavailable"})
    return jsonify(_with_metadata({"addresses": rows}, source_state="projected" if rows else "empty", freshness="per_address" if rows else None, coverage="local_address_observations" if rows else "no_address_observations", evidence_refs=[f"address:{row['observation_id']}" for row in rows if row.get("observation_id")]))


@network_api.get("/sites/<site_id>/sessions")
def sessions(site_id):
    rows = [dict(row) for row in _db().conn.execute("SELECT * FROM network_observation_sessions WHERE scope_id IN (SELECT scope_id FROM network_scope_grants WHERE site_id=?) ORDER BY started_at DESC", (site_id,))]
    for row in rows:
        try:
            row["methods"] = json.loads(row.pop("observation_methods") or "[]")
        except (TypeError, ValueError, json.JSONDecodeError):
            row["methods"] = []
        row.update({"site_id": site_id, "source_state": "projected", "authorization_state": "observed", "freshness": "session_state"})
    return jsonify(_with_metadata({"sessions": rows}, source_state="projected" if rows else "empty", freshness="per_session" if rows else None, coverage="collector_sessions" if rows else "no_sessions", evidence_refs=[f"session:{row['session_id']}" for row in rows if row.get("session_id")]))

@network_api.post("/sites/<site_id>/imports")
def import_evidence(site_id):
    b = request.json or {}
    try:
        receipt = NetworkMappingService(_db()).import_evidence(
            scope_id=b["scope_id"], site_id=site_id, import_id=b["import_id"],
            kind=b["kind"], records=b.get("records", []), source=b.get("source"),
            collector_id=b.get("collector_id", "local"), justification=b.get("justification", ""),
        )
    except (ValueError, KeyError, TypeError) as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(_with_metadata(receipt, source_state="imported", coverage="complete", freshness="received_at", evidence_refs=[f"import:{receipt['import_id']}"])), 201

@network_api.post("/sites/<site_id>/topology")
def add_scoped_topology(site_id):
    b = request.json or {}
    try:
        edge = NetworkMappingService(_db()).add_scoped_topology_edge(
            scope_id=b["scope_id"], site_id=site_id, from_id=b["from_id"],
            from_type=b["from_type"], to_id=b["to_id"], to_type=b["to_type"],
            relation=b["relation"], detail=b.get("detail", ""),
            justification=b.get("justification", ""), actor=b.get("actor", "operator"),
        )
    except (ValueError, KeyError, TypeError) as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(_with_metadata(edge, source_state="observed", freshness="observed", coverage="single_topology_edge", evidence_refs=edge.get("evidence_refs", []))), 201

@network_api.post("/sites/<site_id>/observations")
def record_observation(site_id):
    b = request.json or {}
    try:
        asset = NetworkMappingService(_db()).record_observation(site_id=site_id, scope_id=b["scope_id"], asset_id=b.get("asset_id") or new_uuid(), ip=b["ip"], mac=b.get("mac", ""), asset_type=b.get("asset_type", "unknown"), hostname=b.get("hostname", ""), open_ports=b.get("open_ports", []), source=b.get("source", "passive"), collector_id=b.get("collector_id", "local"))
    except (ValueError, KeyError) as exc: return jsonify({"error": str(exc)}), 400
    return jsonify(_with_metadata(asset.to_dict(), source_state="observed", freshness="observation_time", coverage="single_asset_observation", evidence_refs=[f"asset:{asset.asset_id}"])), 201

@network_api.post("/sites/<site_id>/packets/export")
def export_packet(site_id):
    b = request.json or {}
    try:
        packet = NetworkMappingService(_db()).export_packet(
            scope_id=b["scope_id"], site_id=site_id,
            collector_id=b.get("collector_id", "local"), payload=b.get("payload", {}), event_type=b.get("event_type", "NetworkObservationEvent"),
            tenant_id=b.get("tenant_id"), signature_key=configured_collector_signing_key(),
        )
    except PermissionError as exc:
        return jsonify({"error": str(exc)}), 503
    except (KeyError, TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(_with_metadata({"packet": packet}, source_state="queued", freshness=packet.get("freshness"), coverage=packet.get("payload", {}).get("coverage", "offline_packet_queue") if isinstance(packet.get("payload"), dict) else "offline_packet_queue", evidence_refs=packet.get("evidence_refs", []), authorization_state="observed")), 201

@network_api.get("/sites/<site_id>/packets")
def list_packets(site_id):
    rows = NetworkPacketQueueRepo(_db()).list_for_site(site_id)
    packets = [_queued_packet(row) for row in rows]
    return jsonify(_with_metadata({"packets": packets, "sync_state": "offline_queue" if packets else "no_queued_packets"}, source_state="queued" if packets else "empty", freshness="queue_created_at" if packets else None, coverage="offline_packet_queue" if packets else "no_queued_packets", evidence_refs=[ref for item in packets for ref in item.get("evidence_refs", [])]))


@network_api.get("/sites/<site_id>/evidence")
def evidence(site_id):
    db = _db()
    packets = [_queued_packet(row) for row in NetworkPacketQueueRepo(db).list_for_site(site_id)]
    imports = [dict(row) for row in db.conn.execute("SELECT * FROM network_import_receipts WHERE site_id=? ORDER BY received_at DESC", (site_id,))]
    projections = [dict(row) for row in db.conn.execute("SELECT projection_id,event_id,packet_hash,snapshot_id,event_type,status,received_at FROM network_projection_receipts WHERE site_id=? ORDER BY received_at DESC", (site_id,))]
    conflicts = [dict(row) for row in db.conn.execute("SELECT * FROM network_identity_conflicts WHERE site_id=? ORDER BY observed_at DESC LIMIT 100", (site_id,))]
    has_evidence = bool(packets or imports or projections or conflicts)
    evidence_refs = [ref for item in packets for ref in item.get("evidence_refs", [])]
    evidence_refs.extend(f"import:{row['import_id']}" for row in imports if row.get("import_id"))
    evidence_refs.extend(f"projection:{row['projection_id']}" for row in projections if row.get("projection_id"))
    evidence_refs.extend(f"conflict:{row['conflict_id']}" for row in conflicts if row.get("conflict_id"))
    return jsonify(_with_metadata({"packets": packets, "imports": imports, "projections": projections, "identity_conflicts": conflicts}, source_state="projected" if has_evidence else "empty", freshness="per_record" if has_evidence else None, coverage="local_evidence_receipts" if has_evidence else "no_local_evidence", evidence_refs=evidence_refs))

@network_api.post("/sites/<site_id>/packets/<packet_id>/retry")
def retry_packet(site_id, packet_id):
    b = request.json or {}
    try:
        result = NetworkMappingService(_db()).retry_packet(site_id=site_id, packet_id=packet_id, justification=b.get("justification", ""), actor=b.get("actor", "operator"), error=b.get("last_error"))
    except KeyError:
        return jsonify({"error": "packet not found"}), 404
    except (ValueError, TypeError) as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(_with_metadata({**result, "sync_state": "retry_pending", "transport": "not_performed"}, source_state="queued", freshness="queue_updated_at", coverage="offline_packet_queue", evidence_refs=[f"packet:{packet_id}"]))

@network_api.post("/sites/<site_id>/authorized-snapshots")
def apply_authorized_snapshot(site_id):
    try:
        result = NetworkMappingService(_db()).apply_authorized_snapshot(site_id=site_id, envelope=request.json or {})
    except (ValueError, KeyError, TypeError) as exc:
        return jsonify({"error": str(exc)}), 400
    except PermissionError as exc:
        return jsonify({"error": str(exc)}), 403
    return jsonify(_with_metadata(result, source_state="accepted", freshness="received_at", coverage="expected_inventory_projection", evidence_refs=[f"projection:{result.get('projection_id')}" ] if result.get("projection_id") else [], authorization_state="expected_inventory_only")), 201

@network_api.get("/sites/<site_id>/authorized-snapshots")
def authorized_snapshots(site_id):
    rows = NetworkMappingService(_db()).expected_snapshots(site_id)
    for row in rows:
        row["authorization_state"] = "expected_inventory_only"
        row["trust_assignment"] = "not_performed"
    return jsonify(_with_metadata({"assets": rows}, source_state="projected" if rows else "empty", freshness="received_at" if rows else None, coverage="expected_inventory_projection" if rows else "no_authorized_snapshot", evidence_refs=[f"expected:{row.get('expected_id')}" for row in rows if row.get("expected_id")], authorization_state="expected_inventory_only"))

@network_api.get("/sites/<site_id>/drift")
def drift(site_id):
    result = NetworkMappingService(_db()).drift(site_id)
    return jsonify(_with_metadata(result, source_state=result.get("source_state", "unavailable"), freshness=result.get("freshness"), coverage=result.get("coverage", "unavailable"), evidence_refs=[str(item.get("source_packet_id") or item.get("asset_id")) for item in result.get("items", []) if item.get("source_packet_id") or item.get("asset_id")], authorization_state="observed"))

@network_api.get("/sites/<site_id>/topology")
def topology(site_id):
    from ..services.topology import TopologyService
    edges = TopologyService(_db()).graph_for_site(site_id)
    nodes = {}
    for edge in edges:
        for node_id, node_type in ((edge.get("from_id"), edge.get("from_type")), (edge.get("to_id"), edge.get("to_type"))):
            if node_id and node_type:
                nodes.setdefault((node_id, node_type), {"node_id": node_id, "node_type": node_type, "site_id": site_id, "source_edge_ids": []})["source_edge_ids"].append(edge.get("edge_id"))
    return jsonify(_with_metadata({"nodes": list(nodes.values()), "edges": edges}, source_state="projected" if edges else "empty", freshness="observation_time" if edges else None, coverage="projected_edges" if edges else "no_topology_edges", evidence_refs=[ref for edge in edges for ref in edge.get("evidence_refs", [])], authorization_state="observed"))

def _path_response(site_id, node_id, target_id=None, max_hops=20):
    from ..services.topology import TopologyService
    path = TopologyService(_db()).path_from_node(site_id, node_id, target_id=target_id, max_hops=max_hops)
    return jsonify({
        "node_id": node_id,
        "target_id": target_id,
        "path": path,
        "source_state": "projected" if path else "empty",
        "freshness": "per_edge" if path else None,
        "coverage": "bounded_observed_path" if path else "no_observed_path",
        "evidence_refs": [edge["edge_id"] for edge in path if edge.get("edge_id")],
        "authorization_state": "observed",
    })


@network_api.get("/sites/<site_id>/path")
def generic_path_query(site_id):
    node_id = request.args.get("from_id") or request.args.get("node_id") or request.args.get("asset_id")
    if not node_id:
        return jsonify({"error": "from_id is required"}), 400
    try:
        max_hops = int(request.args.get("max_hops", "20"))
        return _path_response(site_id, node_id, request.args.get("to_id"), max_hops)
    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400


@network_api.get("/sites/<site_id>/path/<asset_id>")
def generic_path(site_id, asset_id):
    try:
        return _path_response(site_id, asset_id, request.args.get("to_id"), int(request.args.get("max_hops", "20")))
    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400

def register_network_routes(app): app.register_blueprint(network_api)
