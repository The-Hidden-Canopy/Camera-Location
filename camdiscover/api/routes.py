"""Thin Flask routes for site/profile/location and reconciliation."""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request

from ..persistence.db import get_database
from ..services.site_service import SiteService
from ..services.reconciliation import ReconciliationService
from ..services.rebuild import NetworkRebuildService
from ..services.merge import MergeService
from ..services.handoff import HandoffService
from ..services.location_verification import LocationVerificationService

from ..services.topology import TopologyService

api = Blueprint("asset_api", __name__, url_prefix="/api")


def _db():
    return current_app.config.get("CAMDISCOVER_DB") or get_database()


def _orchestrator():
    return current_app.config.get("DISCOVERY_ORCHESTRATOR")


def _discovery_service():
    return current_app.config.get("DISCOVERY_SERVICE")


# ─── Site routes ─────────────────────────────────────────────────────────────

@api.route("/sites", methods=["GET"])
def list_sites():
    svc = SiteService(_db())
    return jsonify(svc.list_sites())


@api.route("/sites", methods=["POST"])
def create_site():
    body = request.json or {}
    svc = SiteService(_db())
    try:
        site = svc.create_site(body)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify(site.to_dict()), 201


@api.route("/sites/<site_id>", methods=["GET"])
def get_site(site_id: str):
    svc = SiteService(_db())
    try:
        return jsonify(svc.get_site(site_id, include_children=True))
    except KeyError as e:
        return jsonify({"error": str(e)}), 404


@api.route("/sites/<site_id>/network-profiles", methods=["POST"])
def add_network_profile(site_id: str):
    body = request.json or {}
    svc = SiteService(_db())
    try:
        profile = svc.add_network_profile(site_id, body)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except KeyError as e:
        return jsonify({"error": str(e)}), 404
    return jsonify(profile.to_dict()), 201


@api.route("/sites/<site_id>/locations", methods=["POST"])
def add_location(site_id: str):
    body = request.json or {}
    svc = SiteService(_db())
    try:
        loc = svc.add_location(site_id, body)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except KeyError as e:
        return jsonify({"error": str(e)}), 404
    return jsonify(loc.to_dict()), 201


# ─── Reconciliation routes ───────────────────────────────────────────────────

@api.route("/sites/<site_id>/reconcile", methods=["GET"])
def reconcile_status(site_id: str):
    """Return the four reconciliation queues for a site."""
    db = _db()
    svc = ReconciliationService(db)
    current_ips = []
    for ep in db.conn.execute(
        """SELECT e.ip FROM device_endpoints e
           JOIN camera_assets a ON e.asset_id = a.asset_id
           WHERE a.site_id=? AND e.is_current=1""",
        (site_id,)
    ):
        current_ips.append(ep["ip"])
    return jsonify(svc.reconciliation_queues(site_id, current_ips))


@api.route("/sites/<site_id>/assets", methods=["GET"])
def list_assets(site_id: str):
    from ..persistence.repos import AssetRepo
    assets = AssetRepo(_db()).list_for_site(site_id)
    return jsonify([a.to_dict() for a in assets])


@api.route("/inventory/current", methods=["GET"])
def current_inventory():
    """Return persisted current inventory for the active or requested site."""
    site_id = request.args.get("site_id") or None
    svc = _discovery_service()
    if svc is None:
        return jsonify([])
    return jsonify(svc.current_inventory(site_id=site_id))


@api.route("/sites/<site_id>/assets/<asset_id>/verify", methods=["POST"])
def verify_asset_location(site_id: str, asset_id: str):
    """Operator-confirmed physical attribution."""
    from ..persistence.repos import AssetRepo, LocationRepo
    from ..domain.models import Observation
    from ..persistence.db import new_uuid

    body = request.json or {}
    db = _db()
    asset_repo = AssetRepo(db)
    location_repo = LocationRepo(db)

    asset = asset_repo.get(asset_id)
    if not asset or asset.site_id != site_id:
        return jsonify({"error": "asset not found"}), 404

    location_id = body.get("location_id")
    if location_id:
        loc = location_repo.get(location_id)
        if not loc or loc.site_id != site_id:
            return jsonify({"error": "location not found"}), 404
        asset.expected_location_id = location_id
        asset.human_confirmed = True
        asset.installed_status = "verified"
        asset_repo.save(asset)

    obs = Observation(
        observation_id=new_uuid(),
        site_id=site_id,
        asset_id=asset_id,
        kind="physical_verification",
        detail=body.get("detail", "Operator confirmed physical location."),
        source="operator",
        weight=100,
    )
    from ..persistence.repos import ObservationRepo
    ObservationRepo(db).save(obs)

    return jsonify(asset.to_dict())


@api.route("/sites/<site_id>/assets/<asset_id>/verify-physical", methods=["POST"])
def verify_asset_physical(site_id: str, asset_id: str):
    """Record physical QR/location verification with optional installer photos."""
    body = request.json or {}
    svc = LocationVerificationService(_db())
    try:
        result = svc.verify_asset(site_id, asset_id, **body)
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    return jsonify(result)


# ─── Installer handoff ───────────────────────────────────────────────────────

@api.route("/sites/<site_id>/handoff/export", methods=["POST"])
def export_handoff(site_id: str):
    svc = HandoffService(_db())
    try:
        path = svc.export(site_id)
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    return jsonify({"path": str(path), "filename": path.name})


@api.route("/handoff/import", methods=["POST"])
def import_handoff():
    if "file" not in request.files:
        return jsonify({"error": "file is required"}), 400
    file = request.files["file"]
    from pathlib import Path as _Path
    import tempfile
    tmp = _Path(tempfile.gettempdir()) / file.filename
    file.save(str(tmp))
    svc = HandoffService(_db())
    try:
        new_site_id = svc.import_package(tmp)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"site_id": new_site_id})


@api.route("/sites/<site_id>/topology", methods=["GET"])
def get_topology(site_id: str):
    return jsonify(TopologyService(_db()).graph_for_site(site_id))


@api.route("/sites/<site_id>/topology", methods=["POST"])
def add_topology_edge(site_id: str):
    body = request.json or {}
    try:
        edge = TopologyService(_db()).add_edge(
            site_id=site_id,
            from_id=body.get("from_id", ""),
            from_type=body.get("from_type", ""),
            to_id=body.get("to_id", ""),
            to_type=body.get("to_type", ""),
            relation=body.get("relation", ""),
            detail=body.get("detail", ""),
            verified=bool(body.get("verified", False)),
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify(edge.to_dict()), 201


@api.route("/sites/<site_id>/topology/import", methods=["POST"])
def import_topology(site_id: str):
    body = request.json or {}
    result = TopologyService(_db()).import_csv(site_id, body.get("csv", ""))
    return jsonify(result)


@api.route("/sites/<site_id>/assets/<asset_id>/path", methods=["GET"])
def camera_path(site_id: str, asset_id: str):
    return jsonify(TopologyService(_db()).path_to_camera(site_id, asset_id))


def register_routes(app):
    """Register the asset/reconciliation blueprint on a Flask app."""
    app.register_blueprint(api)


# ─── Network rebuild reconciliation ──────────────────────────────────────────

@api.route("/sites/<site_id>/rebuild", methods=["POST"])
def rebuild_reconcile(site_id: str):
    """Run a reconciliation of the latest discovery against the site inventory.

    Body: {"device_ips": ["192.168.88.34", ...]} — optional list of IPs to
    reconcile. If omitted, all current endpoints for the site are used.
    """
    from ..orchestrator import DiscoveryOrchestrator

    db = _db()
    body = request.json or {}
    device_ips = body.get("device_ips")

    orchestrator = _orchestrator() or DiscoveryOrchestrator()
    devices = []
    if device_ips:
        for ip in device_ips:
            dev = orchestrator.devices.get(ip)
            if dev:
                devices.append(dev)
    else:
        devices = orchestrator.discovered_devices

    svc = NetworkRebuildService(db)
    report = svc.reconcile_session(site_id, devices)
    svc.persist_report(report)
    return jsonify(report.to_dict())


@api.route("/sites/<site_id>/rebuild/confirm", methods=["POST"])
def confirm_rebuild_match(site_id: str):
    body = request.json or {}
    asset_id = body.get("asset_id")
    endpoint_id = body.get("endpoint_id")
    discovered_ip = body.get("discovered_ip")
    if not asset_id:
        return jsonify({"error": "asset_id required"}), 400
    svc = MergeService(_db())
    try:
        result = svc.confirm_match(site_id, asset_id, endpoint_id, discovered_ip)
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    return jsonify(result)


@api.route("/sites/<site_id>/assets/merge", methods=["POST"])
def merge_assets(site_id: str):
    body = request.json or {}
    keep = body.get("keep_asset_id")
    remove = body.get("remove_asset_id")
    if not keep or not remove:
        return jsonify({"error": "keep_asset_id and remove_asset_id required"}), 400
    svc = MergeService(_db())
    try:
        result = svc.merge_assets(site_id, keep, remove)
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    return jsonify(result)


@api.route("/sites/<site_id>/endpoints/<endpoint_id>/split", methods=["POST"])
def split_endpoint(site_id: str, endpoint_id: str):
    body = request.json or {}
    body.setdefault("site_id", site_id)
    svc = MergeService(_db())
    try:
        result = svc.split_endpoint_to_asset(endpoint_id, body)
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    return jsonify(result)
