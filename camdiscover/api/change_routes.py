"""Flask routes for change plans."""

from __future__ import annotations

from flask import Blueprint, jsonify, request

from ..persistence.db import get_database
from ..services.change_plan import ChangePlanService

change_api = Blueprint("change_api", __name__, url_prefix="/api/change-plans")


@change_api.route("", methods=["POST"])
def propose_change():
    body = request.json or {}
    try:
        job = ChangePlanService(get_database()).propose(
            site_id=body.get("site_id"),
            endpoint_id=body.get("endpoint_id"),
            new_ip=body.get("new_ip"),
            mask=body.get("mask"),
            gateway=body.get("gateway"),
            profile_id=body.get("profile_id"),
            user_id=body.get("user_id"),
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify(job.to_dict()), 201


@change_api.route("/<job_id>/approve", methods=["POST"])
def approve_change(job_id: str):
    body = request.json or {}
    try:
        job = ChangePlanService(get_database()).approve(job_id, body.get("confirmation_phrase", ""))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify(job.to_dict())


@change_api.route("/<job_id>/execute", methods=["POST"])
def execute_change(job_id: str):
    svc = ChangePlanService(get_database())
    try:
        job = svc.execute(job_id)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify(job.to_dict())


@change_api.route("/<job_id>", methods=["GET"])
def get_change(job_id: str):
    job = ChangePlanService(get_database())._jobs.get(job_id)
    if not job:
        return jsonify({"error": "not found"}), 404
    return jsonify(job.to_dict())


def register_change_routes(app):
    app.register_blueprint(change_api)
