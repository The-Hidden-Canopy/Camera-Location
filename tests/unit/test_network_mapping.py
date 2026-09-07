from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json

import pytest

from camdiscover.contracts.network_packets import NetworkPacket
from camdiscover.domain.models import CameraAsset, DeviceEndpoint, Site
from camdiscover.domain.network import NetworkInterface, NetworkScopeGrant
from camdiscover.persistence.db import Database
from camdiscover.persistence.repos import AssetRepo, EndpointRepo, SiteRepo
from camdiscover.services.network_mapping import NetworkMappingService


def db(tmp_path):
    result = Database(tmp_path / "network.db")
    result.migrate()
    result.execute("INSERT INTO sites(site_id,name,created_at,updated_at) VALUES(?,?,?,?)", ("site-1", "HQ", datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat()))
    result.conn.commit()
    return result


def test_scope_requires_approval_and_rejects_default_route(tmp_path):
    database = db(tmp_path)
    svc = NetworkMappingService(database)
    with pytest.raises(ValueError, match="default-route"):
        svc.create_scope(site_id="site-1", cidrs=["0.0.0.0/0"], purpose="inventory", actor="op", expires_at=datetime.now(timezone.utc) + timedelta(hours=1), authorization_reference="ticket-1", justification="approved work")
    with pytest.raises(ValueError, match="scope grant not found"):
        svc.record_observation(scope_id="missing", site_id="site-1", asset_id="a", ip="10.0.0.4")


def test_scope_api_persists_scope_id_and_rejects_non_string_expiration(tmp_path):
    from camdiscover.webapp import create_app

    db_path = tmp_path / "api.db"
    database = Database(db_path)
    database.migrate()
    database.execute(
        "INSERT INTO sites(site_id,name,created_at,updated_at) VALUES(?,?,?,?)",
        ("site-1", "HQ", datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat()),
    )
    database.conn.commit()
    app = create_app(db_path=str(db_path), backend_token="test-token", backend_nonce="test-nonce")
    client = app.test_client()
    body = {
        "cidrs": ["10.0.0.0/24"],
        "purpose": "API scope regression",
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        "authorization_reference": "ticket-api",
        "justification": "verify public scope creation",
    }
    response = client.post(
        "/api/network-mapping/sites/site-1/scopes",
        json=body,
        headers={"X-Backend-Token": "test-token"},
    )
    assert response.status_code == 201
    assert response.get_json()["scope_id"]

    malformed = {**body, "expires_at": 123}
    response = client.post(
        "/api/network-mapping/sites/site-1/scopes",
        json=malformed,
        headers={"X-Backend-Token": "test-token"},
    )
    assert response.status_code == 400


def test_network_mapping_api_fails_closed_without_launch_token(tmp_path, monkeypatch):
    from camdiscover.webapp import create_app

    monkeypatch.delenv("CAM_BACKEND_TOKEN", raising=False)
    app = create_app(db_path=str(tmp_path / "no-token.db"))
    response = app.test_client().get("/api/network-mapping/sites/site-1/assets")
    assert response.status_code == 503


def test_expired_scope_cannot_be_approved(tmp_path):
    database = db(tmp_path)
    svc = NetworkMappingService(database)
    grant = svc.create_scope(
        site_id="site-1", cidrs=["10.0.0.0/24"], purpose="expired scope",
        actor="op", expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        authorization_reference="ticket-expired", justification="record expired scope",
    )
    with pytest.raises(ValueError, match="expired"):
        svc.approve_scope(grant.scope_id, actor="approver", justification="reject expired scope")


def test_observation_stays_observed_and_scope_bound(tmp_path):
    database = db(tmp_path)
    svc = NetworkMappingService(database)
    grant = svc.create_scope(site_id="site-1", cidrs=["10.0.0.0/24"], purpose="inventory", actor="op", expires_at=datetime.now(timezone.utc) + timedelta(hours=1), authorization_reference="ticket-1", justification="approved work")
    svc.approve_scope(grant.scope_id, actor="approver", justification="scope reviewed")
    asset = svc.record_observation(scope_id=grant.scope_id, site_id="site-1", asset_id="a", ip="10.0.0.4", asset_type="server", open_ports=[443])
    assert asset.evidence_state == "observed"
    assert database.execute("SELECT COUNT(*) AS n FROM network_services").fetchone()["n"] == 1
    with pytest.raises(ValueError, match="outside"):
        svc.record_observation(scope_id=grant.scope_id, site_id="site-1", asset_id="b", ip="10.0.1.4")


def test_scope_allows_only_one_in_progress_collector_session(tmp_path):
    database = db(tmp_path)
    svc = NetworkMappingService(database)
    grant = svc.create_scope(site_id="site-1", cidrs=["10.0.0.0/24"], purpose="session concurrency", actor="op", expires_at=datetime.now(timezone.utc) + timedelta(hours=1), authorization_reference="ticket-session", justification="approved session concurrency")
    svc.approve_scope(grant.scope_id, actor="approver", justification="scope reviewed")
    session = svc.start_session(scope_id=grant.scope_id, collector_id="collector-1", methods=["passive_arp"])
    with pytest.raises(ValueError, match="active observation session"):
        svc.start_session(scope_id=grant.scope_id, collector_id="collector-2", methods=["passive_arp"])
    svc.finish_session(session.session_id, coverage_state="cancelled", failure_state="test cleanup")
    with pytest.raises(ValueError, match="already finished"):
        svc.finish_session(session.session_id, coverage_state="complete")


def test_identity_conflicts_and_ip_movement_remain_ambiguous(tmp_path):
    database = db(tmp_path)
    svc = NetworkMappingService(database)
    grant = svc.create_scope(site_id="site-1", cidrs=["10.1.0.0/24"], purpose="identity evidence", actor="op", expires_at=datetime.now(timezone.utc) + timedelta(hours=1), authorization_reference="ticket-identity", justification="approved identity evidence")
    svc.approve_scope(grant.scope_id, actor="approver", justification="scope reviewed")

    svc.record_observation(scope_id=grant.scope_id, site_id="site-1", asset_id="asset-a", ip="10.1.0.10", mac="00:11:22:33:44:55")
    svc.record_observation(scope_id=grant.scope_id, site_id="site-1", asset_id="asset-a", ip="10.1.0.11", mac="00:11:22:33:44:55")
    svc.record_observation(scope_id=grant.scope_id, site_id="site-1", asset_id="asset-b", ip="10.1.0.10", mac="00:11:22:33:44:55")
    svc.record_observation(scope_id=grant.scope_id, site_id="site-1", asset_id="asset-c", ip="10.1.0.13", mac="02:11:22:33:44:66")

    assert database.execute("SELECT COUNT(*) AS n FROM network_interfaces WHERE asset_id=?", ("asset-a",)).fetchone()["n"] == 1
    assert database.execute("SELECT COUNT(*) AS n FROM network_addresses WHERE asset_id=?", ("asset-a",)).fetchone()["n"] == 2
    assert database.execute("SELECT COUNT(*) AS n FROM network_identity_conflicts").fetchone()["n"] == 2
    assert "mac_seen_on_multiple_assets" in json.loads(database.execute("SELECT ambiguity FROM network_assets WHERE asset_id=?", ("asset-a",)).fetchone()["ambiguity"])
    assert "locally_administered_or_randomized_mac" in json.loads(database.execute("SELECT ambiguity FROM network_assets WHERE asset_id=?", ("asset-c",)).fetchone()["ambiguity"])


def test_topology_address_node_cannot_escape_approved_scope(tmp_path):
    database = db(tmp_path)
    svc = NetworkMappingService(database)
    grant = svc.create_scope(site_id="site-1", cidrs=["10.1.0.0/24"], purpose="topology boundary", actor="op", expires_at=datetime.now(timezone.utc) + timedelta(hours=1), authorization_reference="ticket-topology", justification="approve topology evidence")
    svc.approve_scope(grant.scope_id, actor="approver", justification="scope reviewed")
    with pytest.raises(ValueError, match="outside"):
        svc.add_scoped_topology_edge(scope_id=grant.scope_id, site_id="site-1", from_id="10.1.0.4", from_type="address", to_id="10.2.0.1", to_type="gateway", relation="routes_through", justification="reject out of scope edge")


def test_topology_cannot_reference_legacy_camera_asset_from_another_site(tmp_path):
    database = db(tmp_path)
    SiteRepo(database).save(Site(site_id="site-2", name="Remote"))
    AssetRepo(database).save(CameraAsset(asset_id="legacy-camera", site_id="site-2"))
    svc = NetworkMappingService(database)
    grant = svc.create_scope(site_id="site-1", cidrs=["10.2.0.0/24"], purpose="legacy topology boundary", actor="op", expires_at=datetime.now(timezone.utc) + timedelta(hours=1), authorization_reference="ticket-legacy-topology", justification="approve legacy topology boundary")
    svc.approve_scope(grant.scope_id, actor="approver", justification="scope reviewed")
    with pytest.raises(ValueError, match="another site"):
        svc.add_scoped_topology_edge(scope_id=grant.scope_id, site_id="site-1", from_id="legacy-camera", from_type="asset", to_id="10.2.0.4", to_type="address", relation="connected_to", justification="reject legacy cross-site edge")


def test_import_cannot_duplicate_legacy_camera_asset_from_another_site(tmp_path):
    database = db(tmp_path)
    SiteRepo(database).save(Site(site_id="site-2", name="Remote"))
    AssetRepo(database).save(CameraAsset(asset_id="legacy-camera", site_id="site-2"))
    svc = NetworkMappingService(database)
    grant = svc.create_scope(site_id="site-1", cidrs=["10.2.0.0/24"], purpose="legacy import boundary", actor="op", expires_at=datetime.now(timezone.utc) + timedelta(hours=1), authorization_reference="ticket-legacy-import", justification="approve legacy import boundary")
    svc.approve_scope(grant.scope_id, actor="approver", justification="scope reviewed")
    with pytest.raises(ValueError, match="crosses site scope"):
        svc.import_evidence(scope_id=grant.scope_id, site_id="site-1", import_id="legacy-import", kind="dhcp", records=[{"record_id": "r-1", "asset_id": "legacy-camera", "address": "10.2.0.4"}], justification="reject legacy cross-site import")


def test_topology_cannot_reference_legacy_camera_endpoint_ip_from_another_site(tmp_path):
    database = db(tmp_path)
    SiteRepo(database).save(Site(site_id="site-2", name="Remote"))
    AssetRepo(database).save(CameraAsset(asset_id="legacy-camera", site_id="site-2"))
    EndpointRepo(database).save(DeviceEndpoint(endpoint_id="legacy-endpoint", asset_id="legacy-camera", ip="10.3.0.4", ip_history=["10.3.0.3"]))
    svc = NetworkMappingService(database)
    grant = svc.create_scope(site_id="site-1", cidrs=["10.3.0.0/24"], purpose="legacy address boundary", actor="op", expires_at=datetime.now(timezone.utc) + timedelta(hours=1), authorization_reference="ticket-legacy-address", justification="approve legacy address boundary")
    svc.approve_scope(grant.scope_id, actor="approver", justification="scope reviewed")
    with pytest.raises(ValueError, match="another site"):
        svc.add_scoped_topology_edge(scope_id=grant.scope_id, site_id="site-1", from_id="10.3.0.4", from_type="address", to_id="10.3.0.5", to_type="address", relation="connected_to", justification="reject legacy endpoint cross-site edge")
    with pytest.raises(ValueError, match="another site"):
        svc.add_scoped_topology_edge(scope_id=grant.scope_id, site_id="site-1", from_id="10.3.0.3", from_type="address", to_id="10.3.0.5", to_type="address", relation="connected_to", justification="reject legacy endpoint history edge")


def test_packet_hash_signature_and_tamper_detection():
    packet = NetworkPacket.create(event_type="NetworkObservationEvent", payload={"asset": {"asset_id": "a"}}, source_system="Camera-Location", source_surface="electron", tenant_id="org-1", facility_id="site-1", collector_id="c-1", scope_id="s-1", evidence_refs=["obs-1"], ambiguity=["identity_unverified"], freshness="observed", signature_key=b"secret")
    assert packet.verify(b"secret", require_signature=True)
    packet.envelope["payload"]["asset"]["asset_id"] = "tampered"
    assert not packet.verify(b"secret", require_signature=True)


def test_network_interface_rejects_naive_observation_time():
    with pytest.raises(ValueError, match="timezone-aware"):
        NetworkInterface("iface-1", "asset-1", observed_at=datetime.now())


def test_observation_rolls_back_when_domain_event_cannot_be_appended(tmp_path, monkeypatch):
    database = db(tmp_path)
    svc = NetworkMappingService(database)
    grant = svc.create_scope(site_id="site-1", cidrs=["10.0.0.0/24"], purpose="inventory", actor="op", expires_at=datetime.now(timezone.utc) + timedelta(hours=1), authorization_reference="ticket-1", justification="approved work")
    svc.approve_scope(grant.scope_id, actor="approver", justification="scope reviewed")

    def fail_event(*_args, **_kwargs):
        raise RuntimeError("event store unavailable")

    monkeypatch.setattr("camdiscover.services.network_mapping.append_domain_event", fail_event)
    with pytest.raises(RuntimeError, match="event store unavailable"):
        svc.record_observation(scope_id=grant.scope_id, site_id="site-1", asset_id="rollback-check", ip="10.0.0.9")
    assert database.execute("SELECT COUNT(*) AS n FROM network_assets").fetchone()["n"] == 0


def _projection_packet(secret_key=b"secret", *, event_type="AuthorizedDeviceSnapshot"):
    packet = NetworkPacket.create(event_type="NetworkObservationEvent", payload={"assets": []}, source_system="RegOS", source_surface="web-console", tenant_id="org-1", facility_id="site-1", collector_id="regos", scope_id="regos-scope", evidence_refs=["regos:snapshot:1"], ambiguity=["trust_not_assigned"], freshness="declared")
    body = packet.to_dict()
    body["event_type"] = event_type
    body["payload"] = {"snapshot_id": "snapshot-1", "assets": [{"asset_id": "expected-1", "asset_type": "switch", "expected_state": "required"}], "scopes": [{"scope_id": "regos-scope", "cidrs": ["10.80.0.0/24"], "purpose": "reference only"}]}
    unsigned = {key: value for key, value in body.items() if key not in {"packet_hash", "signature"}}
    body["packet_hash"] = hashlib.sha256(json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    body["signature"] = hmac.new(secret_key, body["packet_hash"].encode(), hashlib.sha256).hexdigest()
    return body


def test_imported_infrastructure_evidence_is_bounded_and_idempotent(tmp_path):
    database = db(tmp_path)
    svc = NetworkMappingService(database)
    grant = svc.create_scope(site_id="site-1", cidrs=["10.80.0.0/24"], purpose="import evidence", actor="op", expires_at=datetime.now(timezone.utc) + timedelta(hours=1), authorization_reference="ticket-import", justification="approved import")
    svc.approve_scope(grant.scope_id, actor="approver", justification="scope reviewed")
    first = svc.import_evidence(scope_id=grant.scope_id, site_id="site-1", import_id="import-1", kind="lldp", collector_id="collector-1", justification="import switch neighbor evidence", records=[{"record_id": "r1", "asset_id": "host-1", "ip": "10.80.0.12", "mac": "00:11:22:33:44:55", "peer_id": "switch-1", "peer_type": "asset", "services": [{"transport": "tcp", "port": 443, "service_family": "https", "limited_fingerprint": "tls"}]}])
    records = [{"record_id": "r1", "asset_id": "host-1", "ip": "10.80.0.12", "mac": "00:11:22:33:44:55", "peer_id": "switch-1", "peer_type": "asset", "services": [{"transport": "tcp", "port": 443, "service_family": "https", "limited_fingerprint": "tls"}]}]
    second = svc.import_evidence(scope_id=grant.scope_id, site_id="site-1", import_id="import-1", kind="lldp", collector_id="collector-1", justification="replay import evidence", records=records)
    assert first["status"] == "complete"
    assert second["import_id"] == "import-1"
    assert database.execute("SELECT COUNT(*) AS n FROM network_assets").fetchone()["n"] == 1
    assert database.execute("SELECT COUNT(*) AS n FROM topology_edges").fetchone()["n"] == 1
    assert database.execute("SELECT COUNT(*) AS n FROM network_services").fetchone()["n"] == 1
    edge = database.execute("SELECT source_observation_id,observed_at,evidence_state,evidence_refs FROM topology_edges").fetchone()
    assert edge["source_observation_id"]
    assert edge["observed_at"]
    assert edge["evidence_state"] == "observed"
    assert json.loads(edge["evidence_refs"])
    with pytest.raises(ValueError, match="different evidence"):
        svc.import_evidence(
            scope_id=grant.scope_id, site_id="site-1", import_id="import-1",
            kind="lldp", collector_id="collector-1", justification="reject changed replay",
            records=[{"record_id": "r2", "asset_id": "host-2"}],
        )
    with pytest.raises(ValueError, match="different evidence"):
        svc.import_evidence(
            scope_id=grant.scope_id, site_id="site-1", import_id="import-1",
            kind="lldp", collector_id="collector-1", justification="reject empty replay",
            records=[],
        )


def test_signed_authorized_snapshot_stays_expected_only(tmp_path, monkeypatch):
    database = db(tmp_path)
    monkeypatch.setenv("CAM_NETWORK_PACKET_SIGNING_KEY", "snapshot-secret")
    svc = NetworkMappingService(database)
    packet = _projection_packet(b"snapshot-secret")
    receipt = svc.apply_authorized_snapshot(site_id="site-1", envelope=packet)
    replay = svc.apply_authorized_snapshot(site_id="site-1", envelope=packet)
    assert receipt["snapshot_id"] == "snapshot-1"
    assert replay["packet_hash"] == receipt["packet_hash"]
    assert database.execute("SELECT COUNT(*) AS n FROM network_expected_assets").fetchone()["n"] == 1
    assert database.execute("SELECT COUNT(*) AS n FROM network_assets").fetchone()["n"] == 0
    assert database.execute("SELECT expected_state FROM network_expected_scopes").fetchone()["expected_state"] == "reference_only"


def test_corporate_snapshot_requires_distinct_regos_credential(tmp_path, monkeypatch):
    database = db(tmp_path)
    packet = _projection_packet(b"collector-only-secret")
    monkeypatch.setenv("CORPORATE_COLLECTOR_MODE", "1")
    monkeypatch.setenv("CAM_NETWORK_PACKET_SIGNING_KEY", "collector-only-secret")
    monkeypatch.delenv("CAM_NETWORK_REGOS_SIGNING_KEY", raising=False)
    monkeypatch.delenv("CAM_NETWORK_REGOS_SIGNING_KEY_REF", raising=False)
    with pytest.raises(PermissionError, match="signature"):
        NetworkMappingService(database).apply_authorized_snapshot(site_id="site-1", envelope=packet)


def test_expired_authorized_snapshot_is_rejected(tmp_path, monkeypatch):
    database = db(tmp_path)
    monkeypatch.setenv("CAM_NETWORK_PACKET_SIGNING_KEY", "snapshot-expiration-secret")
    packet = _projection_packet(b"snapshot-expiration-secret")
    packet["expires_at"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat().replace("+00:00", "Z")
    unsigned = {key: value for key, value in packet.items() if key not in {"packet_hash", "signature"}}
    packet["packet_hash"] = hashlib.sha256(json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    packet["signature"] = hmac.new(b"snapshot-expiration-secret", packet["packet_hash"].encode(), hashlib.sha256).hexdigest()
    with pytest.raises(ValueError, match="expired"):
        NetworkMappingService(database).apply_authorized_snapshot(site_id="site-1", envelope=packet)


def test_packet_export_requires_scope_site_and_corporate_signing_credential(tmp_path, monkeypatch):
    database = db(tmp_path)
    svc = NetworkMappingService(database)
    grant = svc.create_scope(site_id="site-1", cidrs=["10.92.0.0/24"], purpose="packet export", actor="op", expires_at=datetime.now(timezone.utc) + timedelta(hours=1), authorization_reference="ticket-export", justification="approve packet export")
    svc.approve_scope(grant.scope_id, actor="approver", justification="scope reviewed")
    payload = {"assets": [], "evidence_refs": ["session:1"], "freshness": "observed"}
    monkeypatch.setenv("CORPORATE_COLLECTOR_MODE", "1")
    monkeypatch.delenv("CAM_NETWORK_PACKET_SIGNING_KEY", raising=False)
    with pytest.raises(PermissionError, match="signing credential"):
        svc.export_packet(scope_id=grant.scope_id, site_id="site-1", collector_id="collector-1", payload=payload)
    monkeypatch.setenv("CAM_NETWORK_PACKET_SIGNING_KEY", "collector-secret")
    with pytest.raises(ValueError, match="tenant_id"):
        svc.export_packet(scope_id=grant.scope_id, site_id="site-1", collector_id="collector-1", payload=payload)
    with pytest.raises(ValueError, match="site"):
        svc.export_packet(scope_id=grant.scope_id, site_id="other-site", collector_id="collector-1", payload=payload)


def test_import_rejects_secret_fields_and_out_of_scope_address(tmp_path):
    database = db(tmp_path)
    svc = NetworkMappingService(database)
    grant = svc.create_scope(site_id="site-1", cidrs=["10.90.0.0/24"], purpose="import evidence", actor="op", expires_at=datetime.now(timezone.utc) + timedelta(hours=1), authorization_reference="ticket-import", justification="approved import")
    svc.approve_scope(grant.scope_id, actor="approver", justification="scope reviewed")
    with pytest.raises(ValueError, match="prohibited"):
        svc.import_evidence(scope_id=grant.scope_id, site_id="site-1", import_id="secret-import", kind="dhcp", justification="reject secret", records=[{"record_id": "r1", "ip": "10.90.0.5", "password": "not stored"}])
    with pytest.raises(ValueError, match="outside"):
        svc.import_evidence(scope_id=grant.scope_id, site_id="site-1", import_id="outside-import", kind="dhcp", justification="reject outside", records=[{"record_id": "r2", "ip": "10.91.0.5"}])


def test_import_rejects_known_cross_site_topology_peer(tmp_path):
    database = db(tmp_path)
    now = datetime.now(timezone.utc).isoformat()
    database.execute("INSERT INTO sites(site_id,name,created_at,updated_at) VALUES(?,?,?,?)", ("site-2", "Remote", now, now))
    database.execute(
        "INSERT INTO network_assets(asset_id,site_id,asset_type,first_seen,last_seen) VALUES(?,?,?,?,?)",
        ("foreign-switch", "site-2", "switch", now, now),
    )
    database.conn.commit()
    svc = NetworkMappingService(database)
    grant = svc.create_scope(site_id="site-1", cidrs=["10.91.0.0/24"], purpose="topology import", actor="op", expires_at=datetime.now(timezone.utc) + timedelta(hours=1), authorization_reference="ticket-cross-site", justification="approved cross-site boundary")
    svc.approve_scope(grant.scope_id, actor="approver", justification="scope reviewed")
    with pytest.raises(ValueError, match="another site"):
        svc.import_evidence(
            scope_id=grant.scope_id, site_id="site-1", import_id="cross-site-import",
            kind="lldp", justification="reject cross-site topology",
            records=[{"record_id": "r1", "asset_id": "local-host", "peer_id": "foreign-switch"}],
        )
