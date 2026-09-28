CREATE TABLE IF NOT EXISTS network_assets (
    asset_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    asset_type TEXT NOT NULL DEFAULT 'unknown',
    manufacturer TEXT NOT NULL DEFAULT '',
    model TEXT NOT NULL DEFAULT '',
    display_name TEXT NOT NULL DEFAULT '',
    evidence_state TEXT NOT NULL DEFAULT 'observed',
    ambiguity TEXT NOT NULL DEFAULT '[]',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    freshness_seconds INTEGER
);
CREATE INDEX IF NOT EXISTS idx_network_assets_site ON network_assets(site_id, last_seen);

CREATE TABLE IF NOT EXISTS network_interfaces (
    interface_id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL REFERENCES network_assets(asset_id),
    name TEXT NOT NULL DEFAULT '', mac TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT '', observed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS network_addresses (
    observation_id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL REFERENCES network_assets(asset_id),
    interface_id TEXT REFERENCES network_interfaces(interface_id),
    address TEXT NOT NULL, address_family TEXT NOT NULL, hostname TEXT NOT NULL DEFAULT '', dhcp_name TEXT NOT NULL DEFAULT '', dns_name TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT '', first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
    UNIQUE(asset_id, address)
);
CREATE TABLE IF NOT EXISTS network_services (
    observation_id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL REFERENCES network_assets(asset_id),
    transport TEXT NOT NULL, port INTEGER NOT NULL, service_family TEXT NOT NULL DEFAULT 'unknown', limited_fingerprint TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT '', observed_at TEXT NOT NULL, freshness_seconds INTEGER,
    UNIQUE(asset_id, transport, port)
);
CREATE TABLE IF NOT EXISTS network_scope_grants (
    scope_id TEXT PRIMARY KEY, site_id TEXT NOT NULL REFERENCES sites(site_id), cidrs TEXT NOT NULL, purpose TEXT NOT NULL, actor TEXT NOT NULL, authorization_reference TEXT NOT NULL DEFAULT '', authorization_state TEXT NOT NULL DEFAULT 'draft', justification TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_network_scopes_site ON network_scope_grants(site_id, authorization_state);
CREATE TABLE IF NOT EXISTS network_observation_sessions (
    session_id TEXT PRIMARY KEY, collector_id TEXT NOT NULL, collector_type TEXT NOT NULL, scope_id TEXT NOT NULL REFERENCES network_scope_grants(scope_id), observation_methods TEXT NOT NULL, authorization_reference TEXT NOT NULL, started_at TEXT NOT NULL, completed_at TEXT, coverage_state TEXT NOT NULL, failure_state TEXT, resume_cursor TEXT
);
CREATE TABLE IF NOT EXISTS network_packet_queue (
    packet_id TEXT PRIMARY KEY, event_id TEXT NOT NULL UNIQUE, scope_id TEXT NOT NULL, packet_hash TEXT NOT NULL UNIQUE, signature TEXT, payload TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'queued', attempts INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, last_error TEXT
);
