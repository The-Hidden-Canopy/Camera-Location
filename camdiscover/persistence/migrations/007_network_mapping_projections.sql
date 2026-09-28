CREATE TABLE IF NOT EXISTS network_import_receipts (
    import_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    scope_id TEXT NOT NULL REFERENCES network_scope_grants(scope_id),
    import_kind TEXT NOT NULL,
    source TEXT NOT NULL,
    record_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'complete',
    justification TEXT NOT NULL,
    received_at TEXT NOT NULL,
    failure_state TEXT
);
CREATE INDEX IF NOT EXISTS idx_network_imports_site ON network_import_receipts(site_id, received_at);

CREATE TABLE IF NOT EXISTS network_projection_receipts (
    projection_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    packet_hash TEXT NOT NULL UNIQUE,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    snapshot_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'accepted',
    packet TEXT NOT NULL,
    received_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_network_projections_site ON network_projection_receipts(site_id, received_at);

CREATE TABLE IF NOT EXISTS network_expected_assets (
    expected_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    snapshot_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    asset_type TEXT NOT NULL DEFAULT 'unknown',
    display_name TEXT NOT NULL DEFAULT '',
    expected_state TEXT NOT NULL DEFAULT 'expected',
    scope_id TEXT,
    ambiguity TEXT NOT NULL DEFAULT '[]',
    received_at TEXT NOT NULL,
    UNIQUE(site_id, snapshot_id, asset_id)
);
CREATE INDEX IF NOT EXISTS idx_network_expected_assets_site ON network_expected_assets(site_id, received_at);

CREATE TABLE IF NOT EXISTS network_expected_scopes (
    expected_scope_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    snapshot_id TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    cidrs TEXT NOT NULL DEFAULT '[]',
    purpose TEXT NOT NULL DEFAULT '',
    expected_state TEXT NOT NULL DEFAULT 'reference_only',
    received_at TEXT NOT NULL,
    UNIQUE(site_id, snapshot_id, scope_id)
);
