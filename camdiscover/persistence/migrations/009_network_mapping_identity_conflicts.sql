-- Preserve contradictory identity evidence without merging assets.
CREATE TABLE IF NOT EXISTS network_identity_conflicts (
    conflict_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    scope_id TEXT NOT NULL REFERENCES network_scope_grants(scope_id),
    conflict_kind TEXT NOT NULL,
    identity_value TEXT NOT NULL,
    existing_asset_id TEXT NOT NULL,
    reported_asset_id TEXT NOT NULL,
    source TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    observed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_network_identity_conflicts_site
    ON network_identity_conflicts(site_id, observed_at);
