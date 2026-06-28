-- 001_initial.sql
-- Initial durable schema for Camera-Location.
-- Intentionally normalized: assets, endpoints, locations, and evidence are
-- separate so IP changes, MAC moves, and replacements are observable events.

-- Migration tracking
CREATE TABLE IF NOT EXISTS _migrations (
    version     TEXT PRIMARY KEY,
    applied_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- A scoped place of work (farm, facility, site, customer location)
CREATE TABLE IF NOT EXISTS sites (
    site_id     TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    customer    TEXT,
    address     TEXT,
    local_coords TEXT,
    notes       TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Network segment definitions used by a site
CREATE TABLE IF NOT EXISTS network_profiles (
    profile_id  TEXT PRIMARY KEY,
    site_id     TEXT NOT NULL REFERENCES sites(site_id) ON DELETE CASCADE,
    label       TEXT,
    subnet      TEXT NOT NULL,
    gateway     TEXT,
    vlan_id     INTEGER,
    dhcp_mode   TEXT DEFAULT 'unknown',   -- static | dhcp | reserved | unknown
    method      TEXT DEFAULT 'auto',       -- auto | route | secondary_ip | vlan | direct_nic | manual
    radio_zone  TEXT,
    nvr_segment INTEGER DEFAULT 0,
    internet_blocked INTEGER DEFAULT 1,
    notes       TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Physical places where cameras may be located
CREATE TABLE IF NOT EXISTS physical_locations (
    location_id TEXT PRIMARY KEY,
    site_id     TEXT NOT NULL REFERENCES sites(site_id) ON DELETE CASCADE,
    label       TEXT NOT NULL,           -- "North Gate / Pole 3"
    zone        TEXT,                    -- office | gate | field | barn | pump | road | perimeter | ...
    map_x       REAL,
    map_y       REAL,
    map_source  TEXT,
    direction   TEXT,
    notes       TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Durable camera identity (the thing that does not change when the IP does)
CREATE TABLE IF NOT EXISTS camera_assets (
    asset_id    TEXT PRIMARY KEY,
    site_id     TEXT REFERENCES sites(site_id) ON DELETE SET NULL,
    asset_tag   TEXT,
    qr_code     TEXT,
    serial      TEXT,
    manufacturer TEXT,
    model       TEXT,
    hardware_id TEXT,
    onvif_uuid  TEXT,
    installed_status TEXT DEFAULT 'planned', -- planned | installed | unverified | verified | moved | replaced | retired
    expected_location_id TEXT REFERENCES physical_locations(location_id) ON DELETE SET NULL,
    notes       TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- A network sighting / current endpoint of a camera asset
CREATE TABLE IF NOT EXISTS device_endpoints (
    endpoint_id TEXT PRIMARY KEY,
    asset_id    TEXT REFERENCES camera_assets(asset_id) ON DELETE CASCADE,
    ip          TEXT,
    ip_history  TEXT,                    -- JSON array of previous IPs
    mac         TEXT,
    mac_history TEXT,                    -- JSON array of previous MACs
    onvif_uuid  TEXT,
    rtsp_url    TEXT,
    onvif_url   TEXT,
    web_url     TEXT,
    firmware    TEXT,
    network_profile_id TEXT REFERENCES network_profiles(profile_id) ON DELETE SET NULL,
    subnet      TEXT,
    first_seen  TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen   TEXT NOT NULL DEFAULT (datetime('now')),
    is_current  INTEGER DEFAULT 1,
    device_class TEXT DEFAULT 'unknown'
);

-- Topology relationships: camera -> switch port -> uplink/radio -> NVR channel, PoE source, etc.
CREATE TABLE IF NOT EXISTS topology_edges (
    edge_id     TEXT PRIMARY KEY,
    site_id     TEXT REFERENCES sites(site_id) ON DELETE CASCADE,
    from_id     TEXT NOT NULL,
    from_type   TEXT NOT NULL,           -- asset | switch | radio | nvr | poe | endpoint
    to_id       TEXT NOT NULL,
    to_type     TEXT NOT NULL,
    relation    TEXT NOT NULL,           -- connected_to | powered_by | nvr_channel | uplink_to | trunked_to
    detail      TEXT,
    since       TEXT NOT NULL DEFAULT (datetime('now')),
    until       TEXT,
    verified    INTEGER DEFAULT 0
);

-- Append-only discovery and operator evidence
CREATE TABLE IF NOT EXISTS observations (
    observation_id  TEXT PRIMARY KEY,
    site_id         TEXT REFERENCES sites(site_id) ON DELETE SET NULL,
    endpoint_id     TEXT REFERENCES device_endpoints(endpoint_id) ON DELETE SET NULL,
    asset_id        TEXT REFERENCES camera_assets(asset_id) ON DELETE SET NULL,
    kind            TEXT NOT NULL,       -- e.g. arp_seen, onvif_probe_match_nvt, network_move
    detail          TEXT,
    source          TEXT,                -- passive_wsdiscovery | active_onvif | arp | operator | nvr_export
    sensor_id       TEXT,
    interface       TEXT,
    capture_position TEXT,
    visibility_limit TEXT,
    weight          INTEGER DEFAULT 0,
    raw             TEXT,
    observed_at     TEXT NOT NULL DEFAULT (datetime('now')),
    session_id      TEXT
);

-- Staged network changes (IP readdress, credential swap, network move)
CREATE TABLE IF NOT EXISTS change_jobs (
    job_id          TEXT PRIMARY KEY,
    site_id         TEXT REFERENCES sites(site_id) ON DELETE SET NULL,
    endpoint_id     TEXT REFERENCES device_endpoints(endpoint_id) ON DELETE SET NULL,
    asset_id        TEXT REFERENCES camera_assets(asset_id) ON DELETE SET NULL,
    kind            TEXT NOT NULL,       -- ip_change | credential_change | network_move
    proposed        TEXT NOT NULL,       -- JSON
    prior           TEXT,                -- JSON snapshot
    status          TEXT DEFAULT 'draft', -- draft | proposed | approved | executing | verifying | success | failure | rollback
    approval_phrase TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    approved_at     TEXT,
    executed_at     TEXT,
    verified_at     TEXT,
    result          TEXT,
    rollback_state  TEXT                 -- JSON
);

-- Windows network state changes that must survive process crash
CREATE TABLE IF NOT EXISTS network_change_journal (
    journal_id      TEXT PRIMARY KEY,
    operation_id    TEXT NOT NULL,
    session_id      TEXT,
    interface_name  TEXT NOT NULL,
    ip              TEXT NOT NULL,
    prefix_len      INTEGER,
    action          TEXT NOT NULL,       -- add_secondary_ip | remove_secondary_ip | add_temp_ip
    completed       INTEGER DEFAULT 0,
    user_id         TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    completed_at    TEXT
);

-- Installer handoff packages
CREATE TABLE IF NOT EXISTS installer_handoffs (
    handoff_id      TEXT PRIMARY KEY,
    site_id         TEXT REFERENCES sites(site_id) ON DELETE CASCADE,
    export_path     TEXT,
    package_json    TEXT,                -- JSON metadata
    unresolved      TEXT,                -- JSON array
    checklist       TEXT,                -- JSON accepted checklist
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    exported_at     TEXT
);

-- Credential profiles (secrets stored separately / encrypted)
CREATE TABLE IF NOT EXISTS credential_profiles (
    profile_id      TEXT PRIMARY KEY,
    site_id         TEXT REFERENCES sites(site_id) ON DELETE CASCADE,
    label           TEXT,
    username        TEXT,
    -- NEVER store plaintext passwords here; keep only a reference.
    secret_ref      TEXT,
    scope           TEXT,                -- JSON array of subnets/IPs/tags
    vendor_hint     TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_assets_site ON camera_assets(site_id);
CREATE INDEX IF NOT EXISTS idx_assets_serial ON camera_assets(serial);
CREATE INDEX IF NOT EXISTS idx_assets_mac ON camera_assets(asset_id); -- join via endpoint; intentional
CREATE INDEX IF NOT EXISTS idx_assets_onvif_uuid ON camera_assets(onvif_uuid);
CREATE INDEX IF NOT EXISTS idx_endpoints_asset ON device_endpoints(asset_id);
CREATE INDEX IF NOT EXISTS idx_endpoints_ip ON device_endpoints(ip);
CREATE INDEX IF NOT EXISTS idx_endpoints_mac ON device_endpoints(mac);
CREATE INDEX IF NOT EXISTS idx_endpoints_current ON device_endpoints(is_current);
CREATE INDEX IF NOT EXISTS idx_observations_endpoint ON observations(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_observations_asset ON observations(asset_id);
CREATE INDEX IF NOT EXISTS idx_observations_kind ON observations(kind);
CREATE INDEX IF NOT EXISTS idx_observations_time ON observations(observed_at);
CREATE INDEX IF NOT EXISTS idx_topology_site ON topology_edges(site_id);
CREATE INDEX IF NOT EXISTS idx_change_jobs_status ON change_jobs(status);
