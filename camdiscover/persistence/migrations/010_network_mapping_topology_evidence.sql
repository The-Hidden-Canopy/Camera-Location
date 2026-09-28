-- Extend the compatibility topology table with evidence-backed network edge
-- metadata. Existing camera edges remain addressable by edge_id and retain
-- their legacy since/until/verified fields.
ALTER TABLE topology_edges ADD COLUMN source_observation_id TEXT;
ALTER TABLE topology_edges ADD COLUMN source_session_id TEXT;
ALTER TABLE topology_edges ADD COLUMN observed_at TEXT;
ALTER TABLE topology_edges ADD COLUMN validity_start TEXT;
ALTER TABLE topology_edges ADD COLUMN validity_end TEXT;
ALTER TABLE topology_edges ADD COLUMN confidence TEXT NOT NULL DEFAULT 'observed';
ALTER TABLE topology_edges ADD COLUMN evidence_state TEXT NOT NULL DEFAULT 'observed';
ALTER TABLE topology_edges ADD COLUMN contradiction_status TEXT NOT NULL DEFAULT 'none';
ALTER TABLE topology_edges ADD COLUMN evidence_refs TEXT NOT NULL DEFAULT '[]';

CREATE INDEX IF NOT EXISTS idx_topology_observed_at
    ON topology_edges(site_id, observed_at);
