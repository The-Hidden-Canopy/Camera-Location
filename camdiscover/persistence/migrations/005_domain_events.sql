-- Durable append-only governance events for state-changing workflows.
CREATE TABLE IF NOT EXISTS domain_events (
    event_id       TEXT PRIMARY KEY,
    site_id        TEXT REFERENCES sites(site_id) ON DELETE SET NULL,
    aggregate_type TEXT NOT NULL,
    aggregate_id   TEXT NOT NULL,
    event_type     TEXT NOT NULL,
    from_state     TEXT,
    to_state       TEXT,
    actor          TEXT NOT NULL,
    justification  TEXT NOT NULL,
    payload        TEXT,
    occurred_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_domain_events_aggregate
    ON domain_events(aggregate_type, aggregate_id, occurred_at);
CREATE INDEX IF NOT EXISTS idx_domain_events_site
    ON domain_events(site_id, occurred_at);
