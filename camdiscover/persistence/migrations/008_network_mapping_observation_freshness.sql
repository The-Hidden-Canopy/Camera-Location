-- Preserve freshness on interface and address observations as the generic
-- network model grows beyond the original camera-oriented schema.
ALTER TABLE network_interfaces ADD COLUMN freshness_seconds INTEGER;
ALTER TABLE network_addresses ADD COLUMN freshness_seconds INTEGER;
