-- 002_indexes.sql
-- Additional indexes required for reconciliation and handoff lookups.

CREATE INDEX IF NOT EXISTS idx_observations_site_time ON observations(site_id, observed_at);
CREATE INDEX IF NOT EXISTS idx_observations_session ON observations(session_id);
CREATE INDEX IF NOT EXISTS idx_endpoints_onvif_uuid ON device_endpoints(onvif_uuid);
CREATE INDEX IF NOT EXISTS idx_endpoints_profile ON device_endpoints(network_profile_id);
CREATE INDEX IF NOT EXISTS idx_network_profiles_site ON network_profiles(site_id);
CREATE INDEX IF NOT EXISTS idx_network_profiles_subnet ON network_profiles(subnet);
CREATE INDEX IF NOT EXISTS idx_physical_locations_site ON physical_locations(site_id);
CREATE INDEX IF NOT EXISTS idx_physical_locations_zone ON physical_locations(zone);
CREATE INDEX IF NOT EXISTS idx_camera_assets_qr ON camera_assets(qr_code);
CREATE INDEX IF NOT EXISTS idx_camera_assets_hardware_id ON camera_assets(hardware_id);
CREATE INDEX IF NOT EXISTS idx_change_jobs_site ON change_jobs(site_id);
