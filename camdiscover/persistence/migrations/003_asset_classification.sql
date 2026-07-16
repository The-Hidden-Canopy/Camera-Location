-- 003_asset_classification.sql
-- Add richer durable asset classification without renaming the table yet.

ALTER TABLE camera_assets ADD COLUMN asset_class TEXT DEFAULT 'unknown_endpoint';
ALTER TABLE camera_assets ADD COLUMN operational_role TEXT DEFAULT 'unknown';
ALTER TABLE camera_assets ADD COLUMN criticality TEXT DEFAULT 'normal';
ALTER TABLE camera_assets ADD COLUMN reset_risk TEXT DEFAULT 'moderate';
ALTER TABLE camera_assets ADD COLUMN human_confirmed INTEGER DEFAULT 0;

UPDATE camera_assets
SET asset_class = COALESCE((
    SELECT CASE e.device_class
        WHEN 'camera' THEN 'camera'
        WHEN 'nvr' THEN 'nvr'
        WHEN 'bridge' THEN 'wireless_bridge'
        WHEN 'switch' THEN 'managed_switch'
        WHEN 'router' THEN 'router_firewall'
        WHEN 'server' THEN 'server_nas'
        WHEN 'printer' THEN 'printer'
        ELSE 'unknown_endpoint'
    END
    FROM device_endpoints e
    WHERE e.asset_id = camera_assets.asset_id AND e.is_current = 1
    ORDER BY e.last_seen DESC
    LIMIT 1
), 'unknown_endpoint')
WHERE asset_class IS NULL OR asset_class = '';

UPDATE camera_assets
SET operational_role = CASE asset_class
    WHEN 'camera' THEN 'camera_endpoint'
    WHEN 'nvr' THEN 'recorder'
    WHEN 'wireless_bridge' THEN 'remote_bridge'
    WHEN 'access_point' THEN 'backhaul_hub'
    WHEN 'poe_switch' THEN 'poe_source'
    WHEN 'router_firewall' THEN 'network_gateway'
    WHEN 'legacy_video_appliance' THEN 'legacy_controller'
    ELSE 'unknown'
END
WHERE operational_role IS NULL OR operational_role = '';

UPDATE camera_assets
SET reset_risk = CASE asset_class
    WHEN 'nvr' THEN 'critical'
    WHEN 'access_point' THEN 'critical'
    WHEN 'wireless_bridge' THEN 'critical'
    WHEN 'router_firewall' THEN 'critical'
    WHEN 'poe_switch' THEN 'high'
    WHEN 'managed_switch' THEN 'high'
    WHEN 'server_nas' THEN 'high'
    WHEN 'legacy_video_appliance' THEN 'high'
    WHEN 'camera' THEN 'moderate'
    WHEN 'iot_controller' THEN 'moderate'
    ELSE 'moderate'
END
WHERE reset_risk IS NULL OR reset_risk = '';

UPDATE camera_assets
SET criticality = CASE
    WHEN reset_risk = 'critical' THEN 'critical'
    WHEN asset_class IN ('poe_switch', 'managed_switch', 'server_nas') THEN 'high'
    WHEN asset_class IN ('workstation', 'printer') THEN 'low'
    ELSE 'normal'
END
WHERE criticality IS NULL OR criticality = '';

UPDATE camera_assets
SET human_confirmed = CASE
    WHEN installed_status = 'verified' THEN 1
    ELSE 0
END
WHERE human_confirmed IS NULL OR human_confirmed = 0;
