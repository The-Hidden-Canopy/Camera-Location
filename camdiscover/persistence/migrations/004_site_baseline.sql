ALTER TABLE sites ADD COLUMN authorized_classes TEXT DEFAULT '[]';
ALTER TABLE sites ADD COLUMN expected_camera_count INTEGER DEFAULT 0;
ALTER TABLE sites ADD COLUMN expected_nvr_channels INTEGER DEFAULT 0;
ALTER TABLE sites ADD COLUMN expected_subnets TEXT DEFAULT '[]';
ALTER TABLE sites ADD COLUMN expected_gateways TEXT DEFAULT '[]';
ALTER TABLE sites ADD COLUMN known_old_subnets TEXT DEFAULT '[]';
ALTER TABLE sites ADD COLUMN unauthorized_device_alerts INTEGER DEFAULT 1;
