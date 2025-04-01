-- db/tva_update.sql

-- Helper function to determine threat type from description
CREATE OR REPLACE FUNCTION get_threat_type(description TEXT) RETURNS TEXT AS $$
BEGIN
    IF LOWER(description) LIKE '%malware%' THEN
        RETURN 'Malware';
    ELSIF LOWER(description) LIKE '%phishing%' THEN
        RETURN 'Phishing';
    ELSIF LOWER(description) LIKE '%ip%' THEN
        RETURN 'IP';
    ELSE
        RETURN 'Other';
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Update likelihood based on recent threat data (last 24 hours)
UPDATE tva_mapping
SET likelihood = CASE
    WHEN (
        SELECT COUNT(*)
        FROM threat_data
        WHERE threat_data.threat_type = get_threat_type(tva_mapping.description)
        AND threat_data.risk_score > 20
        AND threat_data.created_at >= NOW() - INTERVAL '24 hours'
    ) > 0 THEN 5  -- High likelihood if recent high-risk threats exist
    ELSE 3  -- Moderate likelihood otherwise
END;

-- Update impact based on average risk score of recent threats
UPDATE tva_mapping
SET impact = CASE
    WHEN (
        SELECT AVG(threat_data.risk_score)
        FROM threat_data
        WHERE threat_data.threat_type = get_threat_type(tva_mapping.description)
        AND threat_data.created_at >= NOW() - INTERVAL '24 hours'
    ) > 80 THEN 5  -- High impact if average risk is very high
    WHEN (
        SELECT AVG(threat_data.risk_score)
        FROM threat_data
        WHERE threat_data.threat_type = get_threat_type(tva_mapping.description)
        AND threat_data.created_at >= NOW() - INTERVAL '24 hours'
    ) > 50 THEN 4  -- Medium-high impact
    ELSE 3  -- Moderate impact
END;

-- Update threat_name based on description (for existing rows)
UPDATE tva_mapping
SET threat_name = get_threat_type(description);


SELECT * FROM tva_mapping;

SELECT * FROM threats;

SELECT * FROM assets;

SELECT * FROM threat_data;

SELECT * FROM alert_logs;

SELECT * FROM incident_logs;

-- db/alerts.sql
CREATE TABLE alert_logs (
    id SERIAL PRIMARY KEY,
    threat VARCHAR(255) NOT NULL,
    risk_score INTEGER NOT NULL,
    alert_type VARCHAR(50) NOT NULL, -- 'email' or 'webhook'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);



ALTER TABLE users RENAME COLUMN password TO password_hash;

WITH rows_to_delete AS (
    SELECT * FROM alert_logs
    WHERE id > 10
    LIMIT 1430
)
DELETE FROM alert_logs
USING rows_to_delete
WHERE alert_logs.id = rows_to_delete.id;


ALTER TABLE assets ADD COLUMN identifier VARCHAR(255);
UPDATE assets SET identifier = '192.168.1.10' WHERE name = 'Primary Application Server';
UPDATE assets SET identifier = '192.168.1.20' WHERE name = 'Development Workstations';
UPDATE assets SET identifier = '192.168.1.30' WHERE name = 'Network Firewall';
UPDATE assets SET identifier = '192.168.1.40' WHERE name = 'Database Server';
UPDATE assets SET identifier = '192.168.1.50' WHERE name = 'Network Switch';
UPDATE assets SET identifier = 'crm.example.com' WHERE name = 'Customer Management System';
UPDATE assets SET identifier = 'api.example.com' WHERE name = 'Payment Processing API';
UPDATE assets SET identifier = 'db.example.com' WHERE name = 'PostgreSQL Database';
UPDATE assets SET identifier = 'auth.example.com' WHERE name = 'Authentication Service';
UPDATE assets SET identifier = 'dashboard.example.com' WHERE name = 'Monitoring Dashboard';
UPDATE assets SET identifier = 'data.example.com' WHERE name = 'Customer Personal Records';
UPDATE assets SET identifier = 'logs.example.com' WHERE name = 'Financial Transaction Logs';
UPDATE assets SET identifier = 'creds.example.com' WHERE name = 'User Authentication Credentials';
UPDATE assets SET identifier = 'config.example.com' WHERE name = 'System Configuration Files';
UPDATE assets SET identifier = 'audit.example.com' WHERE name = 'Audit Logs';
UPDATE assets SET identifier = 'sysadmins@example.com' WHERE name = 'System Administrators';
UPDATE assets SET identifier = 'dbadmins@example.com' WHERE name = 'Database Administrators';
UPDATE assets SET identifier = 'security@example.com' WHERE name = 'Security Team';
UPDATE assets SET identifier = 'devteam@example.com' WHERE name = 'Development Team';
UPDATE assets SET identifier = 'endusers@example.com' WHERE name = 'End Users';
UPDATE assets SET identifier = 'authprocess.example.com' WHERE name = 'User Authentication Process';
UPDATE assets SET identifier = 'backup.example.com' WHERE name = 'Backup and Recovery';
UPDATE assets SET identifier = 'incident.example.com' WHERE name = 'Incident Response';
UPDATE assets SET identifier = 'change.example.com' WHERE name = 'Change Management';
UPDATE assets SET identifier = 'access.example.com' WHERE name = 'Access Control Management';


UPDATE assets SET identifier = 'example.com' WHERE name = 'Customer Management System';
UPDATE assets SET identifier = 'google.com' WHERE name = 'Payment Processing API';
UPDATE assets SET identifier = 'microsoft.com' WHERE name = 'PostgreSQL Database';
UPDATE assets SET identifier = 'github.com' WHERE name = 'Authentication Service';
UPDATE assets SET identifier = 'wikipedia.org' WHERE name = 'Monitoring Dashboard';
UPDATE assets SET identifier = 'amazon.com' WHERE name = 'Customer Personal Records';
UPDATE assets SET identifier = 'paypal.com' WHERE name = 'Financial Transaction Logs';
UPDATE assets SET identifier = 'cloudflare.com' WHERE name = 'User Authentication Credentials';
UPDATE assets SET identifier = 'stackoverflow.com' WHERE name = 'System Configuration Files';
UPDATE assets SET identifier = 'reddit.com' WHERE name = 'Audit Logs';
UPDATE assets SET identifier = 'security@facebook.com' WHERE name = 'Security Team';
UPDATE assets SET identifier = 'devteam@twitter.com' WHERE name = 'Development Team';


ALTER TABLE alert_logs ADD COLUMN threat_type VARCHAR(50) NOT NULL DEFAULT 'Other';