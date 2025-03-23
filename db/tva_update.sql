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