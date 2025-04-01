
-- db/incident_logs.sql
CREATE TABLE incident_logs (
    id SERIAL PRIMARY KEY,
    threat_type VARCHAR(50) NOT NULL,
    description TEXT NOT NULL,
    response_plan TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);