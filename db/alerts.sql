-- db/alerts.sql
CREATE TABLE alert_logs (
    id SERIAL PRIMARY KEY,
    threat VARCHAR(255) NOT NULL,
    risk_score INTEGER NOT NULL,
    alert_type VARCHAR(50) NOT NULL, -- 'email' or 'webhook'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);