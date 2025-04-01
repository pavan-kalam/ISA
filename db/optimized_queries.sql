-- /db/optimized_queries.sql
CREATE INDEX idx_user_username ON users(username);
CREATE INDEX idx_threatdata_description ON threat_data(description);
CREATE INDEX idx_threatdata_created_at ON threat_data(created_at DESC);