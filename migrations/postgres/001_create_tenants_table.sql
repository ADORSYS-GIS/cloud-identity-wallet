CREATE TABLE IF NOT EXISTS tenants (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    created_at BIGINT NOT NULL  -- Unix epoch seconds
);

CREATE INDEX IF NOT EXISTS idx_tenants_name ON tenants(name);
