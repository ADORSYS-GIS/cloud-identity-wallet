CREATE TABLE IF NOT EXISTS tenants (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,

    key_algorithm VARCHAR(16) NOT NULL,
    key_material BYTEA NOT NULL,

    created_at BIGINT NOT NULL
);
