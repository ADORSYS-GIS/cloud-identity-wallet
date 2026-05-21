CREATE TABLE IF NOT EXISTS credentials (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    issuer VARCHAR(255) NOT NULL,
    subject VARCHAR(255),

    credential_types VARCHAR(1024) NOT NULL,
    format VARCHAR(32) NOT NULL,
    external_id VARCHAR(255),

    status VARCHAR(32) NOT NULL,
    issued_at BIGINT NOT NULL,
    valid_until BIGINT,

    is_revoked INTEGER NOT NULL DEFAULT 0,
    status_location VARCHAR(255),
    status_index BIGINT,

    raw_credential BLOB NOT NULL,
    payload_encrypted INTEGER NOT NULL DEFAULT 0,

    UNIQUE (tenant_id, id),
    INDEX idx_credentials_tenant_id (tenant_id),
    INDEX idx_credentials_tenant_format (tenant_id, format),
    INDEX idx_credentials_tenant_status (tenant_id, status),
    INDEX idx_credentials_tenant_issuer (tenant_id, issuer),
    INDEX idx_credentials_tenant_subject (tenant_id, subject),
    INDEX idx_credentials_tenant_issued_at (tenant_id, issued_at DESC)
);
