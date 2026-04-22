CREATE TABLE IF NOT EXISTS credentials (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL,

    issuer VARCHAR(255) NOT NULL,
    subject VARCHAR(255),

    credential_types TEXT NOT NULL,
    format VARCHAR(32) NOT NULL,
    external_id VARCHAR(255),

    status VARCHAR(32) NOT NULL,
    issued_at BIGINT NOT NULL,
    valid_until BIGINT,

    is_revoked INTEGER NOT NULL DEFAULT 0,
    status_location VARCHAR(255),
    status_index BIGINT,REFERENCES tenants(id) ON DELETE CASCADE

    raw_credential BYTEA NOT NULL,
    payload_encrypted INTEGER NOT NULL DEFAULT 0,

    UNIQUE (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_credentials_tenant_id ON credentials(tenant_id);
CREATE INDEX IF NOT EXISTS idx_credentials_tenant_format ON credentials(tenant_id, format);
CREATE INDEX IF NOT EXISTS idx_credentials_tenant_status ON credentials(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_credentials_tenant_issuer ON credentials(tenant_id, issuer);
CREATE INDEX IF NOT EXISTS idx_credentials_tenant_subject ON credentials(tenant_id, subject);
CREATE INDEX IF NOT EXISTS idx_credentials_tenant_issued_at ON credentials(tenant_id, issued_at DESC);
