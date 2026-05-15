CREATE TABLE IF NOT EXISTS credential_display_metadata (
    credential_id VARCHAR(36) NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    tenant_id VARCHAR(36) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    display BLOB NOT NULL,
    issuer_name VARCHAR(255) NOT NULL,
    credential_type VARCHAR(255) NOT NULL,

    PRIMARY KEY (credential_id)
);

CREATE INDEX idx_cred_display_tenant_id ON credential_display_metadata(tenant_id);
