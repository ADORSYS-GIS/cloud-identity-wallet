CREATE TABLE IF NOT EXISTS credential_display_metadata (
    -- One display record per credential (credential_id is globally unique).
    -- tenant_id is for cascade deletes and tenant-scoped joins only,
    -- not for per-tenant overrides of the same credential.
    credential_id VARCHAR(36) NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    tenant_id VARCHAR(36) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    display BYTEA NOT NULL,
    issuer_name VARCHAR(255) NOT NULL,
    credential_type VARCHAR(255) NOT NULL,

    PRIMARY KEY (credential_id)
);

CREATE INDEX IF NOT EXISTS idx_cred_display_tenant_id ON credential_display_metadata(tenant_id);
