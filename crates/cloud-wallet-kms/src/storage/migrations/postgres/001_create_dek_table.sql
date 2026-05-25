CREATE TABLE IF NOT EXISTS data_encryption_keys (
    id VARCHAR(32) PRIMARY KEY,
    master_id VARCHAR(32) NOT NULL,
    encrypted_key BYTEA NOT NULL,
    algorithm VARCHAR(50) NOT NULL,
    created_at BIGINT NOT NULL,
    last_accessed BIGINT
);

CREATE INDEX IF NOT EXISTS idx_dek_master_id ON data_encryption_keys(master_id);
CREATE INDEX IF NOT EXISTS idx_dek_last_accessed ON data_encryption_keys(last_accessed);
