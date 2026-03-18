CREATE TABLE data_encryption_keys (
    id VARCHAR(32) PRIMARY KEY,
    master_id VARCHAR(32) NOT NULL,
    encrypted_key VARCHAR(255) NOT NULL, -- Base64 encoded
    algorithm VARCHAR(50) NOT NULL,
    created_at BIGINT NOT NULL,          -- Unix epoch seconds
    last_accessed BIGINT                 -- Unix epoch seconds
);

CREATE INDEX idx_dek_master_id ON data_encryption_keys(master_id);
CREATE INDEX idx_dek_last_accessed ON data_encryption_keys(last_accessed);