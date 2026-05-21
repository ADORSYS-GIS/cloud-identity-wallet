CREATE TABLE IF NOT EXISTS data_encryption_keys (
    id VARCHAR(32) PRIMARY KEY,
    master_id VARCHAR(32) NOT NULL,
    encrypted_key BLOB NOT NULL,
    algorithm VARCHAR(50) NOT NULL,
    created_at BIGINT NOT NULL,
    last_accessed BIGINT,

    INDEX idx_dek_master_id (master_id),
    INDEX idx_dek_last_accessed (last_accessed)
);
