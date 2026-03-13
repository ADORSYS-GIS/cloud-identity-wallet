-- Credential storage schema for cloud-wallet-openid4vc.
-- Run as a one-shot migration via sqlx::raw_sql on service startup.
--
-- Design: envelope encryption with per-record DEKs.
-- Only the claims JSON is encrypted. All metadata needed for filtering
-- and display is plaintext.

CREATE TABLE IF NOT EXISTS credentials (
    -- ── Identity ──────────────────────────────────────────────────────────────
    id                          TEXT        PRIMARY KEY,

    -- ── Common plaintext metadata (filterable / displayable) ─────────────────
    issuer                      TEXT        NOT NULL,
    subject                     TEXT        NOT NULL,
    credential_type             TEXT        NOT NULL,
    issued_at                   TIMESTAMPTZ NOT NULL,
    expires_at                  TIMESTAMPTZ,                -- NULL → does not expire

    -- Wallet lifecycle status: 'active' | 'revoked' | 'suspended'
    status                      TEXT        NOT NULL DEFAULT 'active',

    -- ── Status list reference (revocation checks, plaintext) ─────────────────
    status_list_url             TEXT,       -- NULL if no issuer status list
    status_list_index           BIGINT,

    -- ── Encrypted payload (DEK envelope encryption) ───────────────────────────
    --
    -- encrypted_dek:
    --   nonce (12 B) ‖ AES-256-GCM(raw_dek_32B, aad=id) ‖ tag (16 B)
    --
    -- encrypted_claims:
    --   nonce ‖ AES-256-GCM(claims_json) ‖ tag

    encrypted_dek               BYTEA       NOT NULL,
    encrypted_claims            BYTEA       NOT NULL
);

-- ── Performance indexes ──────────────────────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_cred_issuer    ON credentials (issuer);
CREATE INDEX IF NOT EXISTS idx_cred_subject   ON credentials (subject);
CREATE INDEX IF NOT EXISTS idx_cred_status    ON credentials (status);
CREATE INDEX IF NOT EXISTS idx_cred_type      ON credentials (credential_type);

CREATE INDEX IF NOT EXISTS idx_cred_expires_at
    ON credentials (expires_at) WHERE expires_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_cred_status_list_url
    ON credentials (status_list_url) WHERE status_list_url IS NOT NULL;
