-- Credential storage schema for cloud-wallet-openid4vc.
-- Run as a one-shot migration via sqlx::raw_sql on service startup.
--
-- Design: envelope encryption with per-record DEKs.
-- Only format-specific credential bytes (token/issuer_signed/claims) are
-- encrypted. All metadata needed for filtering and display is plaintext.

CREATE TABLE IF NOT EXISTS credentials (
    -- ── Identity ──────────────────────────────────────────────────────────────
    id                          TEXT        PRIMARY KEY,

    -- ── Common plaintext metadata (filterable / displayable) ─────────────────
    issuer                      TEXT        NOT NULL,
    subject                     TEXT        NOT NULL,
    issued_at                   TIMESTAMPTZ NOT NULL,
    expires_at                  TIMESTAMPTZ,                -- NULL → does not expire
    credential_configuration_id TEXT        NOT NULL,

    -- Wallet lifecycle status: 'active' | 'revoked' | 'suspended'
    status                      TEXT        NOT NULL DEFAULT 'active',

    -- OpenID4VCI format identifier: 'dc+sd-jwt' | 'mso_mdoc' | 'jwt_vc_json'
    format                      TEXT        NOT NULL,

    -- ── Format-specific plaintext metadata (one column set applies per row) ──
    -- SD-JWT VC (dc+sd-jwt)
    vct                         TEXT,       -- verifiable credential type URI

    -- ISO mdoc (mso_mdoc)
    doc_type                    TEXT,       -- e.g. "org.iso.18013.5.1.mDL"

    -- W3C VC JWT (jwt_vc_json) — stored as JSON array string
    credential_type             TEXT,       -- JSON array, e.g. '["VerifiableCredential","IDCard"]'

    -- ── Status list reference (revocation checks, plaintext) ─────────────────
    status_list_url             TEXT,       -- NULL if no issuer status list
    status_list_index           BIGINT,

    -- ── Encrypted payload (DEK envelope encryption) ───────────────────────────
    --
    -- encrypted_dek:
    --   nonce (12 B) ‖ AES-256-GCM(raw_dek_32B, aad=id) ‖ tag (16 B)
    --
    -- encrypted_payload:
    --   dc+sd-jwt  → nonce ‖ AES-256-GCM(token_bytes + claims_json) ‖ tag
    --   mso_mdoc   → nonce ‖ AES-256-GCM(issuer_signed + namespaces_json) ‖ tag
    --   jwt_vc_json → nonce ‖ AES-256-GCM(token_bytes + credential_subject_json) ‖ tag

    encrypted_dek               BYTEA       NOT NULL,
    encrypted_payload           BYTEA       NOT NULL
);

-- ── Performance indexes ──────────────────────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_cred_issuer    ON credentials (issuer);
CREATE INDEX IF NOT EXISTS idx_cred_subject   ON credentials (subject);
CREATE INDEX IF NOT EXISTS idx_cred_status    ON credentials (status);
CREATE INDEX IF NOT EXISTS idx_cred_format    ON credentials (format);
CREATE INDEX IF NOT EXISTS idx_cred_cfg_id    ON credentials (credential_configuration_id);

CREATE INDEX IF NOT EXISTS idx_cred_expires_at
    ON credentials (expires_at) WHERE expires_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_cred_status_list_url
    ON credentials (status_list_url) WHERE status_list_url IS NOT NULL;

-- Format-specific plaintext columns for display / query filtering
CREATE INDEX IF NOT EXISTS idx_cred_vct      ON credentials (vct)      WHERE vct IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_cred_doc_type ON credentials (doc_type) WHERE doc_type IS NOT NULL;
