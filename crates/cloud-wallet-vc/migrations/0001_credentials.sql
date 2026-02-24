
CREATE TABLE IF NOT EXISTS credentials (
    id                          UUID        PRIMARY KEY,
    format                      TEXT        NOT NULL,
    -- 'dc+sd-jwt' | 'mso_mdoc' | 'jwt_vc_json'

    raw_credential              TEXT        NOT NULL,
    -- JWT/SD-JWT compact string, or base64url-encoded mdoc CBOR

    -- ── Issuer / subject ────────────────────────────────────────────────
    iss                         TEXT        NOT NULL,
    sub                         TEXT,

    -- ── Temporal ────────────────────────────────────────────────────────
    iat                         TIMESTAMPTZ NOT NULL,
    exp                         TIMESTAMPTZ,
    -- NULL means the credential does not expire

    -- ── Format-specific type discriminators ─────────────────────────────
    vct                         TEXT,
    -- SD-JWT VC Verifiable Credential Type

    doctype                     TEXT,
    -- ISO mdoc document type

    credential_type             TEXT[],
    -- W3C VCDM @type array

    -- ── Issuance flow ────────────────────────────────────────────────────
    credential_configuration_id  TEXT,

    -- ── Revocation status ───────────────────────────────────────────────
    status_list_url             TEXT,
    status_list_index           INTEGER,

    -- ── Record timestamps ───────────────────────────────────────────────
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Performance indexes ──────────────────────────────────────────────────────
-- Used when evaluating DCQL queries from Verifiers and for lifecycle management.

CREATE INDEX IF NOT EXISTS idx_cred_format
    ON credentials (format);

CREATE INDEX IF NOT EXISTS idx_cred_iss
    ON credentials (iss);

CREATE INDEX IF NOT EXISTS idx_cred_exp
    ON credentials (exp);

CREATE INDEX IF NOT EXISTS idx_cred_sub
    ON credentials (sub);

-- Format-specific type discriminators (partial indexes to keep them lean)
CREATE INDEX IF NOT EXISTS idx_cred_vct
    ON credentials (vct)
    WHERE vct IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_cred_doctype
    ON credentials (doctype)
    WHERE doctype IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_cred_conf_id
    ON credentials (credential_configuration_id)
    WHERE credential_configuration_id IS NOT NULL;
