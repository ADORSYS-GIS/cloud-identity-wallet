//! Per-credential envelope encryption using Data Encryption Keys (DEKs).
//!
//! # Design
//!
//! Each credential is encrypted with a unique randomly-generated 256-bit
//! **DEK** (Data Encryption Key) using AES-256-GCM. The DEK itself is
//! wrapped by a caller-supplied **KEK** (Key Encryption Key), also using
//! AES-256-GCM. The credential ID is used as AAD when wrapping the DEK,
//! cryptographically binding the DEK to that exact record.
//!
//! Encryption is **format-aware**: the [`EncryptedPayload`] enum mirrors
//! [`CredentialPayload`] and encrypts only the sensitive fields (the raw
//! token / issuer-signed binary / claims), while non-sensitive type
//! identifiers (`vct`, `doc_type`, `credential_type`) remain plaintext.
//!
//! # Layout on disk
//!
//! ```text
//! encrypted_dek     = nonce (12 B) ‖ AES-GCM(raw_dek_32B, aad=id) ‖ tag (16 B)
//!
//! DcSdJwt:
//!   encrypted_token = nonce (12 B) ‖ AES-GCM(token + claims JSON) ‖ tag (16 B)
//! MsoMdoc:
//!   encrypted_data  = nonce (12 B) ‖ AES-GCM(issuer_signed + namespaces JSON) ‖ tag (16 B)
//! JwtVcJson:
//!   encrypted_token = nonce (12 B) ‖ AES-GCM(token + credential_subject JSON) ‖ tag (16 B)
//! ```

use cloud_wallet_crypto::aead::{Algorithm, Key, NONCE_LENGTH};
use cloud_wallet_crypto::rand;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::errors::StoreError;
use crate::models::{
    Credential, CredentialId, CredentialPayload, CredentialStatus, MsoMdocCredential,
    SdJwtCredential, StatusReference, W3cVcJwtCredential,
};
use crate::repository::CredentialFilter;
use crate::schema::CredentialFormatIdentifier;

// ── KEK ───────────────────────────────────────────────────────────────────────

/// Key Encryption Key — wraps/unwraps per-credential DEKs.
///
/// Load from a KMS, hardware token, or environment variable.
/// The underlying key bytes are zeroized on drop.
pub struct Kek(Key);

impl Kek {
    /// Create a KEK from 32 raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, StoreError> {
        Key::new(Algorithm::AesGcm256, bytes)
            .map(Self)
            .map_err(|e| StoreError::Encryption(format!("invalid KEK: {e}")))
    }

    /// Generate a random KEK.
    pub fn generate() -> Result<Self, StoreError> {
        Key::generate(Algorithm::AesGcm256)
            .map(Self)
            .map_err(|e| StoreError::Encryption(format!("KEK generation failed: {e}")))
    }
}

// ── EncryptedPayload ──────────────────────────────────────────────────────────

/// Format-aware encrypted credential payload.
///
/// Mirrors [`CredentialPayload`] but replaces each format's sensitive fields
/// (raw token / issuer-signed binary / claims) with their AES-256-GCM
/// ciphertext. Non-sensitive type identifiers remain in plaintext so they
/// are available for display and filtering without decryption.
#[derive(Debug, Clone)]
pub enum EncryptedPayload {
    /// SD-JWT VC (dc+sd-jwt)
    DcSdJwt {
        /// Verifiable credential type — plaintext, safe for display/filtering.
        vct: String,
        /// `nonce ‖ AES-GCM(token_bytes + claims_json) ‖ tag`
        encrypted_token: Vec<u8>,
    },
    /// ISO 18013-5 mdoc (mso_mdoc)
    MsoMdoc {
        /// Document type — plaintext (e.g. `"org.iso.18013.5.1.mDL"`).
        doc_type: String,
        /// `nonce ‖ AES-GCM(issuer_signed_bytes + namespaces_json) ‖ tag`
        encrypted_data: Vec<u8>,
    },
    /// W3C VC JWT (jwt_vc_json)
    JwtVcJson {
        /// VC type array — plaintext (e.g. `["VerifiableCredential", "IDCard"]`).
        credential_type: Vec<String>,
        /// `nonce ‖ AES-GCM(token_bytes + credential_subject_json) ‖ tag`
        encrypted_token: Vec<u8>,
    },
}

impl EncryptedPayload {
    /// The format identifier for this encrypted payload.
    pub fn format_identifier(&self) -> CredentialFormatIdentifier {
        match self {
            Self::DcSdJwt { .. } => CredentialFormatIdentifier::DcSdJwt,
            Self::MsoMdoc { .. } => CredentialFormatIdentifier::MsoMdoc,
            Self::JwtVcJson { .. } => CredentialFormatIdentifier::JwtVcJson,
        }
    }
}

// ── StoredCredential ──────────────────────────────────────────────────────────

/// The persisted form of a [`Credential`].
///
/// All fields needed for filtering and display remain in plaintext.
/// Only the format-specific credential blob (token / issuer-signed / claims)
/// is encrypted via the [`EncryptedPayload`] enum.
#[derive(Debug, Clone)]
pub struct StoredCredential {
    /// Wallet-internal ID — plaintext, used as AAD for DEK wrapping.
    pub id: CredentialId,
    /// Issuer URL — plaintext for filtering.
    pub issuer: String,
    /// Subject identifier — plaintext for filtering.
    pub subject: String,
    /// Issuance timestamp — plaintext for filtering.
    pub issued_at: OffsetDateTime,
    /// Optional expiry — plaintext for filtering.
    pub expires_at: Option<OffsetDateTime>,
    /// Credential configuration reference — plaintext for filtering.
    pub credential_configuration_id: String,
    /// Wallet lifecycle status — plaintext for filtering.
    pub status: CredentialStatus,
    /// Issuer status-list reference — plaintext for revocation checks.
    pub status_reference: Option<StatusReference>,
    /// Format-aware encrypted credential blob.
    pub encrypted_payload: EncryptedPayload,
    /// `nonce ‖ AES-GCM(raw_dek_32B, aad=id) ‖ tag` — KEK-wrapped DEK.
    pub encrypted_dek: Vec<u8>,
}

impl StoredCredential {
    /// Returns `true` if this stored record matches all conditions in `filter`.
    ///
    /// Filtering operates entirely on plaintext metadata — no decryption needed.
    pub fn matches_filter(&self, filter: &CredentialFilter) -> bool {
        if let Some(ref issuer) = filter.issuer {
            if &self.issuer != issuer {
                return false;
            }
        }
        if let Some(ref subject) = filter.subject {
            if &self.subject != subject {
                return false;
            }
        }
        if let Some(ref status) = filter.status {
            if &self.status != status {
                return false;
            }
        }
        if let Some(ref cfg_id) = filter.credential_configuration_id {
            if &self.credential_configuration_id != cfg_id {
                return false;
            }
        }
        if let Some(active_at) = filter.active_at {
            if let Some(expires) = self.expires_at {
                if expires <= active_at {
                    return false;
                }
            }
        }
        true
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Encrypt a [`Credential`] into a [`StoredCredential`] using a fresh DEK
/// wrapped by `kek`.
///
/// The format is preserved — only the sensitive fields are encrypted per format.
pub fn encrypt_credential(
    kek: &Kek,
    credential: &Credential,
) -> Result<StoredCredential, StoreError> {
    // 1. Generate fresh 32-byte DEK
    let mut dek_raw = [0u8; 32];
    rand::fill_bytes(&mut dek_raw)
        .map_err(|e| StoreError::Encryption(format!("DEK generation failed: {e}")))?;

    let dek = Key::new(Algorithm::AesGcm256, dek_raw)
        .map_err(|e| StoreError::Encryption(format!("DEK construction failed: {e}")))?;

    // 2. Encrypt the format-specific sensitive data
    let encrypted_payload = encrypt_payload(&dek, &credential.credential)?;

    // 3. Wrap DEK with KEK; bind to credential ID via AAD
    let encrypted_dek = aead_seal(&kek.0, &dek_raw, credential.id.as_bytes())?;

    Ok(StoredCredential {
        id: credential.id.clone(),
        issuer: credential.issuer.clone(),
        subject: credential.subject.clone(),
        issued_at: credential.issued_at,
        expires_at: credential.expires_at,
        credential_configuration_id: credential.credential_configuration_id.clone(),
        status: credential.status.clone(),
        status_reference: credential.status_reference.clone(),
        encrypted_payload,
        encrypted_dek,
    })
}

/// Decrypt a [`StoredCredential`] back into a plain [`Credential`].
pub fn decrypt_credential(kek: &Kek, stored: &StoredCredential) -> Result<Credential, StoreError> {
    // 1. Unwrap DEK
    let mut dek_blob = stored.encrypted_dek.clone();
    let dek_raw = aead_open(&kek.0, &mut dek_blob, stored.id.as_bytes())?;

    let dek = Key::new(Algorithm::AesGcm256, dek_raw.to_vec())
        .map_err(|e| StoreError::Decryption(format!("DEK reconstruction failed: {e}")))?;

    // 2. Decrypt the format-specific payload
    let credential_payload = decrypt_payload(&dek, &stored.encrypted_payload)?;

    Ok(Credential {
        id: stored.id.clone(),
        issuer: stored.issuer.clone(),
        subject: stored.subject.clone(),
        issued_at: stored.issued_at,
        expires_at: stored.expires_at,
        credential_configuration_id: stored.credential_configuration_id.clone(),
        credential: credential_payload,
        status: stored.status.clone(),
        status_reference: stored.status_reference.clone(),
    })
}

// ── Format-specific encrypt/decrypt ──────────────────────────────────────────

fn encrypt_payload(dek: &Key, payload: &CredentialPayload) -> Result<EncryptedPayload, StoreError> {
    match payload {
        CredentialPayload::DcSdJwt(c) => {
            // Encrypt token + claims together; keep vct plaintext
            #[derive(Serialize)]
            struct SdJwtSensitive<'a> {
                token: &'a str,
                claims: &'a serde_json::Value,
            }
            let plaintext = serde_json::to_vec(&SdJwtSensitive {
                token: &c.token,
                claims: &c.claims,
            })
            .map_err(|e| StoreError::Encryption(format!("SD-JWT serialisation failed: {e}")))?;

            Ok(EncryptedPayload::DcSdJwt {
                vct: c.vct.clone(),
                encrypted_token: aead_seal(dek, &plaintext, b"")?,
            })
        }

        CredentialPayload::MsoMdoc(c) => {
            // Encrypt issuer_signed + namespaces together; keep doc_type plaintext
            #[derive(Serialize)]
            struct MdocSensitive<'a> {
                issuer_signed: &'a str,
                namespaces: &'a std::collections::HashMap<String, serde_json::Value>,
            }
            let plaintext = serde_json::to_vec(&MdocSensitive {
                issuer_signed: &c.issuer_signed,
                namespaces: &c.namespaces,
            })
            .map_err(|e| StoreError::Encryption(format!("mdoc serialisation failed: {e}")))?;

            Ok(EncryptedPayload::MsoMdoc {
                doc_type: c.doc_type.clone(),
                encrypted_data: aead_seal(dek, &plaintext, b"")?,
            })
        }

        CredentialPayload::JwtVcJson(c) => {
            // Encrypt token + credential_subject; keep credential_type plaintext
            #[derive(Serialize)]
            struct JwtVcSensitive<'a> {
                token: &'a str,
                credential_subject: &'a serde_json::Value,
            }
            let plaintext = serde_json::to_vec(&JwtVcSensitive {
                token: &c.token,
                credential_subject: &c.credential_subject,
            })
            .map_err(|e| StoreError::Encryption(format!("JWT VC serialisation failed: {e}")))?;

            Ok(EncryptedPayload::JwtVcJson {
                credential_type: c.credential_type.clone(),
                encrypted_token: aead_seal(dek, &plaintext, b"")?,
            })
        }
    }
}

fn decrypt_payload(dek: &Key, enc: &EncryptedPayload) -> Result<CredentialPayload, StoreError> {
    match enc {
        EncryptedPayload::DcSdJwt {
            vct,
            encrypted_token,
        } => {
            #[derive(Deserialize)]
            struct SdJwtSensitive {
                token: String,
                claims: serde_json::Value,
            }
            let mut blob = encrypted_token.clone();
            let plaintext = aead_open(dek, &mut blob, b"")?;
            let sensitive: SdJwtSensitive = serde_json::from_slice(plaintext).map_err(|e| {
                StoreError::Decryption(format!("SD-JWT deserialisation failed: {e}"))
            })?;

            Ok(CredentialPayload::DcSdJwt(SdJwtCredential {
                token: sensitive.token,
                vct: vct.clone(),
                claims: sensitive.claims,
            }))
        }

        EncryptedPayload::MsoMdoc {
            doc_type,
            encrypted_data,
        } => {
            #[derive(Deserialize)]
            struct MdocSensitive {
                issuer_signed: String,
                namespaces: std::collections::HashMap<String, serde_json::Value>,
            }
            let mut blob = encrypted_data.clone();
            let plaintext = aead_open(dek, &mut blob, b"")?;
            let sensitive: MdocSensitive = serde_json::from_slice(plaintext)
                .map_err(|e| StoreError::Decryption(format!("mdoc deserialisation failed: {e}")))?;

            Ok(CredentialPayload::MsoMdoc(MsoMdocCredential {
                doc_type: doc_type.clone(),
                namespaces: sensitive.namespaces,
                issuer_signed: sensitive.issuer_signed,
            }))
        }

        EncryptedPayload::JwtVcJson {
            credential_type,
            encrypted_token,
        } => {
            #[derive(Deserialize)]
            struct JwtVcSensitive {
                token: String,
                credential_subject: serde_json::Value,
            }
            let mut blob = encrypted_token.clone();
            let plaintext = aead_open(dek, &mut blob, b"")?;
            let sensitive: JwtVcSensitive = serde_json::from_slice(plaintext).map_err(|e| {
                StoreError::Decryption(format!("JWT VC deserialisation failed: {e}"))
            })?;

            Ok(CredentialPayload::JwtVcJson(W3cVcJwtCredential {
                token: sensitive.token,
                credential_type: credential_type.clone(),
                credential_subject: sensitive.credential_subject,
            }))
        }
    }
}

// ── Internal AEAD helpers ─────────────────────────────────────────────────────

/// AES-256-GCM seal. Output: `nonce (12 B) ‖ ciphertext ‖ tag (16 B)`.
fn aead_seal(key: &Key, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, StoreError> {
    let mut nonce = [0u8; NONCE_LENGTH];
    rand::fill_bytes(&mut nonce)
        .map_err(|e| StoreError::Encryption(format!("nonce generation failed: {e}")))?;

    let mut buf = plaintext.to_vec();
    key.encrypt_append_tag(&nonce, aad, &mut buf)
        .map_err(|e| StoreError::Encryption(format!("AES-GCM seal failed: {e}")))?;

    let mut out = Vec::with_capacity(NONCE_LENGTH + buf.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&buf);
    Ok(out)
}

/// AES-256-GCM open. Input: `nonce (12 B) ‖ ciphertext ‖ tag (16 B)`.
fn aead_open<'a>(key: &Key, blob: &'a mut Vec<u8>, aad: &[u8]) -> Result<&'a [u8], StoreError> {
    if blob.len() < NONCE_LENGTH {
        return Err(StoreError::Decryption(
            "blob too short to contain nonce".into(),
        ));
    }
    let nonce: [u8; NONCE_LENGTH] = blob[..NONCE_LENGTH].try_into().unwrap();
    let result = key
        .decrypt(&nonce, aad, &mut blob[NONCE_LENGTH..])
        .map_err(|e| StoreError::Decryption(format!("AES-GCM open failed: {e}")))?;
    Ok(result as &[u8])
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{MsoMdocCredential, W3cVcJwtCredential};
    use serde_json::json;
    use std::collections::HashMap;
    use time::{Duration, OffsetDateTime};

    fn make_sd_jwt() -> Credential {
        Credential::new(
            "https://issuer.example.com",
            "sub-1234",
            OffsetDateTime::now_utc(),
            Some(OffsetDateTime::now_utc() + Duration::days(365)),
            "identity_credential",
            CredentialPayload::DcSdJwt(SdJwtCredential {
                token: "header.payload.sig~disclosure~".into(),
                vct: "https://credentials.example.com/identity".into(),
                claims: json!({ "given_name": "Alice", "family_name": "Smith" }),
            }),
        )
        .expect("valid SD-JWT credential")
    }

    fn make_mdoc() -> Credential {
        let mut namespaces = HashMap::new();
        namespaces.insert(
            "org.iso.18013.5.1".into(),
            json!({ "family_name": "Smith", "given_name": "Alice" }),
        );
        Credential::new(
            "https://dmv.example.com",
            "sub-5678",
            OffsetDateTime::now_utc(),
            None,
            "mDL_credential",
            CredentialPayload::MsoMdoc(MsoMdocCredential {
                doc_type: "org.iso.18013.5.1.mDL".into(),
                namespaces,
                issuer_signed: "base64url-encoded-issuer-signed-data".into(),
            }),
        )
        .expect("valid mdoc credential")
    }

    fn make_w3c_vc() -> Credential {
        Credential::new(
            "https://university.example.com",
            "sub-9012",
            OffsetDateTime::now_utc(),
            Some(OffsetDateTime::now_utc() + Duration::days(730)),
            "diploma_credential",
            CredentialPayload::JwtVcJson(W3cVcJwtCredential {
                token: "eyJ.eyJ.sig".into(),
                credential_type: vec![
                    "VerifiableCredential".into(),
                    "UniversityDegreeCredential".into(),
                ],
                credential_subject: json!({ "degree": { "type": "BachelorDegree", "name": "BSc Computer Science" } }),
            }),
        )
        .expect("valid W3C VC credential")
    }

    // ── Round-trip tests (one per format) ─────────────────────────────────────

    #[test]
    fn sd_jwt_round_trip() {
        let kek = Kek::generate().unwrap();
        let credential = make_sd_jwt();

        let stored = encrypt_credential(&kek, &credential).unwrap();

        // vct must be plaintext
        assert!(
            matches!(&stored.encrypted_payload, EncryptedPayload::DcSdJwt { vct, .. }
            if vct == "https://credentials.example.com/identity")
        );
        // Encrypted blob must contain nonce + ciphertext + tag
        if let EncryptedPayload::DcSdJwt {
            encrypted_token, ..
        } = &stored.encrypted_payload
        {
            assert!(encrypted_token.len() > NONCE_LENGTH + 16);
        }

        let decrypted = decrypt_credential(&kek, &stored).unwrap();
        assert_eq!(decrypted.id, credential.id);
        let claims = decrypted.credential.claims().unwrap();
        assert_eq!(claims["given_name"], "Alice");
    }

    #[test]
    fn mdoc_round_trip() {
        let kek = Kek::generate().unwrap();
        let credential = make_mdoc();

        let stored = encrypt_credential(&kek, &credential).unwrap();

        // doc_type must be plaintext
        assert!(
            matches!(&stored.encrypted_payload, EncryptedPayload::MsoMdoc { doc_type, .. }
            if doc_type == "org.iso.18013.5.1.mDL")
        );

        let decrypted = decrypt_credential(&kek, &stored).unwrap();
        assert_eq!(decrypted.id, credential.id);
        if let CredentialPayload::MsoMdoc(mdoc) = &decrypted.credential {
            assert_eq!(mdoc.doc_type, "org.iso.18013.5.1.mDL");
            assert_eq!(
                mdoc.claims("org.iso.18013.5.1").unwrap()["given_name"],
                "Alice"
            );
        } else {
            panic!("expected MsoMdoc payload");
        }
    }

    #[test]
    fn w3c_vc_round_trip() {
        let kek = Kek::generate().unwrap();
        let credential = make_w3c_vc();

        let stored = encrypt_credential(&kek, &credential).unwrap();

        // credential_type must be plaintext
        assert!(matches!(&stored.encrypted_payload,
            EncryptedPayload::JwtVcJson { credential_type, .. }
            if credential_type.contains(&"UniversityDegreeCredential".to_string())));

        let decrypted = decrypt_credential(&kek, &stored).unwrap();
        assert_eq!(decrypted.id, credential.id);
        if let CredentialPayload::JwtVcJson(vc) = &decrypted.credential {
            assert_eq!(vc.token, "eyJ.eyJ.sig");
        } else {
            panic!("expected JwtVcJson payload");
        }
    }

    // ── Security tests ────────────────────────────────────────────────────────

    #[test]
    fn wrong_kek_fails() {
        let kek = Kek::generate().unwrap();
        let wrong = Kek::generate().unwrap();
        let stored = encrypt_credential(&kek, &make_sd_jwt()).unwrap();
        assert!(matches!(
            decrypt_credential(&wrong, &stored),
            Err(StoreError::Decryption(_))
        ));
    }

    #[test]
    fn tampered_token_fails() {
        let kek = Kek::generate().unwrap();
        let mut stored = encrypt_credential(&kek, &make_sd_jwt()).unwrap();
        if let EncryptedPayload::DcSdJwt {
            ref mut encrypted_token,
            ..
        } = stored.encrypted_payload
        {
            encrypted_token[NONCE_LENGTH] ^= 0xFF;
        }
        assert!(matches!(
            decrypt_credential(&kek, &stored),
            Err(StoreError::Decryption(_))
        ));
    }

    #[test]
    fn tampered_dek_fails() {
        let kek = Kek::generate().unwrap();
        let mut stored = encrypt_credential(&kek, &make_mdoc()).unwrap();
        stored.encrypted_dek[NONCE_LENGTH] ^= 0xFF;
        assert!(matches!(
            decrypt_credential(&kek, &stored),
            Err(StoreError::Decryption(_))
        ));
    }

    #[test]
    fn each_credential_gets_unique_dek() {
        let kek = Kek::generate().unwrap();
        let s1 = encrypt_credential(&kek, &make_sd_jwt()).unwrap();
        let s2 = encrypt_credential(&kek, &make_sd_jwt()).unwrap();
        assert_ne!(s1.encrypted_dek, s2.encrypted_dek);
    }

    #[test]
    fn same_credential_encrypted_twice_has_distinct_ciphertext() {
        let kek = Kek::generate().unwrap();
        let cred = make_sd_jwt();
        let s1 = encrypt_credential(&kek, &cred).unwrap();
        let s2 = encrypt_credential(&kek, &cred).unwrap();
        if let (
            EncryptedPayload::DcSdJwt {
                encrypted_token: t1,
                ..
            },
            EncryptedPayload::DcSdJwt {
                encrypted_token: t2,
                ..
            },
        ) = (&s1.encrypted_payload, &s2.encrypted_payload)
        {
            assert_ne!(t1, t2, "different nonces must produce different ciphertext");
        }
        // Both must still decrypt correctly
        assert_eq!(decrypt_credential(&kek, &s1).unwrap().id, cred.id);
        assert_eq!(decrypt_credential(&kek, &s2).unwrap().id, cred.id);
    }
}
