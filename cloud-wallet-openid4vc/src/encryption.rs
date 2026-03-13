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
//! The normalized `claims` field is encrypted while `credential_type` remains
//! plaintext for filtering and display.

use cloud_wallet_crypto::aead::{Algorithm, Key, NONCE_LENGTH};
use cloud_wallet_crypto::rand;
use time::OffsetDateTime;
use zeroize::Zeroize;

use crate::errors::StoreError;
use crate::models::{
    Binding, Claims, Credential, CredentialId, CredentialMetadata, CredentialStatus,
    CredentialType, StatusReference,
};
use crate::repository::CredentialFilter;

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

// ── StoredCredential ──────────────────────────────────────────────────────────

/// The persisted form of a [`Credential`].
///
/// All fields needed for filtering and display remain in plaintext.
/// Only the `claims` JSON is encrypted.
#[derive(Debug, Clone)]
pub struct StoredCredential {
    /// Wallet-internal ID — plaintext, used as AAD for DEK wrapping.
    pub id: CredentialId,
    /// Issuer URL — plaintext for filtering.
    pub issuer: String,
    /// Subject identifier — plaintext for filtering.
    pub subject: String,
    /// Credential type — plaintext for filtering.
    pub credential_type: CredentialType,
    /// Issuance timestamp — plaintext for filtering.
    pub issued_at: OffsetDateTime,
    /// Optional expiry — plaintext for filtering.
    pub expires_at: Option<OffsetDateTime>,
    /// Wallet lifecycle status — plaintext for filtering.
    pub status: CredentialStatus,
    /// Issuer status-list reference — plaintext for revocation checks.
    pub status_reference: Option<StatusReference>,
    /// Holder key binding info (serialized).
    pub binding: Binding,
    /// Wallet-local metadata (serialized).
    pub metadata: CredentialMetadata,
    /// Encrypted claims JSON: `nonce ‖ AES-GCM(claims_json) ‖ tag`.
    pub encrypted_claims: Vec<u8>,
    /// `nonce ‖ AES-GCM(raw_dek_32B, aad=id) ‖ tag` — KEK-wrapped DEK.
    pub encrypted_dek: Vec<u8>,
}

impl StoredCredential {
    /// Returns `true` if this stored record matches all conditions in `filter`.
    ///
    /// Filtering operates entirely on plaintext metadata — no decryption needed.
    pub fn matches_filter(&self, filter: &CredentialFilter) -> bool {
        if let Some(ref issuer) = filter.issuer
            && &self.issuer != issuer
        {
            return false;
        }
        if let Some(ref subject) = filter.subject
            && &self.subject != subject
        {
            return false;
        }
        if let Some(ref status) = filter.status
            && &self.status != status
        {
            return false;
        }
        if let Some(ref cred_type) = filter.credential_type
            && &self.credential_type != cred_type
        {
            return false;
        }
        if let Some(active_at) = filter.active_at
            && let Some(expires) = self.expires_at
            && expires <= active_at
        {
            return false;
        }
        true
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Encrypt a [`Credential`] into a [`StoredCredential`] using a fresh DEK
/// wrapped by `kek`.
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

    // 2. Encrypt the claims JSON
    let claims_json = serde_json::to_vec(credential.claims.as_value())
        .map_err(|e| StoreError::Encryption(format!("claims serialisation failed: {e}")))?;
    let encrypted_claims = aead_seal(&dek, &claims_json, b"")?;

    // 3. Wrap DEK with KEK; bind to credential ID via AAD
    let encrypted_dek = aead_seal(&kek.0, &dek_raw, credential.id.as_bytes())?;

    // 4. Zeroize the raw DEK bytes (security fix)
    dek_raw.zeroize();

    Ok(StoredCredential {
        id: credential.id.clone(),
        issuer: credential.issuer.clone(),
        subject: credential.subject.clone(),
        credential_type: credential.credential_type.clone(),
        issued_at: credential.issued_at,
        expires_at: credential.expires_at,
        status: credential.status.clone(),
        status_reference: credential.status_reference.clone(),
        binding: credential.binding.clone(),
        metadata: credential.metadata.clone(),
        encrypted_claims,
        encrypted_dek,
    })
}

/// Decrypt a [`StoredCredential`] back into a plain [`Credential`].
pub fn decrypt_credential(kek: &Kek, stored: &StoredCredential) -> Result<Credential, StoreError> {
    // 1. Unwrap DEK
    let mut dek_blob = stored.encrypted_dek.clone();
    let mut dek_raw = aead_open(&kek.0, &mut dek_blob, stored.id.as_bytes())?.to_vec();

    let dek = Key::new(Algorithm::AesGcm256, dek_raw.clone())
        .map_err(|e| StoreError::Decryption(format!("DEK reconstruction failed: {e}")))?;

    // 2. Decrypt the claims
    let mut claims_blob = stored.encrypted_claims.clone();
    let claims_json = aead_open(&dek, &mut claims_blob, b"")?;
    let claims: Claims = serde_json::from_slice(claims_json)
        .map_err(|e| StoreError::Decryption(format!("claims deserialisation failed: {e}")))?;

    // 3. Zeroize the raw DEK bytes (security fix)
    dek_raw.zeroize();

    Ok(Credential {
        id: stored.id.clone(),
        issuer: stored.issuer.clone(),
        subject: stored.subject.clone(),
        credential_type: stored.credential_type.clone(),
        claims,
        issued_at: stored.issued_at,
        expires_at: stored.expires_at,
        status_reference: stored.status_reference.clone(),
        binding: stored.binding.clone(),
        metadata: stored.metadata.clone(),
        status: stored.status.clone(),
    })
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
fn aead_open<'a>(key: &Key, blob: &'a mut [u8], aad: &[u8]) -> Result<&'a [u8], StoreError> {
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
    use serde_json::json;
    use time::{Duration, OffsetDateTime};

    fn make_credential() -> Credential {
        Credential::new(
            "https://issuer.example.com",
            "sub-1234",
            CredentialType::new("https://credentials.example.com/identity"),
            Claims::new(json!({ "given_name": "Alice", "family_name": "Smith" })),
            OffsetDateTime::now_utc(),
            Some(OffsetDateTime::now_utc() + Duration::days(365)),
            None,
            Binding,
            CredentialMetadata {},
        )
        .expect("valid credential")
    }

    #[test]
    fn round_trip() {
        let kek = Kek::generate().unwrap();
        let credential = make_credential();

        let stored = encrypt_credential(&kek, &credential).unwrap();

        // credential_type must be plaintext
        assert_eq!(
            stored.credential_type.as_ref(),
            "https://credentials.example.com/identity"
        );
        // Encrypted blob must contain nonce + ciphertext + tag
        assert!(stored.encrypted_claims.len() > NONCE_LENGTH + 16);

        let decrypted = decrypt_credential(&kek, &stored).unwrap();
        assert_eq!(decrypted.id, credential.id);
        assert_eq!(decrypted.claims["given_name"], "Alice");
    }

    #[test]
    fn wrong_kek_fails() {
        let kek = Kek::generate().unwrap();
        let wrong = Kek::generate().unwrap();
        let stored = encrypt_credential(&kek, &make_credential()).unwrap();
        assert!(matches!(
            decrypt_credential(&wrong, &stored),
            Err(StoreError::Decryption(_))
        ));
    }

    #[test]
    fn tampered_claims_fails() {
        let kek = Kek::generate().unwrap();
        let mut stored = encrypt_credential(&kek, &make_credential()).unwrap();
        stored.encrypted_claims[NONCE_LENGTH] ^= 0xFF;
        assert!(matches!(
            decrypt_credential(&kek, &stored),
            Err(StoreError::Decryption(_))
        ));
    }

    #[test]
    fn tampered_dek_fails() {
        let kek = Kek::generate().unwrap();
        let mut stored = encrypt_credential(&kek, &make_credential()).unwrap();
        stored.encrypted_dek[NONCE_LENGTH] ^= 0xFF;
        assert!(matches!(
            decrypt_credential(&kek, &stored),
            Err(StoreError::Decryption(_))
        ));
    }

    #[test]
    fn each_credential_gets_unique_dek() {
        let kek = Kek::generate().unwrap();
        let s1 = encrypt_credential(&kek, &make_credential()).unwrap();
        let s2 = encrypt_credential(&kek, &make_credential()).unwrap();
        assert_ne!(s1.encrypted_dek, s2.encrypted_dek);
    }

    #[test]
    fn same_credential_encrypted_twice_has_distinct_ciphertext() {
        let kek = Kek::generate().unwrap();
        let cred = make_credential();
        let s1 = encrypt_credential(&kek, &cred).unwrap();
        let s2 = encrypt_credential(&kek, &cred).unwrap();
        assert_ne!(
            s1.encrypted_claims, s2.encrypted_claims,
            "different nonces must produce different ciphertext"
        );
        // Both must still decrypt correctly
        assert_eq!(decrypt_credential(&kek, &s1).unwrap().id, cred.id);
        assert_eq!(decrypt_credential(&kek, &s2).unwrap().id, cred.id);
    }
}
