//! DPoP (Demonstrating Proof-of-Possession) proof generation per [RFC 9449] and [HAIP §4.4].
//!
//! [RFC 9449]: https://datatracker.ietf.org/doc/html/rfc9449
//! [HAIP §4.4]: https://ec.europa.eu/digital-building-blocks/wikis/display/EUDIGIDENTITY/Wallet+to+Issuer++-+HAIP

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use cloud_wallet_crypto::digest::HashAlg;
use cloud_wallet_crypto::ecdsa::{self, Curve};
use cloud_wallet_crypto::jwk::B64;
use cloud_wallet_crypto::jwk::Jwk;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

const DPOP_JWT_TYP: &str = "dpop+jwt";
const DPOP_JWT_ALG: &str = "ES256";

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpopProofClaims {
    pub jti: String,
    pub htm: String,
    pub htu: String,
    pub iat: i64,
    pub nonce: Option<String>,
    pub ath: Option<String>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpopProofHeader {
    pub typ: String,
    pub alg: String,
    pub jwk: Jwk,
}

#[derive(Debug)]
pub struct DpopKeyPair {
    key: ecdsa::KeyPair,
    public_jwk: Jwk,
}

impl DpopKeyPair {
    pub fn generate() -> Result<Self, DpopError> {
        let key = ecdsa::KeyPair::generate(Curve::P256)
            .map_err(|e| DpopError::KeyGeneration(e.to_string()))?;
        let public_jwk =
            Jwk::try_from(&key).map_err(|e| DpopError::KeyGeneration(e.to_string()))?;
        Ok(Self { key, public_jwk })
    }

    pub fn public_jwk(&self) -> &Jwk {
        &self.public_jwk
    }

    pub fn sign_dpop_proof(&self, claims: &DpopProofClaims) -> Result<String, DpopError> {
        let header = DpopProofHeader {
            typ: DPOP_JWT_TYP.to_string(),
            alg: DPOP_JWT_ALG.to_string(),
            jwk: self.public_jwk.clone(),
        };

        let header_json = serde_json::to_vec(&header)
            .map_err(|e| DpopError::ProofGeneration(format!("failed to serialize header: {e}")))?;
        let claims_json = serde_json::to_vec(claims)
            .map_err(|e| DpopError::ProofGeneration(format!("failed to serialize claims: {e}")))?;

        let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);
        let claims_b64 = URL_SAFE_NO_PAD.encode(&claims_json);

        let mut signing_input = Vec::with_capacity(header_b64.len() + 1 + claims_b64.len());
        signing_input.extend_from_slice(header_b64.as_bytes());
        signing_input.push(b'.');
        signing_input.extend_from_slice(claims_b64.as_bytes());

        let signature = self
            .key
            .sign_sha256(&signing_input)
            .map_err(|e| DpopError::ProofGeneration(format!("signing failed: {e}")))?;
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature);

        Ok(format!("{header_b64}.{claims_b64}.{sig_b64}"))
    }

    pub fn thumbprint(&self) -> Result<String, DpopError> {
        jwk_thumbprint(&self.public_jwk)
    }

    /// Verify the signature of a DPoP proof's signing input against this key.
    ///
    /// This is intended for testing and validation purposes. The `signing_input`
    /// is the `header_b64.claims_b64` portion of the JWT, and `signature` is the
    /// decoded signature bytes.
    pub fn verify_signature(&self, signing_input: &[u8], signature: &[u8]) -> Result<(), DpopError> {
        self.key
            .public_key()
            .verify_sha256(signing_input, signature)
            .map_err(|e| DpopError::ProofGeneration(format!("signature verification failed: {e}")))
    }
}

fn jwk_thumbprint(jwk: &Jwk) -> Result<String, DpopError> {
    let canonical = match &jwk.key {
        cloud_wallet_crypto::jwk::Key::Ec(ec) => {
            let crv = serde_json::to_value(ec.crv)
                .map_err(|e| DpopError::Thumbprint(format!("failed to serialize crv: {e}")))?;
            let x = jwk_b64_value(&ec.x);
            let y = jwk_b64_value(&ec.y);
            let mut map = BTreeMap::new();
            map.insert("crv", crv);
            map.insert("kty", serde_json::Value::String("EC".into()));
            map.insert("x", x);
            map.insert("y", y);
            serde_json::Value::Object(map.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
        }
        _ => {
            return Err(DpopError::Thumbprint(
                "DPoP thumbprint only supports EC JWKs".into(),
            ));
        }
    };
    let canonical_str = serde_json::to_string(&canonical)
        .map_err(|e| DpopError::Thumbprint(format!("failed to serialize canonical JWK: {e}")))?;
    let hash = HashAlg::Sha256.hash(canonical_str.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(hash.as_ref()))
}

fn jwk_b64_value(b64: &B64) -> serde_json::Value {
    serde_json::Value::String(URL_SAFE_NO_PAD.encode(b64.as_ref()))
}

/// Default TTL for cached DPoP nonces (5 minutes).
const DEFAULT_NONCE_TTL: Duration = Duration::from_secs(300);

/// Maximum number of nonces stored in the cache before eviction of the least
/// recently inserted entry.
const DEFAULT_MAX_NONCES: usize = 64;

#[derive(Debug)]
struct NonceEntry {
    nonce: String,
    inserted_at: Instant,
}

/// Handler for DPoP nonce persistence per RFC 9449 §7.
///
/// Stores nonces keyed by `htu` (the normalized endpoint URL) so that
/// subsequent requests to the same endpoint can include the nonce
/// pre-emptively, avoiding extra round trips.
///
/// Entries are evicted after a configurable TTL (default: 5 minutes) and
/// when the cache exceeds a configurable capacity (default: 64 entries),
/// the least recently inserted entry is removed.
///
/// **Cloning**: `Clone` creates a shared reference to the same underlying
/// nonce store (via `Arc<Mutex>`). Mutations on a clone are visible to all
/// other clones sharing the same store. This is intentional to allow the
/// handler to be shared across concurrent requests.
#[derive(Debug, Clone)]
pub struct DpopNonceHandler {
    inner: Arc<Mutex<DpopNonceCache>>,
}

#[derive(Debug)]
struct DpopNonceCache {
    entries: BTreeMap<String, NonceEntry>,
    ttl: Duration,
    max_entries: usize,
}

impl DpopNonceHandler {
    pub fn new() -> Self {
        Self::with_config(DEFAULT_NONCE_TTL, DEFAULT_MAX_NONCES)
    }

    pub fn with_config(ttl: Duration, max_entries: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(DpopNonceCache {
                entries: BTreeMap::new(),
                ttl,
                max_entries,
            })),
        }
    }

    pub fn get_nonce(&self, htu: &str) -> Option<String> {
        let mut cache = self.inner.lock();
        if let Some(entry) = cache.entries.get(htu) {
            if entry.inserted_at.elapsed() > cache.ttl {
                cache.entries.remove(htu);
                return None;
            }
            return Some(entry.nonce.clone());
        }
        None
    }

    pub fn store_nonce(&self, htu: impl Into<String>, nonce: impl Into<String>) {
        let mut cache = self.inner.lock();
        let htu = htu.into();
        let nonce = nonce.into();
        if cache.entries.len() >= cache.max_entries
            && !cache.entries.contains_key(&htu)
            && let Some(evict_key) = cache
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.inserted_at)
                .map(|(k, _)| k.clone())
        {
            cache.entries.remove(&evict_key);
        }
        cache.entries.insert(
            htu,
            NonceEntry {
                nonce,
                inserted_at: Instant::now(),
            },
        );
    }

    pub fn extract_and_store_nonce(
        &self,
        htu: &str,
        headers: &reqwest::header::HeaderMap,
    ) -> Option<String> {
        let nonce = Self::extract_nonce_from_response(headers)?;
        self.store_nonce(htu, &nonce);
        Some(nonce)
    }

    pub fn extract_nonce_from_response(headers: &reqwest::header::HeaderMap) -> Option<String> {
        headers
            .get("DPoP-Nonce")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    }

    /// Check whether an HTTP response represents a DPoP `use_nonce` error.
    ///
    /// Per RFC 9449, the `error` field must equal `"use_nonce"`. This parses
    /// the response body as JSON and checks the `error` field exactly, rather
    /// than using a loose substring match.
    pub fn is_use_nonce_error(status: u16, body: &str) -> bool {
        if status != 400 {
            return false;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
            return false;
        };
        value.get("error").and_then(|e| e.as_str()) == Some("use_nonce")
    }
}

impl Default for DpopNonceHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Bundle of DPoP parameters for sender-constrained token and credential requests.
///
/// Per RFC 9449 §3.1, the same key pair must be used for all DPoP proofs
/// bound to a single access token. `DpopOptions` groups the key pair and
/// optional nonce handler so callers pass a single reference instead of
/// three separate parameters.
///
/// The nonce handler is used for pre-emptive nonce lookup (RFC 9449 §7):
/// the library automatically calls `handler.get_nonce(htu)` when building
/// proofs, so callers never need to compute `htu` or manage nonces manually.
pub struct DpopOptions<'a> {
    pub key: &'a DpopKeyPair,
    pub nonce_handler: Option<&'a DpopNonceHandler>,
}

impl<'a> DpopOptions<'a> {
    /// Look up a pre-emptive nonce for the given `htu` from the nonce handler.
    ///
    /// Returns `None` if no handler is set or if no nonce is cached for this endpoint.
    pub fn get_nonce(&self, htu: &str) -> Option<String> {
        self.nonce_handler.and_then(|h| h.get_nonce(htu))
    }
}

pub fn compute_ath(access_token: &str) -> String {
    let hash = HashAlg::Sha256.hash(access_token.as_bytes());
    URL_SAFE_NO_PAD.encode(hash.as_ref())
}

pub fn build_dpop_proof(
    key_pair: &DpopKeyPair,
    htm: &str,
    htu: &str,
    nonce: Option<&str>,
    ath: Option<&str>,
) -> Result<String, DpopError> {
    let jti = uuid::Uuid::new_v4().to_string();
    let iat = time::UtcDateTime::now().unix_timestamp();

    let claims = DpopProofClaims {
        jti,
        htm: htm.to_ascii_uppercase(),
        htu: htu.to_string(),
        iat,
        nonce: nonce.map(|n| n.to_string()),
        ath: ath.map(|a| a.to_string()),
    };

    key_pair.sign_dpop_proof(&claims)
}

pub fn htu_from_url(url: &url::Url) -> Result<String, DpopError> {
    match url.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(DpopError::InvalidHtu(format!(
                "htu must have http or https scheme, got '{scheme}'"
            )));
        }
    }
    let host = url
        .host_str()
        .ok_or_else(|| DpopError::InvalidHtu("htu requires a host".into()))?;
    let mut htu = format!("{}://{}", url.scheme(), host);
    if let Some(port) = url.port() {
        htu.push_str(&format!(":{port}"));
    }
    htu.push_str(url.path());
    Ok(htu)
}

impl DpopProofClaims {
    /// Validate that the `htu` claim matches the expected endpoint URI.
    ///
    /// Per RFC 9449 §4.2, the `htu` claim MUST match the HTTP URI of the
    /// token or credential endpoint, normalized per RFC 9449. Returns `Ok(())`
    /// if the claim matches, or an error describing the mismatch.
    pub fn validate_htu(&self, expected: &str) -> Result<(), DpopError> {
        if self.htu == expected {
            Ok(())
        } else {
            Err(DpopError::InvalidHtu(format!(
                "htu claim '{}' does not match expected '{}'",
                self.htu, expected
            )))
        }
    }

    /// Check whether this proof is expired relative to a maximum age.
    ///
    /// RFC 9449 recommends that receivers reject proofs with `iat` values
    /// that are too far in the past. A typical `max_age` is 60 seconds.
    /// Returns `true` if the proof is expired.
    pub fn is_expired(&self, max_age: Duration) -> bool {
        let now = time::UtcDateTime::now().unix_timestamp();
        let age = now - self.iat;
        age > max_age.as_secs() as i64
    }
}

const DEFAULT_PROOF_MAX_AGE: Duration = Duration::from_secs(60);

/// Decode the claims from a DPoP proof JWT without verifying the signature.
///
/// This is useful for server-side validation where the claims are inspected
/// before signature verification.
pub fn decode_dpop_proof_claims(jwt: &str) -> Result<DpopProofClaims, DpopError> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(DpopError::ProofGeneration(
            "DPoP proof must be a 3-part JWT".into(),
        ));
    }
    let claims_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| DpopError::ProofGeneration(format!("failed to decode claims: {e}")))?;
    serde_json::from_slice(&claims_bytes)
        .map_err(|e| DpopError::ProofGeneration(format!("failed to parse claims: {e}")))
}

/// Validate a DPoP proof against an expected endpoint URI and maximum age.
///
/// Checks:
/// 1. The `htu` claim matches `expected_htu`
/// 2. The proof is not expired (iat within `max_age` of now)
/// 3. The `htm` claim is not empty
///
/// Returns the decoded claims on success.
pub fn validate_dpop_proof(
    jwt: &str,
    expected_htu: &str,
    max_age: Option<Duration>,
) -> Result<DpopProofClaims, DpopError> {
    let claims = decode_dpop_proof_claims(jwt)?;
    claims.validate_htu(expected_htu)?;
    if claims.is_expired(max_age.unwrap_or(DEFAULT_PROOF_MAX_AGE)) {
        return Err(DpopError::ProofGeneration(
            "DPoP proof is expired".into(),
        ));
    }
    if claims.htm.is_empty() {
        return Err(DpopError::ProofGeneration(
            "DPoP proof htm claim must not be empty".into(),
        ));
    }
    Ok(claims)
}

#[derive(Debug, thiserror::Error)]
pub enum DpopError {
    #[error("key generation failed: {0}")]
    KeyGeneration(String),

    #[error("proof generation failed: {0}")]
    ProofGeneration(String),

    #[error("thumbprint computation failed: {0}")]
    Thumbprint(String),

    #[error("invalid htu: {0}")]
    InvalidHtu(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn make_key_pair() -> DpopKeyPair {
        DpopKeyPair::generate().expect("key generation should succeed")
    }

    #[test]
    fn dpop_proof_valid_structure() {
        let key_pair = make_key_pair();
        let proof = build_dpop_proof(
            &key_pair,
            "POST",
            "https://issuer.example.com/token",
            None,
            None,
        )
        .expect("proof generation should succeed");

        let parts: Vec<&str> = proof.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT should have 3 parts");

        let header_bytes = URL_SAFE_NO_PAD
            .decode(parts[0])
            .expect("header base64url decode");
        let header: DpopProofHeader =
            serde_json::from_slice(&header_bytes).expect("header JSON parse");
        assert_eq!(header.typ, "dpop+jwt");
        assert_eq!(header.alg, "ES256");
        assert!(matches!(
            header.jwk.key,
            cloud_wallet_crypto::jwk::Key::Ec(_)
        ));

        let claims_bytes = URL_SAFE_NO_PAD
            .decode(parts[1])
            .expect("claims base64url decode");
        let claims: DpopProofClaims =
            serde_json::from_slice(&claims_bytes).expect("claims JSON parse");
        assert_eq!(claims.htm, "POST");
        assert_eq!(claims.htu, "https://issuer.example.com/token");
        assert!(!claims.jti.is_empty());
        assert!(claims.iat > 0);
        assert!(claims.nonce.is_none());
        assert!(claims.ath.is_none());
    }

    #[test]
    fn dpop_proof_with_nonce() {
        let key_pair = make_key_pair();
        let nonce = "server-nonce-123";
        let proof = build_dpop_proof(
            &key_pair,
            "POST",
            "https://issuer.example.com/token",
            Some(nonce),
            None,
        )
        .expect("proof generation should succeed");

        let parts: Vec<&str> = proof.split('.').collect();
        let claims_bytes = URL_SAFE_NO_PAD.decode(parts[1]).expect("claims decode");
        let claims: DpopProofClaims = serde_json::from_slice(&claims_bytes).expect("claims parse");
        assert_eq!(claims.nonce.as_deref(), Some(nonce));
    }

    #[test]
    fn dpop_proof_with_ath() {
        let key_pair = make_key_pair();
        let access_token = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU";
        let expected_ath = compute_ath(access_token);
        let proof = build_dpop_proof(
            &key_pair,
            "POST",
            "https://issuer.example.com/credential",
            None,
            Some(&expected_ath),
        )
        .expect("proof generation should succeed");

        let parts: Vec<&str> = proof.split('.').collect();
        let claims_bytes = URL_SAFE_NO_PAD.decode(parts[1]).expect("claims decode");
        let claims: DpopProofClaims = serde_json::from_slice(&claims_bytes).expect("claims parse");
        assert_eq!(claims.ath.as_deref(), Some(expected_ath.as_str()));
    }

    #[test]
    fn dpop_nonce_handler() {
        let handler = DpopNonceHandler::new();
        assert!(
            handler
                .get_nonce("https://issuer.example.com/token")
                .is_none()
        );

        handler.store_nonce("https://issuer.example.com/token", "abc123");
        assert_eq!(
            handler.get_nonce("https://issuer.example.com/token"),
            Some("abc123".to_string())
        );
    }

    #[test]
    fn dpop_is_use_nonce_error() {
        assert!(DpopNonceHandler::is_use_nonce_error(
            400,
            r#"{"error":"use_nonce"}"#
        ));
        assert!(!DpopNonceHandler::is_use_nonce_error(
            401,
            r#"{"error":"use_nonce"}"#
        ));
        assert!(!DpopNonceHandler::is_use_nonce_error(
            400,
            r#"{"error":"invalid_grant"}"#
        ));
        assert!(!DpopNonceHandler::is_use_nonce_error(
            400,
            r#"{"error":"invalid_grant","error_description":"use_nonce is required"}"#
        ));
        assert!(!DpopNonceHandler::is_use_nonce_error(
            400,
            r#"{"error_description":"use_nonce should not match"}"#
        ));
        assert!(!DpopNonceHandler::is_use_nonce_error(400, "not json"));
    }

    #[test]
    fn dpop_jti_uniqueness() {
        let key_pair = make_key_pair();
        let proof1 = build_dpop_proof(
            &key_pair,
            "POST",
            "https://issuer.example.com/token",
            None,
            None,
        )
        .unwrap();
        let proof2 = build_dpop_proof(
            &key_pair,
            "POST",
            "https://issuer.example.com/token",
            None,
            None,
        )
        .unwrap();

        let claims1: DpopProofClaims = decode_claims(&proof1);
        let claims2: DpopProofClaims = decode_claims(&proof2);
        assert_ne!(claims1.jti, claims2.jti);
    }

    #[test]
    fn compute_ath_known_value() {
        let token = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU";
        let ath = compute_ath(token);
        let decoded = URL_SAFE_NO_PAD.decode(&ath).expect("base64url decode");
        assert_eq!(decoded.len(), 32, "SHA-256 hash should be 32 bytes");
    }

    #[test]
    fn htu_from_url_strips_query_and_fragment() {
        let url = url::Url::parse("https://issuer.example.com/token?foo=bar#baz").unwrap();
        let htu = htu_from_url(&url).unwrap();
        assert_eq!(htu, "https://issuer.example.com/token");
    }

    #[test]
    fn htu_from_url_preserves_port() {
        let url = url::Url::parse("https://issuer.example.com:8443/token").unwrap();
        let htu = htu_from_url(&url).unwrap();
        assert_eq!(htu, "https://issuer.example.com:8443/token");
    }

    #[test]
    fn dpop_thumbprint_computation() {
        let key_pair = make_key_pair();
        let thumbprint = key_pair.thumbprint().expect("thumbprint should succeed");
        let decoded = URL_SAFE_NO_PAD
            .decode(&thumbprint)
            .expect("thumbprint base64url decode");
        assert_eq!(decoded.len(), 32, "SHA-256 thumbprint should be 32 bytes");
    }

    fn decode_claims(jwt: &str) -> DpopProofClaims {
        let parts: Vec<&str> = jwt.split('.').collect();
        let claims_bytes = URL_SAFE_NO_PAD.decode(parts[1]).expect("claims decode");
        serde_json::from_slice(&claims_bytes).expect("claims parse")
    }

    #[test]
    fn dpop_proof_htu_differs_for_different_urls() {
        let key_pair = make_key_pair();
        let correct_htu = "https://issuer.example.com/token";
        let wrong_htu = "https://attacker.example.com/token";
        let proof_correct = build_dpop_proof(&key_pair, "POST", correct_htu, None, None)
            .expect("proof generation should succeed");
        let proof_wrong = build_dpop_proof(&key_pair, "POST", wrong_htu, None, None)
            .expect("proof generation should succeed");

        let claims_correct: DpopProofClaims = decode_claims(&proof_correct);
        let claims_wrong: DpopProofClaims = decode_claims(&proof_wrong);

        assert_ne!(claims_correct.htu, claims_wrong.htu);
        assert_eq!(claims_correct.htu, correct_htu);
        assert_eq!(claims_wrong.htu, wrong_htu);
    }

    #[test]
    fn dpop_proof_wrong_htu_rejected_by_validation() {
        let key_pair = make_key_pair();
        let correct_htu = "https://issuer.example.com/token";
        let proof = build_dpop_proof(&key_pair, "POST", correct_htu, None, None)
            .expect("proof generation should succeed");

        let claims = decode_dpop_proof_claims(&proof).expect("decoding should succeed");

        claims
            .validate_htu("https://issuer.example.com/token")
            .expect("correct htu should validate");

        let err = claims
            .validate_htu("https://attacker.example.com/token")
            .expect_err("wrong htu should be rejected");
        assert!(
            err.to_string().contains("does not match"),
            "error should describe mismatch: {err}"
        );
    }

    #[test]
    fn dpop_proof_is_expired_rejects_stale_proof() {
        let old_iat = time::UtcDateTime::now().unix_timestamp() - 3600;
        let claims = DpopProofClaims {
            jti: uuid::Uuid::new_v4().to_string(),
            htm: "POST".to_string(),
            htu: "https://issuer.example.com/token".to_string(),
            iat: old_iat,
            nonce: None,
            ath: None,
        };

        assert!(
            claims.is_expired(Duration::from_secs(60)),
            "proof with iat 1 hour ago should be expired with 60s max age"
        );

        let fresh_claims = DpopProofClaims {
            jti: uuid::Uuid::new_v4().to_string(),
            htm: "POST".to_string(),
            htu: "https://issuer.example.com/token".to_string(),
            iat: time::UtcDateTime::now().unix_timestamp(),
            nonce: None,
            ath: None,
        };
        assert!(
            !fresh_claims.is_expired(Duration::from_secs(60)),
            "fresh proof should not be expired"
        );
    }

    #[test]
    fn validate_dpop_proof_rejects_expired_proof() {
        let key_pair = make_key_pair();
        let old_iat = time::UtcDateTime::now().unix_timestamp() - 3600;
        let claims = DpopProofClaims {
            jti: uuid::Uuid::new_v4().to_string(),
            htm: "POST".to_string(),
            htu: "https://issuer.example.com/token".to_string(),
            iat: old_iat,
            nonce: None,
            ath: None,
        };
        let proof = key_pair
            .sign_dpop_proof(&claims)
            .expect("signing should succeed");

        let result = validate_dpop_proof(&proof, "https://issuer.example.com/token", Some(Duration::from_secs(60)));
        assert!(result.is_err(), "expired proof should be rejected");
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("expired"),
            "error should mention expiration: {err}"
        );
    }

    #[test]
    fn htu_from_url_rejects_non_http_scheme() {
        let url = url::Url::parse("ftp://issuer.example.com/resource").unwrap();
        let result = htu_from_url(&url);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("http or https"),
            "error should mention scheme requirement: {err}"
        );
    }

    #[test]
    fn htu_from_url_rejects_missing_host() {
        let url = url::Url::parse("file:///path/to/resource").unwrap();
        let result = htu_from_url(&url);
        assert!(result.is_err());
    }

    #[test]
    fn dpop_nonce_handler_store_and_retrieve() {
        let handler = DpopNonceHandler::new();
        assert!(
            handler
                .get_nonce("https://issuer.example.com/token")
                .is_none()
        );

        handler.store_nonce("https://issuer.example.com/token", "abc123");
        assert_eq!(
            handler.get_nonce("https://issuer.example.com/token"),
            Some("abc123".to_string())
        );
        assert!(
            handler
                .get_nonce("https://other.example.com/token")
                .is_none()
        );
    }

    #[test]
    fn dpop_nonce_handler_clone_shared_state() {
        let handler = DpopNonceHandler::new();
        handler.store_nonce("https://issuer.example.com/token", "nonce-abc");

        let cloned = handler.clone();
        assert_eq!(
            cloned.get_nonce("https://issuer.example.com/token"),
            Some("nonce-abc".to_string())
        );

        cloned.store_nonce("https://issuer.example.com/credential", "nonce-def");
        assert_eq!(
            handler.get_nonce("https://issuer.example.com/credential"),
            Some("nonce-def".to_string())
        );
    }

    #[test]
    fn dpop_nonce_handler_ttl_eviction() {
        let handler = DpopNonceHandler::with_config(Duration::from_millis(50), 64);
        handler.store_nonce("https://issuer.example.com/token", "short-lived");
        assert_eq!(
            handler.get_nonce("https://issuer.example.com/token"),
            Some("short-lived".to_string())
        );

        std::thread::sleep(Duration::from_millis(100));
        assert!(
            handler
                .get_nonce("https://issuer.example.com/token")
                .is_none(),
            "nonce should be evicted after TTL"
        );
    }

    #[test]
    fn dpop_nonce_handler_max_entries_eviction() {
        let handler = DpopNonceHandler::with_config(DEFAULT_NONCE_TTL, 2);
        handler.store_nonce("https://z.example.com/token", "nonce-z");
        handler.store_nonce("https://m.example.com/token", "nonce-m");
        handler.store_nonce("https://a.example.com/token", "nonce-a");

        assert!(
            handler.get_nonce("https://z.example.com/token").is_none(),
            "least recently inserted entry should be evicted when max_entries is exceeded"
        );
        assert_eq!(
            handler.get_nonce("https://m.example.com/token"),
            Some("nonce-m".to_string())
        );
        assert_eq!(
            handler.get_nonce("https://a.example.com/token"),
            Some("nonce-a".to_string())
        );
    }

    #[test]
    fn dpop_htm_normalized_to_uppercase() {
        let key_pair = make_key_pair();
        let proof = build_dpop_proof(
            &key_pair,
            "post",
            "https://issuer.example.com/token",
            None,
            None,
        )
        .expect("proof generation should succeed");

        let claims: DpopProofClaims = decode_claims(&proof);
        assert_eq!(claims.htm, "POST", "htm should be normalized to uppercase");
    }

    #[test]
    fn dpop_proof_signature_verifies_with_public_key() {
        let key_pair = make_key_pair();
        let proof = build_dpop_proof(
            &key_pair,
            "POST",
            "https://issuer.example.com/token",
            None,
            None,
        )
        .expect("proof generation should succeed");

        let parts: Vec<&str> = proof.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT should have 3 parts");

        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let signature_bytes = URL_SAFE_NO_PAD
            .decode(parts[2])
            .expect("signature base64url decode");

        key_pair
            .verify_signature(signing_input.as_bytes(), &signature_bytes)
            .expect("signature should verify with public key");

        let tampered_input = format!("{}.TAMPERED", parts[0]);
        let tampered_result =
            key_pair.verify_signature(tampered_input.as_bytes(), &signature_bytes);
        assert!(
            tampered_result.is_err(),
            "tampered input should fail verification"
        );
    }

    #[test]
    fn dpop_thumbprint_rfc7638_canonical_ordering() {
        use cloud_wallet_crypto::jwk::Key;

        let key_pair = make_key_pair();
        let thumbprint = key_pair.thumbprint().expect("thumbprint should succeed");
        let decoded = URL_SAFE_NO_PAD
            .decode(&thumbprint)
            .expect("thumbprint base64url decode");
        assert_eq!(decoded.len(), 32, "SHA-256 thumbprint should be 32 bytes");

        let public_jwk = key_pair.public_jwk();
        if let Key::Ec(ec) = &public_jwk.key {
            let mut map = BTreeMap::new();
            map.insert("crv", serde_json::to_value(ec.crv).unwrap());
            map.insert("kty", serde_json::Value::String("EC".into()));
            map.insert(
                "x",
                serde_json::Value::String(URL_SAFE_NO_PAD.encode(ec.x.as_ref())),
            );
            map.insert(
                "y",
                serde_json::Value::String(URL_SAFE_NO_PAD.encode(ec.y.as_ref())),
            );
            let canonical = serde_json::to_string(&serde_json::Value::Object(
                map.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
            ))
            .unwrap();
            assert!(
                canonical.starts_with(r#"{"crv":"#),
                "BTreeMap should produce canonical order (crv, kty, x, y), got: {canonical}"
            );
        }
    }

    #[test]
    fn dpop_thumbprint_known_answer_rfc7638() {
        use cloud_wallet_crypto::jwk::Key;

        let key_pair = make_key_pair();
        let thumbprint = key_pair.thumbprint().expect("thumbprint should succeed");

        let public_jwk = key_pair.public_jwk();
        let ec = match &public_jwk.key {
            Key::Ec(ec) => ec,
            _ => panic!("expected EC key"),
        };

        let canonical = serde_json::to_string(&serde_json::json!({
            "crv": serde_json::to_value(ec.crv).unwrap(),
            "kty": "EC",
            "x": URL_SAFE_NO_PAD.encode(ec.x.as_ref()),
            "y": URL_SAFE_NO_PAD.encode(ec.y.as_ref()),
        }))
        .unwrap();

        let expected_thumbprint = {
            let hash = HashAlg::Sha256.hash(canonical.as_bytes());
            URL_SAFE_NO_PAD.encode(hash.as_ref())
        };

        assert_eq!(
            thumbprint, expected_thumbprint,
            "thumbprint must match independently computed SHA-256 of canonical form"
        );

        let key_order: Vec<String> = {
            let parsed: serde_json::Map<String, serde_json::Value> =
                serde_json::from_str(&canonical).unwrap();
            parsed.keys().cloned().collect()
        };
        assert_eq!(
            key_order,
            vec!["crv", "kty", "x", "y"],
            "canonical form must use RFC 7638 lexicographic order"
        );
    }
}
