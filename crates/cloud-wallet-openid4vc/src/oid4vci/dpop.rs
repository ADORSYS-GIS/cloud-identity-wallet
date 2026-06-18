//! DPoP (Demonstrating Proof-of-Possession) proof generation per [RFC 9449] and [HAIP §4.4].
//!
//! [RFC 9449]: https://datatracker.ietf.org/doc/html/rfc9449
//! [HAIP §4.4]: https://ec.europa.eu/digital-building-blocks/wikis/display/EUDIGIDENTITY/Wallet+to+Issuer++-+HAIP

use std::collections::HashMap;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use cloud_wallet_crypto::digest::HashAlg;
use cloud_wallet_crypto::ecdsa::{self, Curve};
use cloud_wallet_crypto::jwk::B64;
use cloud_wallet_crypto::jwk::Jwk;
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
}

fn jwk_thumbprint(jwk: &Jwk) -> Result<String, DpopError> {
    let canonical = match &jwk.key {
        cloud_wallet_crypto::jwk::Key::Ec(ec) => {
            let crv = serde_json::to_value(ec.crv)
                .map_err(|e| DpopError::Thumbprint(format!("failed to serialize crv: {e}")))?;
            let x = jwk_b64_value(&ec.x);
            let y = jwk_b64_value(&ec.y);
            serde_json::json!({
                "crv": crv,
                "kty": "EC",
                "x": x,
                "y": y,
            })
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

/// Handler for DPoP nonce persistence per RFC 9449 §7.
///
/// Stores nonces keyed by `htu` (the normalized endpoint URL) so that
/// subsequent requests to the same endpoint can include the nonce
/// pre-emptively, avoiding extra round trips.
///
/// **Cloning**: `Clone` creates a shared reference to the same underlying
/// nonce store (via `Arc<Mutex>`). Mutations on a clone are visible to all
/// other clones sharing the same store. This is intentional to allow the
/// handler to be shared across concurrent requests.
#[derive(Debug, Clone, Default)]
pub struct DpopNonceHandler {
    nonces: std::sync::Arc<std::sync::Mutex<HashMap<String, String>>>,
}

impl DpopNonceHandler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_nonce(&self, htu: &str) -> Option<String> {
        self.nonces
            .lock()
            .expect("DpopNonceHandler lock poisoned")
            .get(htu)
            .cloned()
    }

    pub fn store_nonce(&self, htu: impl Into<String>, nonce: impl Into<String>) {
        self.nonces
            .lock()
            .expect("DpopNonceHandler lock poisoned")
            .insert(htu.into(), nonce.into());
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

    pub fn is_use_nonce_error(status: u16, body: &str) -> bool {
        if status != 400 {
            return false;
        }
        body.contains("use_nonce")
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
        htm: htm.to_string(),
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
    fn dpop_proof_wrong_htu_differs_from_correct() {
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
    fn dpop_proof_expired_iat_rejected_by_timestamp() {
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
        let decoded_claims: DpopProofClaims = decode_claims(&proof);
        let now = time::UtcDateTime::now().unix_timestamp();
        assert!(
            decoded_claims.iat < now - 300,
            "proof with iat 1 hour ago should be considered expired"
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
}
