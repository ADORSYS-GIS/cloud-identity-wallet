use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Serialize;

use crate::formats::sd_jwt::IanaHashAlgorithm;

use super::error::HolderBindingProofError;

pub type Result<T> = std::result::Result<T, HolderBindingProofError>;

#[derive(Debug, Clone)]
pub struct KeyBindingInput {
    pub nonce: String,
    pub audience: String,
    pub sd_hash: String,
    pub issued_at: i64,
}

impl KeyBindingInput {
    pub fn new(nonce: impl Into<String>, audience: impl Into<String>, sd_hash: impl Into<String>) -> Self {
        Self {
            nonce: nonce.into(),
            audience: audience.into(),
            sd_hash: sd_hash.into(),
            issued_at: time::OffsetDateTime::now_utc().unix_timestamp(),
        }
    }

    pub fn with_issued_at(mut self, timestamp: i64) -> Self {
        self.issued_at = timestamp;
        self
    }
}

impl KeyBindingInput {
    pub fn into_claims(self) -> KeyBindingClaims {
        KeyBindingClaims {
            iat: self.issued_at,
            aud: self.audience,
            nonce: self.nonce,
            sd_hash: self.sd_hash,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct KeyBindingClaims {
    pub iat: i64,
    pub aud: String,
    pub nonce: String,
    pub sd_hash: String,
}

pub trait HolderBindingProof {
    fn format(&self) -> HolderBindingFormat;
    fn to_presentation(&self) -> Result<Vec<String>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HolderBindingFormat {
    KeyBindingJwt,
    MdocDeviceSignature,
}

impl std::fmt::Display for HolderBindingFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyBindingJwt => write!(f, "kb+jwt"),
            Self::MdocDeviceSignature => write!(f, "mso_mdoc"),
        }
    }
}

pub fn compute_sd_hash(
    issuer_jwt: &str,
    disclosures: &[&str],
    algorithm: IanaHashAlgorithm,
) -> std::result::Result<String, HolderBindingProofError> {
    let parts: Vec<&str> = [issuer_jwt]
        .into_iter()
        .chain(disclosures.iter().copied())
        .collect();
    
    let combined = parts.join("~");
    
    let hash_alg: cloud_wallet_crypto::digest::HashAlg = algorithm.into();
    let digest = hash_alg.hash(combined.as_bytes());
    
    Ok(URL_SAFE_NO_PAD.encode(digest.as_ref()))
}

pub fn build_key_binding_jwt_claims(
    nonce: impl Into<String>,
    audience: impl Into<String>,
    sd_hash: impl Into<String>,
) -> BTreeMap<&'static str, serde_json::Value> {
    let input = KeyBindingInput::new(nonce, audience, sd_hash);
    let claims = input.into_claims();
    
    let mut map = BTreeMap::new();
    map.insert("iat", serde_json::Value::Number(claims.iat.into()));
    map.insert("aud", serde_json::Value::String(claims.aud));
    map.insert("nonce", serde_json::Value::String(claims.nonce));
    map.insert("sd_hash", serde_json::Value::String(claims.sd_hash));
    map
}

#[derive(Debug, Clone)]
pub struct SdJwtHolderBinding {
    pub key_binding_jwt: String,
}

impl SdJwtHolderBinding {
    pub fn new(key_binding_jwt: impl Into<String>) -> Self {
        Self {
            key_binding_jwt: key_binding_jwt.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MdocHolderBinding {
    pub device_signature: Vec<u8>,
}

impl MdocHolderBinding {
    pub fn new(device_signature: Vec<u8>) -> Self {
        Self { device_signature }
    }
}

#[derive(Debug, Clone)]
pub enum HolderBinding {
    SdJwt(SdJwtHolderBinding),
    Mdoc(MdocHolderBinding),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_binding_input_creates_valid_claims() {
        let claims = KeyBindingInput::new(
            "test-nonce",
            "https://verifier.example.com",
            "test-hash",
        )
        .with_issued_at(1234567890)
        .into_claims();

        assert_eq!(claims.iat, 1234567890);
        assert_eq!(claims.aud, "https://verifier.example.com");
        assert_eq!(claims.nonce, "test-nonce");
        assert_eq!(claims.sd_hash, "test-hash");
    }

    #[test]
    fn build_key_binding_jwt_claims_produces_correct_structure() {
        let claims = build_key_binding_jwt_claims(
            "test-nonce",
            "https://verifier.example.com",
            "test-hash",
        );

        assert_eq!(claims.get("nonce").unwrap().as_str().unwrap(), "test-nonce");
        assert_eq!(claims.get("aud").unwrap().as_str().unwrap(), "https://verifier.example.com");
        assert_eq!(claims.get("sd_hash").unwrap().as_str().unwrap(), "test-hash");
        assert!(claims.get("iat").unwrap().as_i64().is_some());
    }
}