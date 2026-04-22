use std::str::FromStr;

use cloud_wallet_crypto::ecdsa;
use cloud_wallet_crypto::ed25519;
use cloud_wallet_crypto::error::ErrorKind;
use cloud_wallet_crypto::jwk::Jwk;
use cloud_wallet_crypto::rsa;
use jsonwebtoken::{Algorithm as JwtAlgorithm, EncodingKey, Header, jwk::Jwk as JwtJwk};
use pkcs8::PrivateKeyInfo;
use serde::{Deserialize, Serialize};

use crate::issuance::client::{ClientError, Result};

const OPENID4VCI_PROOF_JWT_TYP: &str = "openid4vci-proof+jwt";

/// Builds a holder-binding proof JWT for a credential request.
pub trait ProofSigner: Send + Sync + 'static {
    /// Sign `claims` and return the compact JWT string.
    fn sign(&self, claims: ProofClaims) -> Result<String>;

    /// Returns the algorithm used by this signer.
    fn algorithm(&self) -> Algorithm;
}

/// Claims for an `openid4vci-proof+jwt` proof JWT.
#[derive(Debug, Clone, Serialize)]
pub struct ProofClaims {
    /// Audience: the `credential_issuer` URL from issuer metadata.
    pub aud: String,
    /// Issued-at (Unix epoch seconds).
    pub iat: i64,
    /// `client_id` of the Client making the request.
    /// Optional for Pre-Authorized Code Flow with anonymous access to the token endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// Nonce from the issuer, bound to this request.
    /// Must be present when the issuer has a nonce endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

/// JWS `alg` values supported for OpenID4VCI JWT proofs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Algorithm {
    ES256,
    ES384,
    ES512,
    ES256K,
    EdDSA,
    RS256,
    RS384,
    RS512,
    PS256,
    PS384,
    PS512,
}

impl Algorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            Algorithm::ES256 => "ES256",
            Algorithm::ES384 => "ES384",
            Algorithm::ES512 => "ES512",
            Algorithm::ES256K => "ES256K",
            Algorithm::EdDSA => "EdDSA",
            Algorithm::RS256 => "RS256",
            Algorithm::RS384 => "RS384",
            Algorithm::RS512 => "RS512",
            Algorithm::PS256 => "PS256",
            Algorithm::PS384 => "PS384",
            Algorithm::PS512 => "PS512",
        }
    }
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TryFrom<Algorithm> for JwtAlgorithm {
    type Error = cloud_wallet_crypto::Error;
    fn try_from(value: Algorithm) -> std::result::Result<Self, Self::Error> {
        match value {
            Algorithm::ES256 => Ok(JwtAlgorithm::ES256),
            Algorithm::ES384 => Ok(JwtAlgorithm::ES384),
            Algorithm::EdDSA => Ok(JwtAlgorithm::EdDSA),
            Algorithm::RS256 => Ok(JwtAlgorithm::RS256),
            Algorithm::RS384 => Ok(JwtAlgorithm::RS384),
            Algorithm::RS512 => Ok(JwtAlgorithm::RS512),
            Algorithm::PS256 => Ok(JwtAlgorithm::PS256),
            Algorithm::PS384 => Ok(JwtAlgorithm::PS384),
            Algorithm::PS512 => Ok(JwtAlgorithm::PS512),
            _ => Err(ErrorKind::UnsupportedAlgorithm.into()),
        }
    }
}

impl FromStr for Algorithm {
    type Err = cloud_wallet_crypto::Error;
    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "ES256" => Ok(Self::ES256),
            "ES384" => Ok(Self::ES384),
            "ES512" => Ok(Self::ES512),
            "ES256K" => Ok(Self::ES256K),
            "EdDSA" => Ok(Self::EdDSA),
            "RS256" => Ok(Self::RS256),
            "RS384" => Ok(Self::RS384),
            "RS512" => Ok(Self::RS512),
            "PS256" => Ok(Self::PS256),
            "PS384" => Ok(Self::PS384),
            "PS512" => Ok(Self::PS512),
            _ => Err(ErrorKind::UnsupportedAlgorithm.into()),
        }
    }
}

/// [`ProofSigner`] implementation backed by cryptographic key material.
#[derive(Debug)]
pub struct CryptoSigner {
    key: KeyMaterial,
    encoding_key: EncodingKey,
    jwk: JwtJwk,
    algorithm: Algorithm,
}

#[derive(Debug)]
enum KeyMaterial {
    Ecdsa(ecdsa::KeyPair),
    Ed25519(ed25519::KeyPair),
    Rsa(rsa::KeyPair),
}

impl CryptoSigner {
    /// Creates a signer from an ECDSA private key in PKCS#8 DER format.
    #[must_use]
    pub fn from_ecdsa_der(der: impl AsRef<[u8]>) -> Result<Self> {
        let key = KeyMaterial::Ecdsa(ecdsa::KeyPair::from_pkcs8_der(der.as_ref())?);
        let encoding_key = build_encoding_key(&key)?;
        let jwk = build_jwk(&key)?;
        let algorithm = key.algorithm();
        Ok(Self {
            key,
            encoding_key,
            jwk,
            algorithm,
        })
    }

    /// Creates a signer from an Ed25519 private key in PKCS#8 DER format.
    #[must_use]
    pub fn from_ed25519_der(der: impl AsRef<[u8]>) -> Result<Self> {
        let key = KeyMaterial::Ed25519(ed25519::KeyPair::from_pkcs8_der(der.as_ref())?);
        let encoding_key = build_encoding_key(&key)?;
        let jwk = build_jwk(&key)?;
        let algorithm = key.algorithm();
        Ok(Self {
            key,
            encoding_key,
            jwk,
            algorithm,
        })
    }

    /// Creates a signer from an RSA private key in PKCS#8 DER format.
    #[must_use]
    pub fn from_rsa_der(der: impl AsRef<[u8]>) -> Result<Self> {
        let key = KeyMaterial::Rsa(rsa::KeyPair::from_pkcs8_der(der.as_ref())?);
        let encoding_key = build_encoding_key(&key)?;
        let jwk = build_jwk(&key)?;
        let algorithm = key.algorithm();
        Ok(Self {
            key,
            encoding_key,
            jwk,
            algorithm,
        })
    }

    fn encode(&self, claims: &ProofClaims) -> Result<String> {
        let jwt_alg = JwtAlgorithm::try_from(self.algorithm)?;

        // Create header with JWK
        let mut header = Header::new(jwt_alg);
        header.typ = Some(OPENID4VCI_PROOF_JWT_TYP.to_string());
        header.jwk = Some(self.jwk.clone());

        // Encode the JWT
        Ok(jsonwebtoken::encode(&header, claims, &self.encoding_key)?)
    }
}

impl ProofSigner for CryptoSigner {
    fn sign(&self, claims: ProofClaims) -> Result<String> {
        self.encode(&claims)
    }

    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
}

impl KeyMaterial {
    fn algorithm(&self) -> Algorithm {
        match self {
            KeyMaterial::Ecdsa(key) => match key.curve() {
                ecdsa::Curve::P256 => Algorithm::ES256,
                ecdsa::Curve::P384 => Algorithm::ES384,
                ecdsa::Curve::P521 => Algorithm::ES512,
                ecdsa::Curve::P256K1 => Algorithm::ES256K,
            },
            KeyMaterial::Ed25519(_) => Algorithm::EdDSA,
            KeyMaterial::Rsa(key) => match key.modulus_len() {
                256 => Algorithm::PS256,
                384 => Algorithm::PS384,
                512 => Algorithm::PS512,
                _ => Algorithm::PS256,
            },
        }
    }
}

fn build_encoding_key(key: &KeyMaterial) -> Result<EncodingKey> {
    match key {
        KeyMaterial::Ecdsa(keypair) => Ok(EncodingKey::from_ec_der(keypair.to_pkcs8_der())),
        KeyMaterial::Ed25519(keypair) => {
            let mut der = zeroize::Zeroizing::new([0u8; 60]);
            let encoded = keypair.to_pkcs8_der(&mut der[..])?;
            Ok(EncodingKey::from_ed_der(encoded))
        }
        KeyMaterial::Rsa(keypair) => {
            let mut pkcs8 = zeroize::Zeroizing::new(vec![0u8; keypair.modulus_len() * 8]);
            let pkcs8 = keypair.to_pkcs8_der(&mut pkcs8)?;
            let key_info = PrivateKeyInfo::try_from(pkcs8)?;
            // jsonwebtoken RSA DER expects the RSAPrivateKey payload (PKCS#1 DER).
            Ok(EncodingKey::from_rsa_der(key_info.private_key))
        }
    }
}

/// Build a public JWK from key material for inclusion in JWT headers.
fn build_jwk(key: &KeyMaterial) -> Result<JwtJwk> {
    let crypto_jwk = match key {
        KeyMaterial::Ecdsa(keypair) => Jwk::try_from(keypair)?,
        KeyMaterial::Ed25519(keypair) => Jwk::try_from(keypair)?,
        KeyMaterial::Rsa(keypair) => Jwk::try_from(keypair)?,
    };
    Ok(serde_json::from_value(serde_json::to_value(crypto_jwk)?)?)
}

impl From<cloud_wallet_crypto::Error> for ClientError {
    fn from(error: cloud_wallet_crypto::error::Error) -> Self {
        ClientError::internal(format!("underlying crypto error: {error}"))
    }
}

impl From<pkcs8::Error> for ClientError {
    fn from(error: pkcs8::Error) -> Self {
        ClientError::internal(format!("pkcs8 parsing error: {error}"))
    }
}

impl From<serde_json::Error> for ClientError {
    fn from(error: serde_json::Error) -> Self {
        ClientError::internal(format!("failed to serialize JWK: {error}"))
    }
}

impl From<jsonwebtoken::errors::Error> for ClientError {
    fn from(error: jsonwebtoken::errors::Error) -> Self {
        ClientError::internal(format!("JWT encoding failed: {error}"))
    }
}
