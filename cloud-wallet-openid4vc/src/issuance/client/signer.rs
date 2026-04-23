use std::str::FromStr;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use cloud_wallet_crypto::{ecdsa, ed25519, error::ErrorKind, jwk::Jwk, rsa};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::issuance::client::{ClientError, Result};

const OPENID4VCI_PROOF_JWT_TYP: &str = "openid4vci-proof+jwt";

/// Builds a holder-binding proof JWT for a credential request.
pub trait ProofSigner: Send + Sync + 'static {
    /// Sign `claims` with the provided header and return the compact JWT string.
    fn sign(&self, claims: &Claims) -> Result<String>;

    /// Returns the algorithm used by this signer.
    fn algorithm(&self) -> Algorithm;
}

/// JOSE header for OpenID4VCI proof JWTs as defined in [OID4VCI Appendix F]
///
/// [OID4VCI Appendix F]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-jwt-proof-type
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize)]
pub struct Header {
    /// Digital signature algorithm identifier
    pub alg: Algorithm,
    /// JWT proof type (must be "openid4vci-proof+jwt")
    pub typ: &'static str,
    /// Key ID of the key
    pub kid: Option<String>,
    /// Contains the key material the new Credential is to be bound to
    pub jwk: Option<Jwk>,
    /// Contains at least one certificate where the first certificate
    /// contains the key that the Credential is to be bound to
    pub x5c: Option<Vec<String>>,
    /// Contains a key attestation as described in `OID4VCI Appendix D`
    pub attestation: Option<String>,
    /// Contains an OpenID Federation Trust Chain
    pub trust_chain: Option<Vec<String>>,
}

/// JWT body for OpenID4VCI proof JWTs as defined in [OID4VCI Appendix F]
///
/// [OID4VCI Appendix F]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-jwt-proof-type
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize)]
pub struct Claims {
    /// Audience: the `credential_issuer` URL from issuer metadata.
    pub aud: String,
    /// Issued-at (Unix epoch seconds).
    pub iat: i64,
    /// `client_id` of the Client making the request.
    /// Optional for Pre-Authorized Code Flow with anonymous
    /// access to the token endpoint
    pub iss: Option<String>,
    /// Nonce from the issuer, bound to this request.
    /// Must be present when the issuer has a nonce endpoint.
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
    algorithm: Algorithm,
    header_b64: String,
}

#[derive(Debug)]
enum KeyMaterial {
    Ecdsa(ecdsa::KeyPair),
    Ed25519(ed25519::KeyPair),
    Rsa(rsa::KeyPair),
}

impl CryptoSigner {
    /// Creates a signer from an ECDSA private key in PKCS#8 format.
    pub fn from_ecdsa_der(der: impl AsRef<[u8]>) -> Result<Self> {
        let key = KeyMaterial::Ecdsa(ecdsa::KeyPair::from_pkcs8_der(der.as_ref())?);
        let algorithm = key.algorithm();
        let header_b64 = build_header_b64(algorithm, &key)?;
        Ok(Self {
            key,
            algorithm,
            header_b64,
        })
    }

    /// Creates a signer from an Ed25519 private key in PKCS#8 format.
    pub fn from_ed25519_der(der: impl AsRef<[u8]>) -> Result<Self> {
        let key = KeyMaterial::Ed25519(ed25519::KeyPair::from_pkcs8_der(der.as_ref())?);
        let algorithm = key.algorithm();
        let header_b64 = build_header_b64(algorithm, &key)?;
        Ok(Self {
            key,
            algorithm,
            header_b64,
        })
    }

    /// Creates a signer from an RSA private key in PKCS#8 format.
    pub fn from_rsa_der(der: impl AsRef<[u8]>) -> Result<Self> {
        let key = KeyMaterial::Rsa(rsa::KeyPair::from_pkcs8_der(der.as_ref())?);
        let algorithm = key.algorithm();
        let header_b64 = build_header_b64(algorithm, &key)?;
        Ok(Self {
            key,
            algorithm,
            header_b64,
        })
    }

    /// Encode to a JWT with the given claims.
    fn encode(&self, claims: &Claims) -> Result<String> {
        let header_len = self.header_b64.len();

        let payload_b64 = base64_encode_type(claims)?;
        let payload_len = payload_b64.len();

        let mut signing_input = Vec::with_capacity(header_len + 1 + payload_len);
        signing_input.extend_from_slice(self.header_b64.as_bytes());
        signing_input.push(b'.');
        signing_input.extend_from_slice(payload_b64.as_bytes());

        let signature = self.sign_bytes(&signing_input)?;
        let sig_b64 = URL_SAFE_NO_PAD.encode(&signature);

        let jwt_len = header_len + 1 + payload_len + 1 + sig_b64.len();
        let mut jwt = String::with_capacity(jwt_len);
        jwt.push_str(&self.header_b64);
        jwt.push('.');
        jwt.push_str(&payload_b64);
        jwt.push('.');
        jwt.push_str(&sig_b64);
        Ok(jwt)
    }

    /// Sign `msg`, returning signature bytes.
    fn sign_bytes(&self, msg: &[u8]) -> Result<Vec<u8>> {
        match &self.key {
            KeyMaterial::Ecdsa(keypair) => match keypair.curve() {
                ecdsa::Curve::P256 | ecdsa::Curve::P256K1 => Ok(keypair.sign_sha256(msg)?.to_vec()),
                ecdsa::Curve::P384 => Ok(keypair.sign_sha384(msg)?.to_vec()),
                ecdsa::Curve::P521 => Ok(keypair.sign_sha512(msg)?.to_vec()),
            },
            KeyMaterial::Ed25519(keypair) => Ok(keypair.sign(msg).to_vec()),
            KeyMaterial::Rsa(keypair) => {
                let sig_len = keypair.modulus_len();
                let mut sig = vec![0u8; sig_len];
                let sig = match sig_len {
                    256 => keypair.sign_pss_sha256(msg, &mut sig)?,
                    384 => keypair.sign_pss_sha384(msg, &mut sig)?,
                    512 => keypair.sign_pss_sha512(msg, &mut sig)?,
                    _ => keypair.sign_pss_sha256(msg, &mut sig)?,
                };
                Ok(sig.to_vec())
            }
        }
    }
}

impl ProofSigner for CryptoSigner {
    fn sign(&self, claims: &Claims) -> Result<String> {
        self.encode(claims)
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

/// Builds the base64url-encoded JWT header.
fn build_header_b64(alg: Algorithm, key: &KeyMaterial) -> Result<String> {
    // Build minimal JWK from key material
    let jwk = match key {
        KeyMaterial::Ecdsa(keypair) => Jwk::try_from(keypair)?,
        KeyMaterial::Ed25519(keypair) => Jwk::try_from(keypair)?,
        KeyMaterial::Rsa(keypair) => Jwk::try_from(keypair)?,
    };

    let header = Header {
        alg,
        typ: OPENID4VCI_PROOF_JWT_TYP,
        kid: None,
        jwk: Some(jwk),
        x5c: None,
        attestation: None,
        trust_chain: None,
    };
    base64_encode_type(&header)
}

fn base64_encode_type<T: Serialize>(value: &T) -> Result<String> {
    let buffer = serde_json::to_vec(value)?;
    Ok(b64_encode(buffer))
}

fn b64_encode<T: AsRef<[u8]>>(value: T) -> String {
    URL_SAFE_NO_PAD.encode(value)
}

impl From<cloud_wallet_crypto::Error> for ClientError {
    fn from(error: cloud_wallet_crypto::error::Error) -> Self {
        ClientError::internal(format!("underlying crypto error: {error}"))
    }
}

impl From<serde_json::Error> for ClientError {
    fn from(error: serde_json::Error) -> Self {
        ClientError::internal(format!("JSON serialization error: {error}"))
    }
}

impl From<base64::EncodeSliceError> for ClientError {
    fn from(error: base64::EncodeSliceError) -> Self {
        ClientError::internal(format!("base64 encoding error: {error}"))
    }
}
