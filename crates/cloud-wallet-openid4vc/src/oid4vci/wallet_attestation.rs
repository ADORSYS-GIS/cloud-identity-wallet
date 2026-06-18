use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use cloud_wallet_crypto::{ecdsa, ed25519, jwk::Jwk, rsa};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::oid4vci::client::Algorithm;
use crate::oid4vci::client::ClientError;

type Result<T> = std::result::Result<T, ClientError>;

const OAUTH_CLIENT_ATTESTATION_TYP: &str = "oauth-client-attestation+jwt";
const OAUTH_CLIENT_ATTESTATION_POP_TYP: &str = "oauth-client-attestation-pop+jwt";

/// Wallet Attestation JWT claims as defined in OID4VCI Appendix E.
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletAttestation {
    pub iss: String,

    pub sub: String,

    pub iat: i64,

    pub exp: i64,

    pub nbf: Option<i64>,

    pub wallet_name: Option<String>,

    pub wallet_link: Option<String>,

    pub status: Option<serde_json::Value>,

    pub cnf: Cnf,
}

/// Confirmation claim containing the public key used for PoP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cnf {
    pub jwk: Jwk,
}

/// Client Attestation PoP JWT claims as defined in
/// I-D.ietf-oauth-attestation-based-client-auth Section 5.2.
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientAttestationPop {
    /// Unique identifier for the PoP JWT.
    pub jti: String,
    /// Audience: the endpoint URL.
    pub aud: String,
    /// Issued-at time (Unix epoch seconds).
    pub iat: i64,
    /// Optional nonce from the server.
    pub nonce: Option<String>,
}

/// JOSE header for the Wallet Attestation JWT.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AttestationHeader {
    pub alg: Algorithm,
    pub typ: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,
}

/// JOSE header for the Client Attestation PoP JWT.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PopHeader {
    pub alg: Algorithm,
    pub typ: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    pub jwk: Jwk,
}

/// A cryptographic key used for signing JWTs in the wallet attestation flow.
#[derive(Debug)]
pub struct AttestationKey {
    key: KeyMaterial,
    algorithm: Algorithm,
    public_jwk: Option<Jwk>,
}

#[derive(Debug)]
enum KeyMaterial {
    Ecdsa(ecdsa::KeyPair),
    Ed25519(ed25519::KeyPair),
    Rsa(rsa::KeyPair),
}

impl AttestationKey {
    /// Creates an attestation key from an ECDSA private key in PKCS#8 format.
    pub fn from_ecdsa_der(der: impl AsRef<[u8]>) -> Result<Self> {
        let ecdsa_key = ecdsa::KeyPair::from_pkcs8_der(der.as_ref())
            .map_err(|e| ClientError::internal(format!("crypto error: {e}")))?;
        let key = KeyMaterial::Ecdsa(ecdsa_key);
        let algorithm = key.algorithm();
        let public_jwk = match &key {
            KeyMaterial::Ecdsa(k) => Some(Jwk::try_from(k).map_err(|e| {
                ClientError::internal(format!("failed to convert key to JWK: {e}"))
            })?),
            _ => unreachable!(),
        };
        Ok(Self {
            key,
            algorithm,
            public_jwk,
        })
    }

    /// Creates an attestation key from an Ed25519 private key in PKCS#8 format.
    pub fn from_ed25519_der(der: impl AsRef<[u8]>) -> Result<Self> {
        let ed25519_key = ed25519::KeyPair::from_pkcs8_der(der.as_ref())
            .map_err(|e| ClientError::internal(format!("crypto error: {e}")))?;
        let key = KeyMaterial::Ed25519(ed25519_key);
        let algorithm = key.algorithm();
        let public_jwk = match &key {
            KeyMaterial::Ed25519(k) => Some(Jwk::try_from(k).map_err(|e| {
                ClientError::internal(format!("failed to convert key to JWK: {e}"))
            })?),
            _ => unreachable!(),
        };
        Ok(Self {
            key,
            algorithm,
            public_jwk,
        })
    }

    /// Creates an attestation key from an RSA private key in PKCS#8 format.
    pub fn from_rsa_der(der: impl AsRef<[u8]>) -> Result<Self> {
        let rsa_key = rsa::KeyPair::from_pkcs8_der(der.as_ref())
            .map_err(|e| ClientError::internal(format!("crypto error: {e}")))?;
        let key = KeyMaterial::Rsa(rsa_key);
        let algorithm = key.algorithm();
        let public_jwk = match &key {
            KeyMaterial::Rsa(k) => Some(Jwk::try_from(k).map_err(|e| {
                ClientError::internal(format!("failed to convert key to JWK: {e}"))
            })?),
            _ => unreachable!(),
        };
        Ok(Self {
            key,
            algorithm,
            public_jwk,
        })
    }

    /// Returns the JWS algorithm.
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Returns the public JWK, if available.
    pub fn public_jwk(&self) -> Option<&Jwk> {
        self.public_jwk.as_ref()
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        self.key.sign(msg)
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

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        use ecdsa::Curve;
        match self {
            KeyMaterial::Ecdsa(keypair) => match keypair.curve() {
                Curve::P256 | Curve::P256K1 => Ok(keypair.sign_sha256(msg)?.to_vec()),
                Curve::P384 => Ok(keypair.sign_sha384(msg)?.to_vec()),
                Curve::P521 => Ok(keypair.sign_sha512(msg)?.to_vec()),
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

/// Constructs and signs Wallet Attestation and Client Attestation PoP JWTs.
#[derive(Debug)]
pub struct WalletAttestationSigner {
    attestation_jwt: String,
    attestation_claims: WalletAttestation,
    wallet_key: AttestationKey,
}

impl WalletAttestationSigner {
    /// Creates a new signer.
    ///
    /// The `provider_key` signs the attestation JWT. The `wallet_key` must have a
    /// public JWK and is used to sign the PoP JWTs. The `cnf` claim is overwritten
    /// with the wallet key's public JWK.
    pub fn new(
        provider_key: AttestationKey,
        mut attestation_claims: WalletAttestation,
        wallet_key: AttestationKey,
    ) -> Result<Self> {
        let jwk = wallet_key.public_jwk().ok_or_else(|| {
            ClientError::configuration("wallet key must have a public JWK for cnf claim")
        })?;
        attestation_claims.cnf = Cnf { jwk: jwk.clone() };

        let attestation_header = AttestationHeader {
            alg: provider_key.algorithm(),
            typ: OAUTH_CLIENT_ATTESTATION_TYP,
            kid: None,
            x5c: None,
        };

        let attestation_jwt = sign_jwt(&provider_key, &attestation_header, &attestation_claims)?;

        Ok(Self {
            attestation_jwt,
            attestation_claims,
            wallet_key,
        })
    }

    /// Returns the signed Wallet Attestation JWT.
    pub fn attestation_jwt(&self) -> &str {
        &self.attestation_jwt
    }

    /// Returns the `client_id` (the `sub` claim of the attestation).
    pub fn client_id(&self) -> &str {
        &self.attestation_claims.sub
    }

    /// Generates a Client Attestation PoP JWT for the given audience.
    pub fn pop_jwt(&self, audience: &str, nonce: Option<&str>) -> Result<String> {
        let jwk = self
            .wallet_key
            .public_jwk()
            .ok_or_else(|| ClientError::internal("wallet key must have a public JWK"))?;

        let pop_header = PopHeader {
            alg: self.wallet_key.algorithm(),
            typ: OAUTH_CLIENT_ATTESTATION_POP_TYP,
            kid: None,
            jwk: jwk.clone(),
        };

        let claims = ClientAttestationPop {
            jti: format!("pop-{}", current_timestamp_nanos()),
            aud: audience.to_string(),
            iat: current_timestamp(),
            nonce: nonce.map(|s| s.to_string()),
        };

        sign_jwt(&self.wallet_key, &pop_header, &claims)
    }

    /// Validates that the attestation is not expired.
    pub fn validate_attestation(&self) -> Result<()> {
        let now = current_timestamp();
        if now >= self.attestation_claims.exp {
            return Err(ClientError::validation("wallet attestation has expired"));
        }
        if let Some(nbf) = self.attestation_claims.nbf
            && now < nbf
        {
            return Err(ClientError::validation(
                "wallet attestation is not yet valid",
            ));
        }

        Ok(())
    }
}

fn sign_jwt<T: Serialize, H: Serialize>(
    key: &AttestationKey,
    header: &H,
    claims: &T,
) -> Result<String> {
    let header_b64 = base64_encode_type(header)?;
    let payload_b64 = base64_encode_type(claims)?;
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = key.sign(signing_input.as_bytes())?;
    let sig_b64 = b64_encode(signature);
    Ok(format!("{header_b64}.{payload_b64}.{sig_b64}"))
}

fn base64_encode_type<T: Serialize>(value: &T) -> Result<String> {
    let serialized = serde_json::to_vec(value)?;
    Ok(b64_encode(serialized))
}

fn b64_encode<T: AsRef<[u8]>>(value: T) -> String {
    URL_SAFE_NO_PAD.encode(value)
}

fn current_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_secs() as i64
}

fn current_timestamp_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_nanos()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cloud_wallet_crypto::ecdsa::{Curve, KeyPair as EcdsaKeyPair};
    use jsonwebtoken::{Algorithm as JwtAlgorithm, DecodingKey, Validation, decode, decode_header};

    fn get_ecdsa_keys() -> (AttestationKey, AttestationKey) {
        let provider_keypair = EcdsaKeyPair::generate(Curve::P256).unwrap();
        let wallet_keypair = EcdsaKeyPair::generate(Curve::P256).unwrap();
        let provider_der = provider_keypair.to_pkcs8_der().to_vec();
        let wallet_der = wallet_keypair.to_pkcs8_der().to_vec();
        (
            AttestationKey::from_ecdsa_der(&provider_der).unwrap(),
            AttestationKey::from_ecdsa_der(&wallet_der).unwrap(),
        )
    }

    fn sample_attestation_claims() -> WalletAttestation {
        WalletAttestation {
            iss: "https://wallet-provider.example.com".to_string(),
            sub: "https://wallet.example.org".to_string(),
            iat: current_timestamp(),
            exp: current_timestamp() + 3600,
            nbf: None,
            wallet_name: Some("Test Wallet".to_string()),
            wallet_link: None,
            status: None,
            cnf: Cnf {
                jwk: Jwk::try_from(&EcdsaKeyPair::generate(Curve::P256).unwrap()).unwrap(),
            },
        }
    }

    fn decode_attestation_payload(jwt: &str) -> WalletAttestation {
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .unwrap();
        serde_json::from_slice(&payload_bytes).unwrap()
    }

    #[test]
    fn test_valid_attestation_and_pop() {
        let (provider_key, wallet_key) = get_ecdsa_keys();
        let claims = sample_attestation_claims();
        let signer = WalletAttestationSigner::new(provider_key, claims, wallet_key).unwrap();

        // Verify attestation JWT structure
        let attestation_jwt = signer.attestation_jwt();
        let parts: Vec<&str> = attestation_jwt.split('.').collect();
        assert_eq!(parts.len(), 3);

        // Decode attestation payload and verify claims
        let decoded_claims = decode_attestation_payload(attestation_jwt);
        assert_eq!(decoded_claims.iss, "https://wallet-provider.example.com");
        assert_eq!(decoded_claims.sub, "https://wallet.example.org");
        assert_eq!(decoded_claims.wallet_name, Some("Test Wallet".to_string()));
        assert!(decoded_claims.exp > decoded_claims.iat);
        assert!(matches!(
            decoded_claims.cnf.jwk.key,
            cloud_wallet_crypto::jwk::Key::Ec(_)
        ));

        // Verify client_id
        assert_eq!(signer.client_id(), "https://wallet.example.org");

        // Generate and verify PoP
        let pop_jwt = signer.pop_jwt("https://as.example.com/par", None).unwrap();
        let pop_header = decode_header(&pop_jwt).unwrap();
        assert_eq!(pop_header.alg, JwtAlgorithm::ES256);
        assert_eq!(
            pop_header.typ,
            Some(OAUTH_CLIENT_ATTESTATION_POP_TYP.to_string())
        );
        assert!(pop_header.jwk.is_some());

        let mut pop_validation = Validation::new(JwtAlgorithm::ES256);
        pop_validation.set_audience(&["https://as.example.com/par"]);
        pop_validation.set_required_spec_claims(&["jti", "aud", "iat"]);
        let pop_decoding_key = DecodingKey::from_jwk(&pop_header.jwk.unwrap()).unwrap();
        let pop_data =
            decode::<ClientAttestationPop>(&pop_jwt, &pop_decoding_key, &pop_validation).unwrap();
        assert_eq!(pop_data.claims.aud, "https://as.example.com/par");
        assert!(pop_data.claims.jti.starts_with("pop-"));
        assert!(pop_data.claims.nonce.is_none());
    }

    #[test]
    fn test_expired_attestation_rejection() {
        let (provider_key, wallet_key) = get_ecdsa_keys();
        let mut claims = sample_attestation_claims();
        claims.exp = current_timestamp() - 3600; // expired 1 hour ago
        let signer = WalletAttestationSigner::new(provider_key, claims, wallet_key).unwrap();

        let result = signer.validate_attestation();
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("expired"));
    }

    #[test]
    fn test_wrong_aud_in_pop() {
        let (provider_key, wallet_key) = get_ecdsa_keys();
        let claims = sample_attestation_claims();
        let signer = WalletAttestationSigner::new(provider_key, claims, wallet_key).unwrap();

        let pop_jwt = signer.pop_jwt("https://as.example.com/par", None).unwrap();
        let pop_header = decode_header(&pop_jwt).unwrap();
        let pop_decoding_key = DecodingKey::from_jwk(&pop_header.jwk.unwrap()).unwrap();

        // Verify correct aud passes
        let mut validation = Validation::new(JwtAlgorithm::ES256);
        validation.set_audience(&["https://as.example.com/par"]);
        validation.set_required_spec_claims(&["jti", "aud", "iat"]);
        let result = decode::<ClientAttestationPop>(&pop_jwt, &pop_decoding_key, &validation);
        assert!(result.is_ok());

        // Verify wrong aud fails
        let mut wrong_validation = Validation::new(JwtAlgorithm::ES256);
        wrong_validation.set_audience(&["https://other.example.com/par"]);
        wrong_validation.set_required_spec_claims(&["jti", "aud", "iat"]);
        let result = decode::<ClientAttestationPop>(&pop_jwt, &pop_decoding_key, &wrong_validation);
        assert!(result.is_err());
    }
}
