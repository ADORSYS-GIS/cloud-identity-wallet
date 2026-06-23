use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use cloud_wallet_crypto::jwk::Jwk;
use cloud_wallet_crypto::rand;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::oid4vci::client::Algorithm;
use crate::oid4vci::client::ClientError;
use crate::oid4vci::client::JwtSigner;

type Result<T> = std::result::Result<T, ClientError>;

const OAUTH_CLIENT_ATTESTATION_TYP: &str = "oauth-client-attestation+jwt";
const OAUTH_CLIENT_ATTESTATION_POP_TYP: &str = "oauth-client-attestation-pop+jwt";

/// Wallet Attestation JWT claims as defined in OID4VCI Appendix E.
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct WalletAttestation {
    pub iss: String,

    pub sub: String,

    /// Issued-at time (Unix epoch seconds).
    pub iat: i64,

    /// Expiration time (Unix epoch seconds).
    pub exp: i64,

    pub nbf: Option<i64>,

    pub wallet_name: Option<String>,

    pub wallet_link: Option<String>,

    pub status: Option<serde_json::Value>,

    pub cnf: Cnf,
}

/// Confirmation claim containing the public key used for PoP.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Cnf {
    pub jwk: Jwk,
}

/// Client Attestation PoP JWT claims as defined in
/// I-D.ietf-oauth-attestation-based-client-auth Section 5.2.
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
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

/// Constructs and signs Wallet Attestation and Client Attestation PoP JWTs.
#[derive(Debug)]
#[non_exhaustive]
pub struct WalletAttestationSigner {
    attestation_jwt: String,
    attestation_claims: WalletAttestation,
    wallet_key: JwtSigner,
    provider_public_jwk: Jwk,
}

impl WalletAttestationSigner {
    /// Creates a new signer.
    ///
    /// The `provider_key` signs the attestation JWT. The `wallet_key` must have a
    /// public JWK and is used to sign the PoP JWTs. The `cnf` claim is overwritten
    /// with the wallet key's public JWK.
    pub fn new(
        provider_key: JwtSigner,
        mut attestation_claims: WalletAttestation,
        wallet_key: JwtSigner,
    ) -> Result<Self> {
        let jwk = wallet_key.public_jwk().clone();
        attestation_claims.cnf = Cnf { jwk: jwk.clone() };

        let attestation_header = AttestationHeader {
            alg: provider_key.algorithm(),
            typ: OAUTH_CLIENT_ATTESTATION_TYP,
            kid: None,
            x5c: None,
        };

        // Ensure x5c is either None or contains at least one certificate
        if matches!(attestation_header.x5c, Some(ref x5c) if x5c.is_empty()) {
            return Err(ClientError::validation(
                "x5c must contain at least one certificate when present",
            ));
        }

        let attestation_jwt = provider_key.encode(&attestation_header, &attestation_claims)?;

        Ok(Self {
            attestation_jwt,
            attestation_claims,
            wallet_key,
            provider_public_jwk: provider_key.public_jwk().clone(),
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

    /// Returns the provider's public JWK used to verify the attestation JWT.
    pub fn provider_public_jwk(&self) -> &Jwk {
        &self.provider_public_jwk
    }

    /// Generates a Client Attestation PoP JWT for the given audience.
    pub fn pop_jwt(&self, audience: &str, nonce: Option<&str>) -> Result<String> {
        let jwk = self.wallet_key.public_jwk().clone();

        let pop_header = PopHeader {
            alg: self.wallet_key.algorithm(),
            typ: OAUTH_CLIENT_ATTESTATION_POP_TYP,
            kid: None,
            jwk,
        };

        // Generate cryptographically unpredictable jti using CSPRNG (16 random bytes)
        let mut jti_bytes = [0u8; 16];
        rand::fill_bytes(&mut jti_bytes)
            .map_err(|e| ClientError::internal(format!("failed to generate random jti: {e}")))?;
        let jti = URL_SAFE_NO_PAD.encode(jti_bytes);

        let claims = ClientAttestationPop {
            jti: format!("pop-{jti}"),
            aud: audience.to_string(),
            iat: jsonwebtoken::get_current_timestamp() as i64,
            nonce: nonce.map(|s| s.to_string()),
        };

        self.wallet_key.encode(&pop_header, &claims)
    }

    /// Validates the attestation JWT by verifying its signature against the wallet
    /// provider public key and checking that it is not expired.
    pub fn validate_attestation(&self) -> Result<()> {
        let header = jsonwebtoken::decode_header(&self.attestation_jwt)
            .map_err(|e| ClientError::validation(format!("invalid attestation JWT header: {e}")))?;
        let jwk_json = serde_json::to_value(&self.provider_public_jwk).map_err(|e| {
            ClientError::validation(format!("failed to serialize provider JWK: {e}"))
        })?;
        let jwt_jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(jwk_json)
            .map_err(|e| ClientError::validation(format!("invalid provider JWK: {e}")))?;
        let decoding_key = jsonwebtoken::DecodingKey::from_jwk(&jwt_jwk)
            .map_err(|e| ClientError::validation(format!("invalid provider JWK: {e}")))?;

        let mut validation = jsonwebtoken::Validation::new(header.alg);
        validation.set_required_spec_claims(&["exp"]);
        let _ = jsonwebtoken::decode::<WalletAttestation>(
            &self.attestation_jwt,
            &decoding_key,
            &validation,
        )
        .map_err(|e| match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                ClientError::validation("wallet attestation has expired")
            }
            jsonwebtoken::errors::ErrorKind::ImmatureSignature => {
                ClientError::validation("wallet attestation is not yet valid")
            }
            _ => ClientError::validation(format!("attestation JWT validation failed: {e}")),
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use cloud_wallet_crypto::ecdsa::{Curve, KeyPair as EcdsaKeyPair};
    use jsonwebtoken::{Algorithm as JwtAlgorithm, DecodingKey, Validation, decode, decode_header};

    fn get_ecdsa_keys() -> (JwtSigner, JwtSigner) {
        let provider_keypair = EcdsaKeyPair::generate(Curve::P256).unwrap();
        let wallet_keypair = EcdsaKeyPair::generate(Curve::P256).unwrap();
        let provider_der = provider_keypair.to_pkcs8_der().to_vec();
        let wallet_der = wallet_keypair.to_pkcs8_der().to_vec();
        (
            JwtSigner::from_ecdsa_der(&provider_der).unwrap(),
            JwtSigner::from_ecdsa_der(&wallet_der).unwrap(),
        )
    }

    fn sample_attestation_claims() -> WalletAttestation {
        let now = jsonwebtoken::get_current_timestamp() as i64;
        WalletAttestation {
            iss: "https://wallet-provider.example.com".to_string(),
            sub: "https://wallet.example.org".to_string(),
            iat: now,
            exp: now + 3600,
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
        claims.exp = jsonwebtoken::get_current_timestamp() as i64 - 3600; // expired 1 hour ago
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

    #[test]
    fn test_attestation_signature_verification() {
        let (provider_key, wallet_key) = get_ecdsa_keys();
        let claims = sample_attestation_claims();
        let signer = WalletAttestationSigner::new(provider_key, claims, wallet_key).unwrap();

        // Should pass with the correct provider key
        assert!(signer.validate_attestation().is_ok());
    }

    #[test]
    fn test_tampered_attestation_rejected() {
        let (provider_key, wallet_key) = get_ecdsa_keys();
        let claims = sample_attestation_claims();
        let mut signer = WalletAttestationSigner::new(provider_key, claims, wallet_key).unwrap();

        // Tamper with the stored JWT payload (flip a byte in the base64 payload)
        let parts: Vec<&str> = signer.attestation_jwt.split('.').collect();
        // Reconstruct with a modified payload - just append a character to make it invalid
        signer.attestation_jwt = format!("{}.{}x.{}", parts[0], parts[1], parts[2]);

        let result = signer.validate_attestation();
        assert!(result.is_err());
    }

    #[test]
    fn test_pop_jwt_jwk_does_not_leak_private_key() {
        let (provider_key, wallet_key) = get_ecdsa_keys();
        let claims = sample_attestation_claims();
        let signer = WalletAttestationSigner::new(provider_key, claims, wallet_key).unwrap();

        // Generate PoP JWT
        let pop_jwt = signer.pop_jwt("https://as.example.com/par", None).unwrap();

        // Decode the header and extract the jwk
        let header = decode_header(&pop_jwt).unwrap();
        let jwk = header.jwk.as_ref().unwrap();

        // Serialize the JWK to JSON and verify no private key parameters are present
        let jwk_value: serde_json::Value = serde_json::to_value(jwk).unwrap();

        // For ECDSA keys, 'd' is the private key parameter that must NOT be present
        assert!(
            jwk_value.get("d").is_none(),
            "PoP JWT jwk header must not contain private key parameter 'd'"
        );

        // Additional check: ensure public key parameters ARE present
        assert!(
            jwk_value.get("x").is_some() && jwk_value.get("y").is_some(),
            "PoP JWT jwk header must contain public key parameters 'x' and 'y'"
        );

        // Verify the JWK represents an EC key
        assert_eq!(
            jwk_value.get("kty").and_then(|v| v.as_str()),
            Some("EC"),
            "PoP JWT jwk must have kty='EC'"
        );
    }
}
