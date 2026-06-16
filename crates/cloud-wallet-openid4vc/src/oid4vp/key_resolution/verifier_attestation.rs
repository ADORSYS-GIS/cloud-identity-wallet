use jsonwebtoken::{DecodingKey, Header};

use crate::errors::{Error, ErrorKind};
use crate::oid4vp::client_id::ParsedClientId;
use crate::oid4vp::request_object::VerifierKeyResolver;
use crate::oid4vp::verifier_attestation::{TrustedAttestationIssuer, VerifierAttestationJwt};

/// Key resolver for `verifier_attestation:` client identifier prefix.
///
/// Implements the `VerifierKeyResolver` trait to resolve the Verifier's public key
/// from a Verifier Attestation JWT as defined in OpenID4VP §5.9.3 and §12.
pub struct VerifierAttestationKey {
    trusted_issuers: Vec<TrustedAttestationIssuer>,

    /// The URI to validate against the attestation's `redirect_uris` allowlist.
    /// Each resolver instance is bound to a single request's response_uri/redirect_uri.
    /// If the trait ever gains a request-context parameter, this field should move
    /// to the method signature instead.
    expected_uri: String,
}

impl VerifierAttestationKey {
    /// Creates a new `VerifierAttestationKey` resolver.
    pub fn new(trusted_issuers: Vec<TrustedAttestationIssuer>, expected_uri: String) -> Self {
        Self {
            trusted_issuers,
            expected_uri,
        }
    }

    /// Extracts the attestation JWT from the JOSE header's `jwt` field.
    ///
    /// Per OpenID4VP §5.9.3, the Verifier Attestation JWT is passed in the
    /// Request Object's JOSE header as a custom `jwt` parameter.
    fn extract_jwt_from_header(header: &Header) -> crate::errors::Result<&str> {
        let jwt_value = header
            .extras
            .get("jwt")
            .map(|s| s.as_str())
            .ok_or_else(|| {
                Error::message(
                    ErrorKind::InvalidPresentationRequest,
                    "missing required 'jwt' header parameter for verifier_attestation client_id",
                )
            })?;

        Ok(jwt_value)
    }
}

#[async_trait::async_trait]
impl VerifierKeyResolver for VerifierAttestationKey {
    async fn resolve_key(
        &self,
        client_id: &ParsedClientId,
        header: &Header,
    ) -> crate::errors::Result<DecodingKey> {
        // Verify this is a verifier_attestation client_id
        if !client_id.is_verifier_attestation() {
            return Err(Error::message(
                ErrorKind::InvalidPresentationRequest,
                format!(
                    "VerifierAttestationKey can only resolve verifier_attestation client_ids, got: {}",
                    client_id.raw()
                ),
            ));
        }

        // Extract the unprefixed client_id value (the sub claim expected value)
        let verifier_id = client_id.value();

        // Extract the attestation JWT from the header's `jwt` field
        let attestation_jwt = Self::extract_jwt_from_header(header)?;

        // Decode and validate the attestation JWT
        let attestation = VerifierAttestationJwt::decode_and_validate(
            attestation_jwt,
            verifier_id,
            &self.trusted_issuers,
        )
        .map_err(|e| Error::new(ErrorKind::InvalidPresentationRequest, e))?;

        // Validate redirect_uris allowlist against the expected URI
        // Per OpenID4VP §12, the attestation contains an allowlist of redirect_uris
        // that the verifier is authorized to use. A missing allowlist means no URIs
        // are allowed, not that all URIs are allowed.
        if attestation.allowed_redirect_uris().is_none() {
            return Err(Error::message(
                ErrorKind::InvalidPresentationRequest,
                "verifier attestation must include redirect_uris to authorize a response_uri",
            ));
        }
        attestation
            .validate_redirect_uri(&self.expected_uri)
            .map_err(|e| Error::new(ErrorKind::InvalidPresentationRequest, e))?;

        // Convert cnf.jwk to DecodingKey
        let jwk = attestation.verifier_public_key();
        let decoding_key = crate::oid4vp::jwk_to_decoding_key(jwk)
            .map_err(|e| Error::message(ErrorKind::InvalidPresentationRequest, e))?;

        Ok(decoding_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cloud_wallet_crypto::jwk::{Jwk, KeyUse, Operations, Parameters};
    use jsonwebtoken::{Algorithm, EncodingKey};

    const TEST_ISSUER: &str = "https://attestation.example.com";
    const TEST_VERIFIER_ID: &str = "verifier123";
    const TEST_RESPONSE_URI: &str = "https://verifier.example.com/cb1";

    /// Helper struct to manage test keys.
    struct TestKeys {
        issuer_key_pair: cloud_wallet_crypto::ecdsa::KeyPair,
        verifier_key_pair: cloud_wallet_crypto::ecdsa::KeyPair,
    }

    impl TestKeys {
        fn generate() -> Self {
            Self {
                issuer_key_pair: cloud_wallet_crypto::ecdsa::KeyPair::generate(
                    cloud_wallet_crypto::ecdsa::Curve::P256,
                )
                .expect("failed to generate issuer key"),
                verifier_key_pair: cloud_wallet_crypto::ecdsa::KeyPair::generate(
                    cloud_wallet_crypto::ecdsa::Curve::P256,
                )
                .expect("failed to generate verifier key"),
            }
        }

        fn issuer_jwk(&self) -> Jwk {
            Jwk::try_from(&self.issuer_key_pair).expect("failed to convert issuer key to JWK")
        }

        fn verifier_jwk(&self) -> Jwk {
            let mut jwk = Jwk::try_from(&self.verifier_key_pair)
                .expect("failed to convert verifier key to JWK");
            jwk.prm.key_use = Some(KeyUse::Signing);
            jwk.prm.ops = Some([Operations::Verify, Operations::Sign].into_iter().collect());
            jwk
        }

        fn issuer_encoding_key(&self) -> EncodingKey {
            let secret = self.issuer_key_pair.to_pkcs8_der();
            EncodingKey::from_ec_der(secret)
        }
    }

    /// Helper to create a JWK with the required metadata for a verifier key.
    fn create_verifier_jwk(keys: &TestKeys) -> Jwk {
        let mut jwk = keys.verifier_jwk();
        jwk.prm = Parameters {
            key_use: Some(KeyUse::Signing),
            ops: Some([Operations::Verify, Operations::Sign].into_iter().collect()),
            ..Default::default()
        };
        jwk
    }

    /// Creates claims for a Verifier Attestation JWT.
    fn create_attestation_claims(
        keys: &TestKeys,
        verifier_id: &str,
        redirect_uris: Vec<String>,
        exp_offset: i64,
    ) -> crate::oid4vp::verifier_attestation::VerifierAttestationClaims {
        use crate::oid4vp::verifier_attestation::{CnfClaim, VerifierAttestationClaims};

        let now = jsonwebtoken::get_current_timestamp() as i64;
        VerifierAttestationClaims {
            iss: TEST_ISSUER.to_string(),
            sub: verifier_id.to_string(),
            aud: None,
            iat: Some(now),
            exp: now + exp_offset,
            nbf: None,
            jti: Some("test-jti".to_string()),
            cnf: CnfClaim {
                jwk: create_verifier_jwk(keys),
            },
            redirect_uris: Some(redirect_uris),
            nonce: None,
        }
    }

    /// Creates claims for a Verifier Attestation JWT without redirect_uris.
    fn create_attestation_claims_no_redirect_uris(
        keys: &TestKeys,
        verifier_id: &str,
        exp_offset: i64,
    ) -> crate::oid4vp::verifier_attestation::VerifierAttestationClaims {
        use crate::oid4vp::verifier_attestation::{CnfClaim, VerifierAttestationClaims};

        let now = jsonwebtoken::get_current_timestamp() as i64;
        VerifierAttestationClaims {
            iss: TEST_ISSUER.to_string(),
            sub: verifier_id.to_string(),
            aud: None,
            iat: Some(now),
            exp: now + exp_offset,
            nbf: None,
            jti: Some("test-jti".to_string()),
            cnf: CnfClaim {
                jwk: create_verifier_jwk(keys),
            },
            redirect_uris: None,
            nonce: None,
        }
    }

    /// Creates a signed Verifier Attestation JWT.
    fn create_attestation_jwt(
        keys: &TestKeys,
        claims: &crate::oid4vp::verifier_attestation::VerifierAttestationClaims,
    ) -> String {
        use crate::oid4vp::verifier_attestation::VerifierAttestationJwt;

        let header = jsonwebtoken::Header {
            typ: Some(VerifierAttestationJwt::EXPECTED_TYP.to_string()),
            alg: Algorithm::ES256,
            kid: None,
            ..Default::default()
        };

        jsonwebtoken::encode(&header, claims, &keys.issuer_encoding_key())
            .expect("failed to encode attestation JWT")
    }

    /// Creates a trusted issuer configuration.
    fn create_trusted_issuer(keys: &TestKeys) -> TrustedAttestationIssuer {
        TrustedAttestationIssuer {
            issuer_id: TEST_ISSUER.to_string(),
            jwks: vec![keys.issuer_jwk()],
        }
    }

    /// Creates a ParsedClientId for verifier_attestation prefix.
    fn create_client_id(verifier_id: &str) -> ParsedClientId {
        ParsedClientId::parse(format!("verifier_attestation:{verifier_id}"))
            .expect("valid client_id")
    }

    /// Creates a Header with the jwt field containing the attestation.
    fn create_header_with_jwt(attestation_jwt: &str) -> Header {
        let mut header = Header::new(Algorithm::ES256);
        header.typ = Some("oauth-authz-req+jwt".to_string());
        header
            .extras
            .insert("jwt".to_string(), attestation_jwt.to_string());
        header
    }

    #[tokio::test]
    async fn valid_attestation_resolves_key() {
        let keys = TestKeys::generate();
        let trusted_issuers = vec![create_trusted_issuer(&keys)];

        let claims = create_attestation_claims(
            &keys,
            TEST_VERIFIER_ID,
            vec![TEST_RESPONSE_URI.to_string()],
            3600,
        );
        let attestation_jwt = create_attestation_jwt(&keys, &claims);

        let resolver = VerifierAttestationKey::new(trusted_issuers, TEST_RESPONSE_URI.to_string());
        let client_id = create_client_id(TEST_VERIFIER_ID);
        let header = create_header_with_jwt(&attestation_jwt);

        let result = resolver.resolve_key(&client_id, &header).await;

        assert!(
            result.is_ok(),
            "Expected successful key resolution, got: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn untrusted_issuer_rejected() {
        let keys = TestKeys::generate();
        let other_keys = TestKeys::generate();

        // Use a different issuer key that is not trusted
        let trusted_issuers = vec![TrustedAttestationIssuer {
            issuer_id: TEST_ISSUER.to_string(),
            jwks: vec![other_keys.issuer_jwk()], // Different key
        }];

        let claims = create_attestation_claims(
            &keys,
            TEST_VERIFIER_ID,
            vec![TEST_RESPONSE_URI.to_string()],
            3600,
        );
        let attestation_jwt = create_attestation_jwt(&keys, &claims);

        let resolver = VerifierAttestationKey::new(trusted_issuers, TEST_RESPONSE_URI.to_string());
        let client_id = create_client_id(TEST_VERIFIER_ID);
        let header = create_header_with_jwt(&attestation_jwt);

        let result = resolver.resolve_key(&client_id, &header).await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("untrusted issuer") || err.contains("signature verification failed"),
            "Expected untrusted issuer error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn expired_attestation_rejected() {
        let keys = TestKeys::generate();
        let trusted_issuers = vec![create_trusted_issuer(&keys)];

        // Create expired claims
        let claims = create_attestation_claims(
            &keys,
            TEST_VERIFIER_ID,
            vec![TEST_RESPONSE_URI.to_string()],
            -3600, // Expired 1 hour ago
        );
        let attestation_jwt = create_attestation_jwt(&keys, &claims);

        let resolver = VerifierAttestationKey::new(trusted_issuers, TEST_RESPONSE_URI.to_string());
        let client_id = create_client_id(TEST_VERIFIER_ID);
        let header = create_header_with_jwt(&attestation_jwt);

        let result = resolver.resolve_key(&client_id, &header).await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("expired") || err.contains("attestation"),
            "Expected expired attestation error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn sub_mismatch_rejected() {
        let keys = TestKeys::generate();
        let trusted_issuers = vec![create_trusted_issuer(&keys)];

        // Create claims with wrong sub
        let claims = create_attestation_claims(
            &keys,
            "different-verifier", // Wrong sub
            vec![TEST_RESPONSE_URI.to_string()],
            3600,
        );
        let attestation_jwt = create_attestation_jwt(&keys, &claims);

        let resolver = VerifierAttestationKey::new(trusted_issuers, TEST_RESPONSE_URI.to_string());
        // Still using original verifier_id as client_id
        let client_id = create_client_id(TEST_VERIFIER_ID);
        let header = create_header_with_jwt(&attestation_jwt);

        let result = resolver.resolve_key(&client_id, &header).await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("sub") || err.contains("subject") || err.contains("mismatch"),
            "Expected subject mismatch error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn redirect_uris_violation_rejected() {
        let keys = TestKeys::generate();
        let trusted_issuers = vec![create_trusted_issuer(&keys)];

        // Create claims with different redirect_uris
        let claims = create_attestation_claims(
            &keys,
            TEST_VERIFIER_ID,
            vec!["https://other.example.com/cb".to_string()], // Different URI
            3600,
        );
        let attestation_jwt = create_attestation_jwt(&keys, &claims);

        // Expected URI doesn't match the allowlist
        let resolver = VerifierAttestationKey::new(trusted_issuers, TEST_RESPONSE_URI.to_string());
        let client_id = create_client_id(TEST_VERIFIER_ID);
        let header = create_header_with_jwt(&attestation_jwt);

        let result = resolver.resolve_key(&client_id, &header).await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("redirect_uri")
                || err.contains("response_uri")
                || err.contains("not allowed"),
            "Expected redirect_uri not allowed error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn missing_redirect_uris_rejected() {
        let keys = TestKeys::generate();
        let trusted_issuers = vec![create_trusted_issuer(&keys)];

        let claims = create_attestation_claims_no_redirect_uris(&keys, TEST_VERIFIER_ID, 3600);
        let attestation_jwt = create_attestation_jwt(&keys, &claims);

        let resolver = VerifierAttestationKey::new(trusted_issuers, TEST_RESPONSE_URI.to_string());
        let client_id = create_client_id(TEST_VERIFIER_ID);
        let header = create_header_with_jwt(&attestation_jwt);

        let result = resolver.resolve_key(&client_id, &header).await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("redirect_uris") || err.contains("response_uri"),
            "Expected missing redirect_uris error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn missing_jwt_header_rejected() {
        let keys = TestKeys::generate();
        let trusted_issuers = vec![create_trusted_issuer(&keys)];

        let resolver = VerifierAttestationKey::new(trusted_issuers, TEST_RESPONSE_URI.to_string());
        let client_id = create_client_id(TEST_VERIFIER_ID);

        // Header without jwt field
        let header = Header::new(Algorithm::ES256);

        let result = resolver.resolve_key(&client_id, &header).await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("jwt") && err.contains("missing"),
            "Expected missing jwt header error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn wrong_prefix_rejected() {
        let keys = TestKeys::generate();
        let trusted_issuers = vec![create_trusted_issuer(&keys)];

        let claims = create_attestation_claims(
            &keys,
            TEST_VERIFIER_ID,
            vec![TEST_RESPONSE_URI.to_string()],
            3600,
        );
        let attestation_jwt = create_attestation_jwt(&keys, &claims);

        let resolver = VerifierAttestationKey::new(trusted_issuers, TEST_RESPONSE_URI.to_string());
        // Use redirect_uri prefix instead of verifier_attestation
        let client_id = ParsedClientId::parse("redirect_uri:https://verifier.example.com").unwrap();
        let header = create_header_with_jwt(&attestation_jwt);

        let result = resolver.resolve_key(&client_id, &header).await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("verifier_attestation"),
            "Expected verifier_attestation prefix error, got: {}",
            err
        );
    }
}
