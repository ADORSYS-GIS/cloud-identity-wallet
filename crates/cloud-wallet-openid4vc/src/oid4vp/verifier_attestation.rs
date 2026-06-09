use std::collections::HashSet;

use cloud_wallet_crypto::jwk::Jwk;
use jsonwebtoken::{DecodingKey, Validation, decode, jwk::Jwk as JwtJwk};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::oid4vp::VerifierAttestationError;

/// Claims of a Verifier Attestation JWT.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierAttestationClaims {
    pub iss: String,

    pub sub: String,

    pub aud: Option<String>,

    pub iat: Option<i64>,

    pub exp: i64,

    pub nbf: Option<i64>,

    pub jti: Option<String>,

    pub cnf: CnfClaim,

    pub response_uris: Option<Vec<String>>,

    pub nonce: Option<String>,
}

/// A validated Verifier Attestation JWT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierAttestationJwt {
    claims: VerifierAttestationClaims,

    raw: String,
}

impl VerifierAttestationJwt {
    /// The expected `typ` header value for Verifier Attestation JWTs.
    pub const EXPECTED_TYP: &'static str = "verifier-attestation+jwt";

    /// Decodes and validates a Verifier Attestation JWT.
    pub fn decode_and_validate(
        jwt: &str,
        client_id: &str,
        trusted_issuers: &[TrustedAttestationIssuer],
    ) -> Result<Self, VerifierAttestationError> {
        let header = Self::decode_header(jwt)?;

        Self::validate_typ(&header)?;

        // Find the trusted issuer based on the 'iss' claim
        // We need to get the issuer from the claims first
        let unverified_claims = Self::decode_unverified_claims(jwt)?;

        let trusted_issuer = Self::find_trusted_issuer(&unverified_claims.iss, trusted_issuers)?;

        // Now perform full signature verification with the issuer's key
        let claims = Self::verify_signature(jwt, &header, trusted_issuer)?;

        // Validate the subject matches the expected client_id
        Self::validate_subject(&claims, client_id)?;

        // Validate temporal claims
        Self::validate_temporal(&claims)?;

        // Validate that cnf.jwk is present
        Self::validate_cnf(&claims)?;

        Ok(Self {
            claims,
            raw: jwt.to_string(),
        })
    }

    /// Decodes just the header to extract algorithm and key ID.
    fn decode_header(jwt: &str) -> Result<jsonwebtoken::Header, VerifierAttestationError> {
        jsonwebtoken::decode_header(jwt).map_err(|e| {
            VerifierAttestationError::InvalidFormat(format!("failed to decode header: {e}"))
        })
    }

    /// Decodes claims without signature verification.
    ///
    /// This is used to extract the issuer before we have the verification key.
    fn decode_unverified_claims(
        jwt: &str,
    ) -> Result<VerifierAttestationClaims, VerifierAttestationError> {
        use jsonwebtoken::dangerous::insecure_decode;

        let token_data = insecure_decode::<VerifierAttestationClaims>(jwt).map_err(|e| {
            VerifierAttestationError::DecodingFailed(format!("failed to decode claims: {e}"))
        })?;

        Ok(token_data.claims)
    }

    /// Validates the `typ` header parameter.
    fn validate_typ(header: &jsonwebtoken::Header) -> Result<(), VerifierAttestationError> {
        let actual_typ = header.typ.as_deref().unwrap_or("");
        if actual_typ != Self::EXPECTED_TYP {
            return Err(VerifierAttestationError::InvalidTyp {
                expected: Self::EXPECTED_TYP.to_string(),
                actual: actual_typ.to_string(),
            });
        }
        Ok(())
    }

    /// Finds the trusted issuer configuration for the given issuer ID.
    fn find_trusted_issuer<'a>(
        issuer_id: &str,
        trusted_issuers: &'a [TrustedAttestationIssuer],
    ) -> Result<&'a TrustedAttestationIssuer, VerifierAttestationError> {
        trusted_issuers
            .iter()
            .find(|issuer| issuer.issuer_id == issuer_id)
            .ok_or_else(|| VerifierAttestationError::UntrustedIssuer(issuer_id.to_string()))
    }

    /// Verifies the JWT signature using the trusted issuer's keys.
    fn verify_signature(
        jwt: &str,
        header: &jsonwebtoken::Header,
        trusted_issuer: &TrustedAttestationIssuer,
    ) -> Result<VerifierAttestationClaims, VerifierAttestationError> {
        // Find the appropriate key based on header (kid) or try all keys
        let key = Self::resolve_verification_key(header, &trusted_issuer.jwks)?;

        // Configure validation - we validate exp and iat here, others manually
        let mut validation = Validation::new(header.alg);
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.validate_aud = false; // Audience is optional per spec, validate manually if needed
        validation.required_spec_claims.clear();

        let token_data = decode::<VerifierAttestationClaims>(jwt, &key, &validation)
            .map_err(|e| VerifierAttestationError::SignatureVerificationFailed(e.to_string()))?;

        Ok(token_data.claims)
    }

    /// Resolves the verification key from the JWKS based on the header.
    fn resolve_verification_key(
        header: &jsonwebtoken::Header,
        jwks: &[Jwk],
    ) -> Result<DecodingKey, VerifierAttestationError> {
        // If there's a kid in the header, find the matching key
        if let Some(ref kid) = header.kid {
            let key = jwks.iter().find(|k| k.prm.kid.as_deref() == Some(kid));
            if let Some(key) = key {
                return Self::jwk_to_decoding_key(key);
            }
        }

        // If no kid or no matching key found, try the first key (if only one)
        if jwks.len() == 1 {
            return Self::jwk_to_decoding_key(&jwks[0]);
        }

        if !jwks.is_empty() {
            // Return the first key - the decode function will fail if it doesn't match
            return Self::jwk_to_decoding_key(&jwks[0]);
        }

        Err(VerifierAttestationError::SignatureVerificationFailed(
            "no verification keys available".to_string(),
        ))
    }

    /// Converts a JWK to a jsonwebtoken DecodingKey.
    fn jwk_to_decoding_key(jwk: &Jwk) -> Result<DecodingKey, VerifierAttestationError> {
        // Convert our Jwk type to jsonwebtoken's Jwk type
        let jwt_jwk = serde_json::to_value(jwk)
            .and_then(serde_json::from_value::<JwtJwk>)
            .map_err(|e| {
                VerifierAttestationError::SignatureVerificationFailed(format!(
                    "failed to convert JWK: {e}"
                ))
            })?;

        DecodingKey::from_jwk(&jwt_jwk).map_err(|e| {
            VerifierAttestationError::SignatureVerificationFailed(format!(
                "failed to create decoding key from JWK: {e}"
            ))
        })
    }

    /// Validates that the `sub` claim matches the expected client_id.
    fn validate_subject(
        claims: &VerifierAttestationClaims,
        expected_client_id: &str,
    ) -> Result<(), VerifierAttestationError> {
        if claims.sub != expected_client_id {
            return Err(VerifierAttestationError::SubjectMismatch {
                expected: expected_client_id.to_string(),
                actual: claims.sub.clone(),
            });
        }
        Ok(())
    }

    /// Validates temporal claims (exp, iat, nbf).
    fn validate_temporal(
        claims: &VerifierAttestationClaims,
    ) -> Result<(), VerifierAttestationError> {
        let now = jsonwebtoken::get_current_timestamp() as i64;

        // Check expiration
        if claims.exp < now {
            return Err(VerifierAttestationError::Expired);
        }

        // Check not-before if present
        if let Some(nbf) = claims.nbf
            && nbf > now
        {
            return Err(VerifierAttestationError::NotYetValid);
        }

        // Check issued-at if present (iat should not be in the future)
        if let Some(iat) = claims.iat
            && iat > now
        {
            return Err(VerifierAttestationError::IssuedInFuture);
        }

        Ok(())
    }

    /// Validate that the `cnf` claim contains a valid `jwk`.
    fn validate_cnf(claims: &VerifierAttestationClaims) -> Result<(), VerifierAttestationError> {
        // Check that the cnf claim exists (it's required by struct definition)
        // and that the JWK contains valid key material
        match &claims.cnf.jwk.key {
            cloud_wallet_crypto::jwk::Key::Ec(ec) => {
                // Validate that EC key has non-empty coordinates
                if ec.x.is_empty() || ec.y.is_empty() {
                    return Err(VerifierAttestationError::MissingCnfJwk);
                }
            }
            cloud_wallet_crypto::jwk::Key::Rsa(rsa) => {
                // Validate that RSA key has non-empty modulus and exponent
                if rsa.n.is_empty() || rsa.e.is_empty() {
                    return Err(VerifierAttestationError::MissingCnfJwk);
                }
            }
            cloud_wallet_crypto::jwk::Key::Oct(oct) => {
                // Validate that octet key has non-empty value
                if oct.k.is_empty() {
                    return Err(VerifierAttestationError::MissingCnfJwk);
                }
            }
            cloud_wallet_crypto::jwk::Key::Okp(okp) => {
                // Validate that OKP key has non-empty public key
                if okp.x.is_empty() {
                    return Err(VerifierAttestationError::MissingCnfJwk);
                }
            }
            // Handle non-exhaustive enum - any future key types are considered invalid
            _ => {
                return Err(VerifierAttestationError::MissingCnfJwk);
            }
        }
        Ok(())
    }

    /// Validates that a responseuri is in the allowed list.
    pub fn validate_response_uri(
        &self,
        response_uri: &str,
    ) -> Result<(), VerifierAttestationError> {
        if let Some(ref allowed_uris) = self.claims.response_uris {
            let allowed_set: HashSet<&str> = allowed_uris.iter().map(String::as_str).collect();
            if !allowed_set.contains(response_uri) {
                return Err(VerifierAttestationError::ResponseUriNotAllowed(
                    response_uri.to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Returns the decoded claims of the attestation JWT.
    pub fn claims(&self) -> &VerifierAttestationClaims {
        &self.claims
    }

    /// Returns the Verifier's public key from the `cnf.jwk` claim.
    pub fn verifier_public_key(&self) -> &Jwk {
        &self.claims.cnf.jwk
    }

    /// Returns the issuer of the attestation (the trusted attestation issuer).
    pub fn issuer(&self) -> &str {
        &self.claims.iss
    }

    /// Returns the subject of the attestation (the Verifier's identifier).
    pub fn subject(&self) -> &str {
        &self.claims.sub
    }

    /// Returns the raw JWT string.
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// Returns the list of allowed response URIs, if specified.
    pub fn allowed_response_uris(&self) -> Option<&[String]> {
        self.claims.response_uris.as_deref()
    }
}

/// Confirmation claim (`cnf`) containing the Verifier's public key.
///
/// The `cnf` claim is defined in [RFC 7800](https://datatracker.ietf.org/doc/html/rfc7800)
/// and is used to confirm the binding between the attestation and the key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CnfClaim {
    /// The JSON Web Key representing the Verifier's public key.
    pub jwk: Jwk,
}

/// Configuration for trusted attestation issuers.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TrustedAttestationIssuer {
    /// The issuer identifier (value of the `iss` claim).
    pub issuer_id: String,

    /// The JWKS or single JWK used to verify the attestation JWTs from this issuer.
    pub jwks: Vec<Jwk>,
}

#[cfg(test)]
mod tests {
    use cloud_wallet_crypto::jwk::Jwk;
    use jsonwebtoken::{Algorithm, EncodingKey};

    use super::*;

    const TEST_ISSUER: &str = "https://attestation.example.com";
    const TEST_CLIENT_ID: &str = "verifier_attestation:verifier123";

    /// Helper struct to manage test keys for creating and validating JWTs.
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
            Jwk::try_from(&self.verifier_key_pair).expect("failed to convert verifier key to JWK")
        }

        fn issuer_encoding_key(&self) -> EncodingKey {
            // Get the PKCS#8 DER encoded private key bytes from the key pair
            let secret = self.issuer_key_pair.to_pkcs8_der();
            EncodingKey::from_ec_der(secret)
        }
    }

    /// Creates a signed Verifier Attestation JWT with the given claims.
    fn create_test_jwt(keys: &TestKeys, claims: &VerifierAttestationClaims, typ: &str) -> String {
        let header = jsonwebtoken::Header {
            typ: Some(typ.to_string()),
            alg: Algorithm::ES256,
            kid: None,
            ..Default::default()
        };

        let encoding_key = keys.issuer_encoding_key();
        jsonwebtoken::encode(&header, claims, &encoding_key).expect("failed to encode JWT")
    }

    /// Creates a standard valid set of claims.
    fn valid_claims(keys: &TestKeys) -> VerifierAttestationClaims {
        let now = jsonwebtoken::get_current_timestamp() as i64;
        VerifierAttestationClaims {
            iss: TEST_ISSUER.to_string(),
            sub: TEST_CLIENT_ID.to_string(),
            aud: Some("https://wallet.example.com".to_string()),
            iat: Some(now),
            exp: now + 3600, // Valid for 1 hour
            nbf: None,
            jti: Some("test-jti".to_string()),
            cnf: CnfClaim {
                jwk: keys.verifier_jwk(),
            },
            response_uris: Some(vec![
                "https://verifier.example.com/cb1".to_string(),
                "https://verifier.example.com/cb2".to_string(),
            ]),
            nonce: Some("test-nonce".to_string()),
        }
    }

    fn trusted_issuer(keys: &TestKeys) -> TrustedAttestationIssuer {
        TrustedAttestationIssuer {
            issuer_id: TEST_ISSUER.to_string(),
            jwks: vec![keys.issuer_jwk()],
        }
    }

    #[test]
    fn test_decode_and_validate_success() {
        let keys = TestKeys::generate();
        let claims = valid_claims(&keys);
        let jwt = create_test_jwt(&keys, &claims, VerifierAttestationJwt::EXPECTED_TYP);
        let trusted_issuers = vec![trusted_issuer(&keys)];

        let result =
            VerifierAttestationJwt::decode_and_validate(&jwt, TEST_CLIENT_ID, &trusted_issuers);

        assert!(
            result.is_ok(),
            "expected success but got: {:?}",
            result.err()
        );
        let attestation = result.unwrap();
        assert_eq!(attestation.issuer(), TEST_ISSUER);
        assert_eq!(attestation.subject(), TEST_CLIENT_ID);
        assert!(attestation.allowed_response_uris().is_some());
    }

    #[test]
    fn test_valid_jwt_without_optional_claims() {
        let keys = TestKeys::generate();
        let now = jsonwebtoken::get_current_timestamp() as i64;
        let claims = VerifierAttestationClaims {
            iss: TEST_ISSUER.to_string(),
            sub: TEST_CLIENT_ID.to_string(),
            aud: None, // Optional
            iat: None, // Optional - iat is now optional per spec
            exp: now + 3600,
            nbf: None, // Optional
            jti: None, // Optional
            cnf: CnfClaim {
                jwk: keys.verifier_jwk(),
            },
            response_uris: None, // Optional - no restrictions
            nonce: None,         // Optional
        };
        let jwt = create_test_jwt(&keys, &claims, VerifierAttestationJwt::EXPECTED_TYP);
        let trusted_issuers = vec![trusted_issuer(&keys)];

        let result =
            VerifierAttestationJwt::decode_and_validate(&jwt, TEST_CLIENT_ID, &trusted_issuers);

        assert!(result.is_ok());
        let attestation = result.unwrap();
        assert!(attestation.allowed_response_uris().is_none());
    }

    #[test]
    fn test_wrong_typ_header_rejection() {
        let keys = TestKeys::generate();
        let claims = valid_claims(&keys);
        let jwt = create_test_jwt(&keys, &claims, "JWT"); // Wrong typ header
        let trusted_issuers = vec![trusted_issuer(&keys)];

        let result =
            VerifierAttestationJwt::decode_and_validate(&jwt, TEST_CLIENT_ID, &trusted_issuers);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            VerifierAttestationError::InvalidTyp { .. }
        ));
    }

    #[test]
    fn test_missing_typ_header_rejection() {
        let keys = TestKeys::generate();
        let claims = valid_claims(&keys);
        let jwt = create_test_jwt(&keys, &claims, ""); // Empty typ header
        let trusted_issuers = vec![trusted_issuer(&keys)];

        let result =
            VerifierAttestationJwt::decode_and_validate(&jwt, TEST_CLIENT_ID, &trusted_issuers);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            VerifierAttestationError::InvalidTyp { .. }
        ));
    }

    #[test]
    fn test_untrusted_issuer_rejection() {
        let keys = TestKeys::generate();
        let claims = valid_claims(&keys);
        let jwt = create_test_jwt(&keys, &claims, VerifierAttestationJwt::EXPECTED_TYP);

        // Use a different issuer (not matching the JWT's iss claim)
        let other_keys = TestKeys::generate();
        let wrong_issuer = TrustedAttestationIssuer {
            issuer_id: TEST_ISSUER.to_string(), // Same ID but different key
            jwks: vec![other_keys.issuer_jwk()],
        };

        let result =
            VerifierAttestationJwt::decode_and_validate(&jwt, TEST_CLIENT_ID, &[wrong_issuer]);

        assert!(result.is_err());
        // Signature verification will fail because the key doesn't match
        assert!(matches!(
            result.unwrap_err(),
            VerifierAttestationError::SignatureVerificationFailed(_)
        ));
    }

    #[test]
    fn test_unknown_issuer_rejection() {
        let keys = TestKeys::generate();
        let claims = valid_claims(&keys);
        let jwt = create_test_jwt(&keys, &claims, VerifierAttestationJwt::EXPECTED_TYP);

        // Empty trusted issuers list
        let result = VerifierAttestationJwt::decode_and_validate(&jwt, TEST_CLIENT_ID, &[]);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            VerifierAttestationError::UntrustedIssuer(iss) if iss == TEST_ISSUER
        ));
    }

    #[test]
    fn test_subject_client_id_mismatch_rejection() {
        let keys = TestKeys::generate();
        let claims = valid_claims(&keys);
        let jwt = create_test_jwt(&keys, &claims, VerifierAttestationJwt::EXPECTED_TYP);
        let trusted_issuers = vec![trusted_issuer(&keys)];

        let result = VerifierAttestationJwt::decode_and_validate(
            &jwt,
            "verifier_attestation:wrong-client", // Different client_id
            &trusted_issuers,
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            VerifierAttestationError::SubjectMismatch { .. }
        ));
    }

    #[test]
    fn test_expired_attestation_rejection() {
        let keys = TestKeys::generate();
        let now = jsonwebtoken::get_current_timestamp() as i64;
        let claims = VerifierAttestationClaims {
            iss: TEST_ISSUER.to_string(),
            sub: TEST_CLIENT_ID.to_string(),
            aud: None,
            iat: Some(now - 7200), // Issued 2 hours ago
            exp: now - 3600,       // Expired 1 hour ago
            nbf: None,
            jti: None,
            cnf: CnfClaim {
                jwk: keys.verifier_jwk(),
            },
            response_uris: None,
            nonce: None,
        };
        let jwt = create_test_jwt(&keys, &claims, VerifierAttestationJwt::EXPECTED_TYP);
        let trusted_issuers = vec![trusted_issuer(&keys)];

        let result =
            VerifierAttestationJwt::decode_and_validate(&jwt, TEST_CLIENT_ID, &trusted_issuers);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            VerifierAttestationError::Expired
        ));
    }

    #[test]
    fn test_not_yet_valid_rejection() {
        let keys = TestKeys::generate();
        let now = jsonwebtoken::get_current_timestamp() as i64;
        let claims = VerifierAttestationClaims {
            iss: TEST_ISSUER.to_string(),
            sub: TEST_CLIENT_ID.to_string(),
            aud: None,
            iat: Some(now),
            exp: now + 7200,
            nbf: Some(now + 3600), // Not valid for another hour
            jti: None,
            cnf: CnfClaim {
                jwk: keys.verifier_jwk(),
            },
            response_uris: None,
            nonce: None,
        };
        let jwt = create_test_jwt(&keys, &claims, VerifierAttestationJwt::EXPECTED_TYP);
        let trusted_issuers = vec![trusted_issuer(&keys)];

        let result =
            VerifierAttestationJwt::decode_and_validate(&jwt, TEST_CLIENT_ID, &trusted_issuers);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            VerifierAttestationError::NotYetValid
        ));
    }

    #[test]
    fn test_invalid_jwt_format_rejection() {
        let result =
            VerifierAttestationJwt::decode_and_validate("not.a.valid.jwt", TEST_CLIENT_ID, &[]);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            VerifierAttestationError::InvalidFormat(_)
        ));
    }

    #[test]
    fn test_verifier_attestation_jwt_accessors() {
        let keys = TestKeys::generate();
        let claims = valid_claims(&keys);
        let jwt = create_test_jwt(&keys, &claims, VerifierAttestationJwt::EXPECTED_TYP);
        let trusted_issuers = vec![trusted_issuer(&keys)];

        let attestation =
            VerifierAttestationJwt::decode_and_validate(&jwt, TEST_CLIENT_ID, &trusted_issuers)
                .expect("should succeed");

        assert_eq!(attestation.issuer(), TEST_ISSUER);
        assert_eq!(attestation.subject(), TEST_CLIENT_ID);
        assert_eq!(attestation.raw(), jwt);

        // Check that verifier_public_key returns the key from cnf.jwk
        let verifier_jwk = keys.verifier_jwk();
        assert_eq!(
            serde_json::to_string(attestation.verifier_public_key()).unwrap(),
            serde_json::to_string(&verifier_jwk).unwrap()
        );

        let allowed_uris = attestation.allowed_response_uris().unwrap();
        assert_eq!(allowed_uris.len(), 2);
        assert!(allowed_uris.contains(&"https://verifier.example.com/cb1".to_string()));
    }

    #[test]
    fn test_validate_response_uri_allowed() {
        let keys = TestKeys::generate();
        let claims = valid_claims(&keys);
        let jwt = create_test_jwt(&keys, &claims, VerifierAttestationJwt::EXPECTED_TYP);
        let trusted_issuers = vec![trusted_issuer(&keys)];

        let attestation =
            VerifierAttestationJwt::decode_and_validate(&jwt, TEST_CLIENT_ID, &trusted_issuers)
                .expect("should succeed");

        // Both URIs from the allowlist should be valid
        assert!(
            attestation
                .validate_response_uri("https://verifier.example.com/cb1")
                .is_ok()
        );
        assert!(
            attestation
                .validate_response_uri("https://verifier.example.com/cb2")
                .is_ok()
        );
    }

    #[test]
    fn test_validate_response_uri_not_allowed() {
        let keys = TestKeys::generate();
        let claims = valid_claims(&keys);
        let jwt = create_test_jwt(&keys, &claims, VerifierAttestationJwt::EXPECTED_TYP);
        let trusted_issuers = vec![trusted_issuer(&keys)];

        let attestation =
            VerifierAttestationJwt::decode_and_validate(&jwt, TEST_CLIENT_ID, &trusted_issuers)
                .expect("should succeed");

        let result = attestation.validate_response_uri("https://evil.com/cb");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            VerifierAttestationError::ResponseUriNotAllowed(uri) if uri == "https://evil.com/cb"
        ));
    }

    #[test]
    fn test_validate_response_uri_no_restrictions() {
        let keys = TestKeys::generate();
        let now = jsonwebtoken::get_current_timestamp() as i64;
        let claims = VerifierAttestationClaims {
            iss: TEST_ISSUER.to_string(),
            sub: TEST_CLIENT_ID.to_string(),
            aud: None,
            iat: Some(now),
            exp: now + 3600,
            nbf: None,
            jti: None,
            cnf: CnfClaim {
                jwk: keys.verifier_jwk(),
            },
            response_uris: None, // No restrictions
            nonce: None,
        };
        let jwt = create_test_jwt(&keys, &claims, VerifierAttestationJwt::EXPECTED_TYP);
        let trusted_issuers = vec![trusted_issuer(&keys)];

        let attestation =
            VerifierAttestationJwt::decode_and_validate(&jwt, TEST_CLIENT_ID, &trusted_issuers)
                .expect("should succeed");

        // Any URI should be allowed when response_uris is not set
        assert!(
            attestation
                .validate_response_uri("https://any.com/cb")
                .is_ok()
        );
        assert!(
            attestation
                .validate_response_uri("https://other.com/cb")
                .is_ok()
        );
    }

    #[test]
    fn test_verifier_attestation_error_display() {
        let err = VerifierAttestationError::InvalidFormat("test error".to_string());
        assert!(err.to_string().contains("invalid JWT format"));

        let err = VerifierAttestationError::InvalidTyp {
            expected: "verifier-attestation+jwt".to_string(),
            actual: "jwt".to_string(),
        };
        assert!(err.to_string().contains("invalid 'typ' header"));

        let err = VerifierAttestationError::UntrustedIssuer("bad-issuer".to_string());
        assert!(err.to_string().contains("untrusted issuer"));

        let err = VerifierAttestationError::SubjectMismatch {
            expected: "expected-sub".to_string(),
            actual: "actual-sub".to_string(),
        };
        assert!(err.to_string().contains("subject mismatch"));

        let err = VerifierAttestationError::Expired;
        assert!(err.to_string().contains("expired"));

        let err = VerifierAttestationError::NotYetValid;
        assert!(err.to_string().contains("not yet valid"));

        let err = VerifierAttestationError::MissingCnfJwk;
        assert!(err.to_string().contains("cnf.jwk"));

        let err = VerifierAttestationError::ResponseUriNotAllowed("https://evil.com".to_string());
        assert!(err.to_string().contains("response_uri not allowed"));

        let err = VerifierAttestationError::IssuedInFuture;
        assert!(err.to_string().contains("iat claim in the future"));
    }

    #[test]
    fn test_trusted_attestation_issuer_creation() {
        let issuer = TrustedAttestationIssuer {
            issuer_id: TEST_ISSUER.to_string(),
            jwks: vec![],
        };
        assert_eq!(issuer.issuer_id, TEST_ISSUER);
    }

    #[test]
    fn test_verifier_attestation_claims_serde() {
        let keys = TestKeys::generate();
        let now = jsonwebtoken::get_current_timestamp() as i64;
        let claims = VerifierAttestationClaims {
            iss: TEST_ISSUER.to_string(),
            sub: TEST_CLIENT_ID.to_string(),
            aud: Some("https://wallet.example.com".to_string()),
            iat: Some(now),
            exp: now + 3600,
            nbf: Some(now),
            jti: Some("test-jti".to_string()),
            cnf: CnfClaim {
                jwk: keys.verifier_jwk(),
            },
            response_uris: Some(vec!["https://verifier.example.com/cb".to_string()]),
            nonce: Some("test-nonce".to_string()),
        };

        let serialized = serde_json::to_string(&claims).expect("failed to serialize");
        let deserialized: VerifierAttestationClaims =
            serde_json::from_str(&serialized).expect("failed to deserialize");

        assert_eq!(deserialized.iss, claims.iss);
        assert_eq!(deserialized.sub, claims.sub);
        assert_eq!(deserialized.aud, claims.aud);
        assert_eq!(deserialized.iat, claims.iat);
        assert_eq!(deserialized.exp, claims.exp);
    }

    #[test]
    fn test_cnfg_claim_serde() {
        let keys = TestKeys::generate();
        let cnf = CnfClaim {
            jwk: keys.verifier_jwk(),
        };
        let serialized = serde_json::to_string(&cnf).expect("failed to serialize");
        assert!(serialized.contains("jwk"));

        let deserialized: CnfClaim =
            serde_json::from_str(&serialized).expect("failed to deserialize");
        assert!(matches!(
            deserialized.jwk.key,
            cloud_wallet_crypto::jwk::Key::Ec(_)
        ));
    }

    #[test]
    fn test_issued_in_future_rejection() {
        let keys = TestKeys::generate();
        let now = jsonwebtoken::get_current_timestamp() as i64;
        let claims = VerifierAttestationClaims {
            iss: TEST_ISSUER.to_string(),
            sub: TEST_CLIENT_ID.to_string(),
            aud: None,
            iat: Some(now + 3600), // Issued 1 hour in the future - invalid
            exp: now + 7200,
            nbf: None,
            jti: None,
            cnf: CnfClaim {
                jwk: keys.verifier_jwk(),
            },
            response_uris: None,
            nonce: None,
        };
        let jwt = create_test_jwt(&keys, &claims, VerifierAttestationJwt::EXPECTED_TYP);
        let trusted_issuers = vec![trusted_issuer(&keys)];

        let result =
            VerifierAttestationJwt::decode_and_validate(&jwt, TEST_CLIENT_ID, &trusted_issuers);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            VerifierAttestationError::IssuedInFuture
        ));
    }

    #[test]
    fn test_missing_cnf_claim_rejection() {
        use jsonwebtoken::Algorithm;

        let keys = TestKeys::generate();
        let now = jsonwebtoken::get_current_timestamp() as i64;

        // Create claims without cnf by manually constructing the JWT payload
        let claims_without_cnf = serde_json::json!({
            "iss": TEST_ISSUER,
            "sub": TEST_CLIENT_ID,
            "exp": now + 3600,
            "iat": now,
        });

        // Create a JWT without the cnf claim
        let header = jsonwebtoken::Header {
            typ: Some(VerifierAttestationJwt::EXPECTED_TYP.to_string()),
            alg: Algorithm::ES256,
            kid: None,
            ..Default::default()
        };

        let encoding_key = keys.issuer_encoding_key();
        let jwt = jsonwebtoken::encode(&header, &claims_without_cnf, &encoding_key)
            .expect("failed to encode JWT");

        let trusted_issuers = vec![trusted_issuer(&keys)];

        // Attempt to decode and validate - should fail due to missing cnf
        let result =
            VerifierAttestationJwt::decode_and_validate(&jwt, TEST_CLIENT_ID, &trusted_issuers);

        assert!(result.is_err());
        // The error should be a decoding/validation error due to missing cnf
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                VerifierAttestationError::DecodingFailed(_)
                    | VerifierAttestationError::MissingCnf(_)
                    | VerifierAttestationError::MissingCnfJwk
            ),
            "Expected error due to missing cnf, got: {:?}",
            err
        );
    }
}
