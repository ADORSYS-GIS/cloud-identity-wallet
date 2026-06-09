use std::collections::HashSet;

use cloud_wallet_crypto::jwk::{Jwk, Key, KeyUse, Operations};
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

    /// Authorized redirect URIs for this verifier.
    /// The Wallet must compare the Authorization Request `redirect_uri` or `response_uri`
    /// against this allowlist as defined in OpenID4VP Section 12.
    pub redirect_uris: Option<Vec<String>>,

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
    ///
    /// The `client_id` should be the unprefixed verifier identifier (without `verifier_attestation:`).
    /// The `sub` claim in the JWT must match this client_id exactly.
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

        // Validate that cnf.jwk is present and is a valid public key
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
        // If there's a kid in the header, find the matching key and use it
        if let Some(ref kid) = header.kid {
            let key = trusted_issuer
                .jwks
                .iter()
                .find(|k| k.prm.kid.as_deref() == Some(kid));
            match key {
                Some(key) => {
                    let decoding_key = Self::jwk_to_decoding_key(key)?;
                    return Self::decode_with_key(jwt, header, &decoding_key);
                }
                None => {
                    return Err(VerifierAttestationError::UnknownKeyId(kid.clone()));
                }
            }
        }

        // No kid in header - if exactly one key, use it
        if trusted_issuer.jwks.len() == 1 {
            let decoding_key = Self::jwk_to_decoding_key(&trusted_issuer.jwks[0])?;
            return Self::decode_with_key(jwt, header, &decoding_key);
        }

        // No kid and multiple keys - try all keys until one verifies
        for jwk in &trusted_issuer.jwks {
            let decoding_key = match Self::jwk_to_decoding_key(jwk) {
                Ok(key) => key,
                Err(_) => continue, // Skip keys that can't be converted
            };
            if let Ok(claims) = Self::decode_with_key(jwt, header, &decoding_key) {
                return Ok(claims);
            }
        }

        // None of the keys verified
        Err(VerifierAttestationError::SignatureVerificationFailed(
            "signature verification failed with all available keys".to_string(),
        ))
    }

    /// Decodes the JWT with a specific decoding key.
    fn decode_with_key(
        jwt: &str,
        header: &jsonwebtoken::Header,
        decoding_key: &DecodingKey,
    ) -> Result<VerifierAttestationClaims, VerifierAttestationError> {
        // Configure validation - we validate exp and iat here, others manually
        let mut validation = Validation::new(header.alg);
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.validate_aud = false; // Audience is optional per spec, validate manually if needed
        validation.required_spec_claims.clear();

        let token_data = decode::<VerifierAttestationClaims>(jwt, decoding_key, &validation)
            .map_err(|e| VerifierAttestationError::SignatureVerificationFailed(e.to_string()))?;

        Ok(token_data.claims)
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
    ///
    /// The JWK must be a public key suitable for verifying request object signatures.
    /// Symmetric keys (Oct) are rejected as they would represent a shared secret
    /// rather than a public verification key.
    fn validate_cnf(claims: &VerifierAttestationClaims) -> Result<(), VerifierAttestationError> {
        let jwk = &claims.cnf.jwk;

        // Reject symmetric keys - cnf.jwk must be a public key for signature verification
        if matches!(jwk.key, Key::Oct(_)) {
            return Err(VerifierAttestationError::InvalidKeyType(
                "symmetric keys (oct) are not allowed for cnf.jwk - must be a public key"
                    .to_string(),
            ));
        }

        // Check key usage metadata when present
        if let Some(key_use) = &jwk.prm.key_use
            && *key_use != KeyUse::Signing
        {
            return Err(VerifierAttestationError::InvalidKeyType(format!(
                "key 'use' must be 'sig' for signature verification, got '{:?}'",
                key_use
            )));
        }

        // Check key operations when present
        if let Some(ops) = &jwk.prm.ops {
            // For signature verification, the key should support 'verify' operation
            if !ops.contains(&Operations::Verify) {
                return Err(VerifierAttestationError::InvalidKeyType(
                    "key 'key_ops' must include 'verify' for signature verification".to_string(),
                ));
            }
        }

        // Validate key material based on key type
        match &jwk.key {
            Key::Ec(ec) => {
                // Validate that EC key has non-empty coordinates
                if ec.x.is_empty() || ec.y.is_empty() {
                    return Err(VerifierAttestationError::MissingCnfJwk);
                }
            }
            Key::Rsa(rsa) => {
                // Validate that RSA key has non-empty modulus and exponent
                if rsa.n.is_empty() || rsa.e.is_empty() {
                    return Err(VerifierAttestationError::MissingCnfJwk);
                }
            }
            Key::Okp(okp) => {
                // Validate that OKP key has non-empty public key
                if okp.x.is_empty() {
                    return Err(VerifierAttestationError::MissingCnfJwk);
                }
            }
            // Oct keys were already rejected above, this handles any future key types
            _ => {
                return Err(VerifierAttestationError::InvalidKeyType(
                    "unsupported key type for cnf.jwk".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Validates that a redirect_uri or response_uri is in the allowed list.
    ///
    /// Per OpenID4VP Section 13.3, the `response_uri` value follows the same
    /// permission rules as `redirect_uri`. The attestation JWT contains a
    /// `redirect_uris` allowlist that the request URI must match against.
    pub fn validate_redirect_uri(&self, uri: &str) -> Result<(), VerifierAttestationError> {
        if let Some(ref allowed_uris) = self.claims.redirect_uris {
            let allowed_set: HashSet<&str> = allowed_uris.iter().map(String::as_str).collect();
            if !allowed_set.contains(uri) {
                return Err(VerifierAttestationError::ResponseUriNotAllowed(
                    uri.to_string(),
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

    /// Returns the list of allowed redirect URIs, if specified.
    pub fn allowed_redirect_uris(&self) -> Option<&[String]> {
        self.claims.redirect_uris.as_deref()
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
    // The client_id WITHOUT the prefix - sub claim must match this exactly
    const TEST_VERIFIER_ID: &str = "verifier123";

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
            let mut jwk = Jwk::try_from(&self.verifier_key_pair)
                .expect("failed to convert verifier key to JWK");
            // Set appropriate key metadata for a signing key
            jwk.prm.key_use = Some(KeyUse::Signing);
            jwk.prm.ops = Some([Operations::Verify, Operations::Sign].into_iter().collect());
            jwk
        }

        fn issuer_encoding_key(&self) -> EncodingKey {
            // Get the PKCS#8 DER encoded private key bytes from the key pair
            let secret = self.issuer_key_pair.to_pkcs8_der();
            EncodingKey::from_ec_der(secret)
        }
    }

    /// Creates a signed Verifier Attestation JWT with the given claims.
    fn create_test_jwt(
        keys: &TestKeys,
        claims: &VerifierAttestationClaims,
        typ: &str,
        kid: Option<&str>,
    ) -> String {
        let header = jsonwebtoken::Header {
            typ: Some(typ.to_string()),
            alg: Algorithm::ES256,
            kid: kid.map(|s| s.to_string()),
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
            sub: TEST_VERIFIER_ID.to_string(), // sub is the unprefixed verifier ID
            aud: Some("https://wallet.example.com".to_string()),
            iat: Some(now),
            exp: now + 3600, // Valid for 1 hour
            nbf: None,
            jti: Some("test-jti".to_string()),
            cnf: CnfClaim {
                jwk: keys.verifier_jwk(),
            },
            redirect_uris: Some(vec![
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

    fn trusted_issuer_with_kid(keys: &TestKeys, kid: &str) -> TrustedAttestationIssuer {
        let mut jwk = keys.issuer_jwk();
        jwk.prm.kid = Some(kid.to_string());
        TrustedAttestationIssuer {
            issuer_id: TEST_ISSUER.to_string(),
            jwks: vec![jwk],
        }
    }

    /// 1. Valid attestation JWT decode and validation
    #[test]
    fn test_valid_attestation_decode_and_validation() {
        let keys = TestKeys::generate();
        let claims = valid_claims(&keys);
        let jwt = create_test_jwt(&keys, &claims, VerifierAttestationJwt::EXPECTED_TYP, None);
        let trusted_issuers = vec![trusted_issuer(&keys)];

        // Pass the unprefixed verifier ID
        let result =
            VerifierAttestationJwt::decode_and_validate(&jwt, TEST_VERIFIER_ID, &trusted_issuers);

        assert!(
            result.is_ok(),
            "Expected success but got: {:?}",
            result.err()
        );
        let attestation = result.unwrap();
        assert_eq!(attestation.issuer(), TEST_ISSUER);
        assert_eq!(attestation.subject(), TEST_VERIFIER_ID); // sub is the unprefixed ID
    }

    /// 2. Wrong `typ` header rejection
    #[test]
    fn test_wrong_typ_header_rejection() {
        let keys = TestKeys::generate();
        let claims = valid_claims(&keys);
        let jwt = create_test_jwt(&keys, &claims, "JWT", None); // Wrong typ header
        let trusted_issuers = vec![trusted_issuer(&keys)];

        let result =
            VerifierAttestationJwt::decode_and_validate(&jwt, TEST_VERIFIER_ID, &trusted_issuers);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            VerifierAttestationError::InvalidTyp { .. }
        ));
    }

    /// 3. Untrusted issuer rejection
    #[test]
    fn test_untrusted_issuer_rejection() {
        let keys = TestKeys::generate();
        let claims = valid_claims(&keys);
        let jwt = create_test_jwt(&keys, &claims, VerifierAttestationJwt::EXPECTED_TYP, None);

        // Unknown issuer - not in trusted list
        let result = VerifierAttestationJwt::decode_and_validate(&jwt, TEST_VERIFIER_ID, &[]);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            VerifierAttestationError::UntrustedIssuer(iss) if iss == TEST_ISSUER
        ));
    }

    /// 4. `sub` / `client_id` mismatch rejection
    #[test]
    fn test_sub_client_id_mismatch_rejection() {
        let keys = TestKeys::generate();
        let claims = valid_claims(&keys);
        let jwt = create_test_jwt(&keys, &claims, VerifierAttestationJwt::EXPECTED_TYP, None);
        let trusted_issuers = vec![trusted_issuer(&keys)];

        let result = VerifierAttestationJwt::decode_and_validate(
            &jwt,
            "wrong-verifier", // Different client_id
            &trusted_issuers,
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            VerifierAttestationError::SubjectMismatch { .. }
        ));
    }

    /// 5. Expired attestation rejection
    #[test]
    fn test_expired_attestation_rejection() {
        let keys = TestKeys::generate();
        let now = jsonwebtoken::get_current_timestamp() as i64;
        let claims = VerifierAttestationClaims {
            iss: TEST_ISSUER.to_string(),
            sub: TEST_VERIFIER_ID.to_string(),
            aud: None,
            iat: None,
            exp: now - 3600, // Expired 1 hour ago
            nbf: None,
            jti: None,
            cnf: CnfClaim {
                jwk: keys.verifier_jwk(),
            },
            redirect_uris: None,
            nonce: None,
        };
        let jwt = create_test_jwt(&keys, &claims, VerifierAttestationJwt::EXPECTED_TYP, None);
        let trusted_issuers = vec![trusted_issuer(&keys)];

        let result =
            VerifierAttestationJwt::decode_and_validate(&jwt, TEST_VERIFIER_ID, &trusted_issuers);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            VerifierAttestationError::Expired
        ));
    }

    /// 6. Missing `cnf.jwk` rejection
    #[test]
    fn test_missing_cnf_jwk_rejection() {
        use jsonwebtoken::Algorithm;

        let keys = TestKeys::generate();
        let now = jsonwebtoken::get_current_timestamp() as i64;

        // Create claims without cnf by manually constructing the JWT payload
        let claims_without_cnf = serde_json::json!({
            "iss": TEST_ISSUER,
            "sub": TEST_VERIFIER_ID,
            "exp": now + 3600,
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
            VerifierAttestationJwt::decode_and_validate(&jwt, TEST_VERIFIER_ID, &trusted_issuers);

        assert!(result.is_err());
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

    /// 7. `redirect_uris` allowlist enforcement
    #[test]
    fn test_redirect_uris_allowlist_enforcement() {
        let keys = TestKeys::generate();
        let claims = valid_claims(&keys);
        let jwt = create_test_jwt(&keys, &claims, VerifierAttestationJwt::EXPECTED_TYP, None);
        let trusted_issuers = vec![trusted_issuer(&keys)];

        let attestation =
            VerifierAttestationJwt::decode_and_validate(&jwt, TEST_VERIFIER_ID, &trusted_issuers)
                .expect("should succeed");

        // Allowed URI should succeed
        assert!(
            attestation
                .validate_redirect_uri("https://verifier.example.com/cb1")
                .is_ok()
        );

        // Not allowed URI should fail
        let result = attestation.validate_redirect_uri("https://evil.com/cb");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            VerifierAttestationError::ResponseUriNotAllowed(uri) if uri == "https://evil.com/cb"
        ));
    }

    /// 8. Unknown `kid` in header should fail (not fallback to other keys)
    #[test]
    fn test_unknown_kid_rejection() {
        let keys = TestKeys::generate();
        let claims = valid_claims(&keys);

        // Create issuer with a specific kid
        let trusted_issuers = vec![trusted_issuer_with_kid(&keys, "known-key-1")];

        // Create JWT with a different kid
        let jwt = create_test_jwt(
            &keys,
            &claims,
            VerifierAttestationJwt::EXPECTED_TYP,
            Some("unknown-key-id"),
        );

        let result =
            VerifierAttestationJwt::decode_and_validate(&jwt, TEST_VERIFIER_ID, &trusted_issuers);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            VerifierAttestationError::UnknownKeyId(kid) if kid == "unknown-key-id"
        ));
    }

    /// 9. Symmetric key (oct) in cnf.jwk should be rejected
    #[test]
    fn test_symmetric_key_rejection() {
        let keys = TestKeys::generate();
        let now = jsonwebtoken::get_current_timestamp() as i64;

        // Create a symmetric key (oct) for cnf.jwk
        let symmetric_jwk = Jwk {
            key: Key::Oct(cloud_wallet_crypto::jwk::Oct {
                k: cloud_wallet_crypto::secret::Secret::new(vec![1, 2, 3, 4, 5, 6, 7, 8]),
            }),
            prm: cloud_wallet_crypto::jwk::Parameters::default(),
        };

        let claims = VerifierAttestationClaims {
            iss: TEST_ISSUER.to_string(),
            sub: TEST_VERIFIER_ID.to_string(),
            aud: None,
            iat: None,
            exp: now + 3600,
            nbf: None,
            jti: None,
            cnf: CnfClaim { jwk: symmetric_jwk },
            redirect_uris: None,
            nonce: None,
        };

        let jwt = create_test_jwt(&keys, &claims, VerifierAttestationJwt::EXPECTED_TYP, None);
        let trusted_issuers = vec![trusted_issuer(&keys)];

        let result =
            VerifierAttestationJwt::decode_and_validate(&jwt, TEST_VERIFIER_ID, &trusted_issuers);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            VerifierAttestationError::InvalidKeyType(_)
        ));
    }

    /// 10. Key with wrong 'use' (encryption instead of signing) should be rejected
    #[test]
    fn test_key_wrong_use_rejection() {
        let keys = TestKeys::generate();
        let now = jsonwebtoken::get_current_timestamp() as i64;

        // Create a verifier key with wrong 'use' (enc instead of sig)
        let mut wrong_use_jwk = keys.verifier_jwk();
        wrong_use_jwk.prm.key_use = Some(KeyUse::Encryption); // Wrong use

        let claims = VerifierAttestationClaims {
            iss: TEST_ISSUER.to_string(),
            sub: TEST_VERIFIER_ID.to_string(),
            aud: None,
            iat: None,
            exp: now + 3600,
            nbf: None,
            jti: None,
            cnf: CnfClaim { jwk: wrong_use_jwk },
            redirect_uris: None,
            nonce: None,
        };

        let jwt = create_test_jwt(&keys, &claims, VerifierAttestationJwt::EXPECTED_TYP, None);
        let trusted_issuers = vec![trusted_issuer(&keys)];

        let result =
            VerifierAttestationJwt::decode_and_validate(&jwt, TEST_VERIFIER_ID, &trusted_issuers);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            VerifierAttestationError::InvalidKeyType(_)
        ));
    }

    /// 11. Key without 'verify' operation should be rejected
    #[test]
    fn test_key_missing_verify_operation_rejection() {
        let keys = TestKeys::generate();
        let now = jsonwebtoken::get_current_timestamp() as i64;

        // Create a verifier key with key_ops that doesn't include 'verify'
        let mut wrong_ops_jwk = keys.verifier_jwk();
        wrong_ops_jwk.prm.ops = Some([Operations::Sign].into_iter().collect()); // Missing 'verify'

        let claims = VerifierAttestationClaims {
            iss: TEST_ISSUER.to_string(),
            sub: TEST_VERIFIER_ID.to_string(),
            aud: None,
            iat: None,
            exp: now + 3600,
            nbf: None,
            jti: None,
            cnf: CnfClaim { jwk: wrong_ops_jwk },
            redirect_uris: None,
            nonce: None,
        };

        let jwt = create_test_jwt(&keys, &claims, VerifierAttestationJwt::EXPECTED_TYP, None);
        let trusted_issuers = vec![trusted_issuer(&keys)];

        let result =
            VerifierAttestationJwt::decode_and_validate(&jwt, TEST_VERIFIER_ID, &trusted_issuers);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            VerifierAttestationError::InvalidKeyType(_)
        ));
    }

    /// 12. Valid kid in header resolves to correct key
    #[test]
    fn test_valid_kid_resolves_correctly() {
        let keys = TestKeys::generate();
        let claims = valid_claims(&keys);

        // Create issuer with a specific kid
        let trusted_issuers = vec![trusted_issuer_with_kid(&keys, "issuer-key-1")];

        // Create JWT with matching kid
        let jwt = create_test_jwt(
            &keys,
            &claims,
            VerifierAttestationJwt::EXPECTED_TYP,
            Some("issuer-key-1"),
        );

        let result =
            VerifierAttestationJwt::decode_and_validate(&jwt, TEST_VERIFIER_ID, &trusted_issuers);

        assert!(
            result.is_ok(),
            "Expected success but got: {:?}",
            result.err()
        );
    }
}
