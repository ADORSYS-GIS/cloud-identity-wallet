//! JWT-Secured Authorization Request (JAR) parsing and validation.
//!
//! Implements parsing and validation of Request Objects per OpenID4VP Section 5.8
//! and RFC 9101. Verifiers send Authorization Requests as signed JWTs; the Wallet
//! verifies the signature and validates claims.

use super::authorization::AuthorizationRequest;
use super::client_id::ParsedClientId;
use crate::core::rfc7519::RFC7519Claims;
use crate::oid4vp::error::RequestObjectError;

use jsonwebtoken::{DecodingKey, Header, Validation, dangerous, decode, decode_header};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

const REQUEST_OBJECT_TYP: &str = "oauth-authz-req+jwt";
const SELF_ISSUED_AUDIENCE: &str = "https://self-issued.me/v2";

/// Discovery mode for audience validation.
///
/// Per OpenID4VP Section 5.8:
/// - In **static discovery mode**, the `aud` claim MUST be `https://self-issued.me/v2`
/// - In **dynamic discovery mode**, the `aud` claim MUST equal the Request Object `iss`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryMode {
    Static,
    Dynamic,
}

#[async_trait::async_trait]
pub trait VerifierKeyResolver: Send + Sync {
    async fn resolve_key(
        &self,
        client_id: &ParsedClientId,
        header: &Header,
    ) -> crate::errors::Result<DecodingKey>;
}

#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RequestObjectClaims {
    #[serde(flatten)]
    pub rfc7519: RFC7519Claims,

    #[serde(flatten)]
    pub params: AuthorizationRequest,
}

/// Minimal claims needed before signature verification to derive the audience
/// for dynamic discovery. This avoids deserializing the embedded
/// `AuthorizationRequest` on untrusted payload data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct MinimalRequestObjectClaims {
    iss: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RequestObject {
    pub header: Header,
    pub claims: RequestObjectClaims,
    pub client_id: ParsedClientId,
}

impl RequestObject {
    pub async fn decode_and_validate(
        jwt: &str,
        outer_client_id: &str,
        discovery_mode: DiscoveryMode,
        resolver: &dyn VerifierKeyResolver,
    ) -> std::result::Result<Self, RequestObjectError> {
        let header = decode_header(jwt).map_err(|e| {
            if e.to_string().contains("none") {
                RequestObjectError::Unsigned
            } else {
                RequestObjectError::InvalidFormat(format!("malformed JWT: {e}"))
            }
        })?;
        validate_header(&header)?;

        // Parse the outer client_id first and use it for key resolution.
        // Per the updated ticket, the outer Authorization Request client_id is the
        // trusted source for verifier identity; the Request Object client_id claim
        // is only checked for equality after decode.
        let outer_parsed_client_id = ParsedClientId::parse(outer_client_id)
            .map_err(|e| RequestObjectError::InvalidClientId(e.to_string()))?;

        let decoding_key = resolver
            .resolve_key(&outer_parsed_client_id, &header)
            .await
            .map_err(|e| RequestObjectError::KeyResolutionFailed(e.to_string()))?;

        // Decode only the minimal JWT claims needed to build the Validation rules
        // before signature verification. This avoids deserializing the full
        // AuthorizationRequest (which runs validation) on untrusted payload data.
        let minimal_claims: MinimalRequestObjectClaims =
            dangerous::insecure_decode::<MinimalRequestObjectClaims>(jwt)
                .map_err(|e| RequestObjectError::InvalidFormat(format!("malformed JWT: {e}")))?
                .claims;

        let algorithm = header.alg;
        let mut validation = Validation::new(algorithm);
        match discovery_mode {
            DiscoveryMode::Static => {
                validation.set_audience(&[SELF_ISSUED_AUDIENCE]);
            }
            DiscoveryMode::Dynamic => {
                let iss = minimal_claims.iss.as_deref().ok_or_else(|| {
                    RequestObjectError::InvalidClaims(
                        "missing required claim: iss (required for dynamic discovery)".to_string(),
                    )
                })?;
                validation.set_audience(&[iss]);
            }
        }
        validation.set_required_spec_claims(&["exp"]);

        let token_data =
            decode::<RequestObjectClaims>(jwt, &decoding_key, &validation).map_err(|e| match e
                .kind()
            {
                jsonwebtoken::errors::ErrorKind::InvalidSignature
                | jsonwebtoken::errors::ErrorKind::InvalidKeyFormat
                | jsonwebtoken::errors::ErrorKind::InvalidEcdsaKey
                | jsonwebtoken::errors::ErrorKind::InvalidEddsaKey
                | jsonwebtoken::errors::ErrorKind::InvalidRsaKey(_)
                | jsonwebtoken::errors::ErrorKind::RsaFailedSigning
                | jsonwebtoken::errors::ErrorKind::Signing(_)
                | jsonwebtoken::errors::ErrorKind::InvalidAlgorithm
                | jsonwebtoken::errors::ErrorKind::Provider(_) => {
                    RequestObjectError::SignatureVerificationFailed(e.to_string())
                }
                jsonwebtoken::errors::ErrorKind::ExpiredSignature
                | jsonwebtoken::errors::ErrorKind::InvalidIssuer
                | jsonwebtoken::errors::ErrorKind::InvalidAudience
                | jsonwebtoken::errors::ErrorKind::InvalidSubject
                | jsonwebtoken::errors::ErrorKind::ImmatureSignature
                | jsonwebtoken::errors::ErrorKind::MissingRequiredClaim(_)
                | jsonwebtoken::errors::ErrorKind::InvalidClaimFormat(_) => {
                    RequestObjectError::InvalidClaims(e.to_string())
                }
                _ => RequestObjectError::InvalidFormat(format!("malformed JWT: {e}")),
            })?;

        // Validate that the Request Object client_id matches the outer client_id
        let request_object_client_id_str = token_data.claims.params.client_id.as_str();
        if outer_client_id != request_object_client_id_str {
            return Err(RequestObjectError::InvalidClientId(format!(
                "Request Object client_id '{request_object_client_id_str}' does not match outer client_id '{outer_client_id}'"
            )));
        }

        validate_claims(&token_data.claims, discovery_mode)?;
        token_data
            .claims
            .params
            .validate()
            .map_err(|e| RequestObjectError::InvalidClaims(e.to_string()))?;

        Ok(Self {
            header,
            claims: token_data.claims,
            client_id: outer_parsed_client_id,
        })
    }
}

fn validate_header(header: &Header) -> std::result::Result<(), RequestObjectError> {
    let typ = header
        .typ
        .as_deref()
        .ok_or_else(|| RequestObjectError::InvalidHeader("missing typ".to_string()))?;
    // Per RFC 9101, `typ` MUST be "oauth-authz-req+jwt" (exact case-sensitive value). RFC 7515
    // Section 4.1.9 recommends case-sensitive matching for registered `typ` values.
    if typ != REQUEST_OBJECT_TYP {
        return Err(RequestObjectError::InvalidHeader(format!(
            "typ must be '{REQUEST_OBJECT_TYP}', got '{typ}'"
        )));
    }
    Ok(())
}

fn validate_claims(
    claims: &RequestObjectClaims,
    discovery_mode: DiscoveryMode,
) -> std::result::Result<(), RequestObjectError> {
    match discovery_mode {
        DiscoveryMode::Static => {
            let aud = claims.rfc7519.aud.as_deref().ok_or_else(|| {
                RequestObjectError::InvalidClaims("missing required claim: aud".to_string())
            })?;
            if aud != SELF_ISSUED_AUDIENCE {
                return Err(RequestObjectError::InvalidClaims(format!(
                    "invalid aud for static discovery: expected '{SELF_ISSUED_AUDIENCE}', got '{aud}'"
                )));
            }
        }
        DiscoveryMode::Dynamic => {
            let iss = claims.rfc7519.iss.as_deref().ok_or_else(|| {
                RequestObjectError::InvalidClaims(
                    "missing required claim: iss (required for dynamic discovery)".to_string(),
                )
            })?;
            let aud = claims.rfc7519.aud.as_deref().ok_or_else(|| {
                RequestObjectError::InvalidClaims("missing required claim: aud".to_string())
            })?;
            if aud != iss {
                return Err(RequestObjectError::InvalidClaims(format!(
                    "invalid aud for dynamic discovery: expected '{iss}' (must equal iss), got '{aud}'"
                )));
            }
        }
    }

    let now: i64 = jsonwebtoken::get_current_timestamp() as i64;

    match claims.rfc7519.exp {
        Some(exp) if exp <= now => {
            return Err(RequestObjectError::InvalidClaims(
                "expired Request Object".to_string(),
            ));
        }
        None => {
            return Err(RequestObjectError::InvalidClaims(
                "missing required claim: exp".to_string(),
            ));
        }
        _ => {}
    }

    if let Some(nbf) = claims.rfc7519.nbf {
        if nbf > now {
            return Err(RequestObjectError::InvalidClaims(
                "invalid nbf: token not yet active".to_string(),
            ));
        }
        if let Some(exp) = claims.rfc7519.exp
            && nbf > exp
        {
            return Err(RequestObjectError::InvalidClaims(
                "invalid nbf: not-before time is after expiration time".to_string(),
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64ct::{Base64UrlUnpadded, Encoding};
    use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, encode};

    const TEST_SECRET: &[u8] = b"test-secret";

    fn create_signed_jwt(client_id: &str, aud: &str) -> String {
        let now = jsonwebtoken::get_current_timestamp() as i64;
        let payload = serde_json::json!({
            "iss": client_id,
            "aud": aud,
            "exp": now + 300,
            "iat": now,
            "client_id": client_id,
            "response_type": "vp_token",
            "response_mode": "direct_post",
            "nonce": "test-nonce",
            "response_uri": "https://verifier.example.com/response",
            "scope": "openid",
        });
        let mut header = Header::new(Algorithm::HS256);
        header.typ = Some(REQUEST_OBJECT_TYP.to_string());
        encode(&header, &payload, &EncodingKey::from_secret(TEST_SECRET)).unwrap()
    }

    struct MockResolver {
        key: DecodingKey,
    }

    #[async_trait::async_trait]
    impl VerifierKeyResolver for MockResolver {
        async fn resolve_key(
            &self,
            _client_id: &ParsedClientId,
            _header: &Header,
        ) -> crate::errors::Result<DecodingKey> {
            Ok(self.key.clone())
        }
    }

    #[tokio::test]
    async fn valid_signed_request_object_dynamic() {
        let client_id = "redirect_uri:https://verifier.example.com";
        let jwt = create_signed_jwt(client_id, client_id);
        let resolver = MockResolver {
            key: DecodingKey::from_secret(TEST_SECRET),
        };
        let result =
            RequestObject::decode_and_validate(&jwt, client_id, DiscoveryMode::Dynamic, &resolver)
                .await;
        assert!(result.is_ok(), "should succeed: {:?}", result.err());
    }

    #[tokio::test]
    async fn valid_signed_request_object_static() {
        let client_id = "redirect_uri:https://verifier.example.com";
        let jwt = create_signed_jwt(client_id, SELF_ISSUED_AUDIENCE);
        let resolver = MockResolver {
            key: DecodingKey::from_secret(TEST_SECRET),
        };
        let result =
            RequestObject::decode_and_validate(&jwt, client_id, DiscoveryMode::Static, &resolver)
                .await;
        assert!(result.is_ok(), "should succeed: {:?}", result.err());
    }

    #[tokio::test]
    async fn invalid_signature() {
        let client_id = "redirect_uri:https://verifier.example.com";
        let jwt = create_signed_jwt(client_id, client_id);
        let resolver = MockResolver {
            key: DecodingKey::from_secret(b"wrong-secret"),
        };
        let result =
            RequestObject::decode_and_validate(&jwt, client_id, DiscoveryMode::Dynamic, &resolver)
                .await;
        assert!(result.is_err(), "should fail with invalid signature");
    }

    #[tokio::test]
    async fn expired_request_object() {
        let now = jsonwebtoken::get_current_timestamp() as i64;
        let client_id = "redirect_uri:https://verifier.example.com";
        let payload = serde_json::json!({
            "iss": client_id,
            "aud": client_id,
            "exp": now - 1,
            "iat": now - 100,
            "client_id": client_id,
            "response_type": "vp_token",
            "response_mode": "direct_post",
            "nonce": "test-nonce",
            "scope": "openid",
        });
        let mut header = Header::new(Algorithm::HS256);
        header.typ = Some(REQUEST_OBJECT_TYP.to_string());
        let jwt = encode(&header, &payload, &EncodingKey::from_secret(TEST_SECRET)).unwrap();
        let resolver = MockResolver {
            key: DecodingKey::from_secret(TEST_SECRET),
        };
        let result =
            RequestObject::decode_and_validate(&jwt, client_id, DiscoveryMode::Dynamic, &resolver)
                .await;
        assert!(result.is_err(), "should fail for expired");
    }

    #[tokio::test]
    async fn invalid_nbf() {
        let now = jsonwebtoken::get_current_timestamp() as i64;
        let client_id = "redirect_uri:https://verifier.example.com";
        let payload = serde_json::json!({
            "iss": client_id,
            "aud": client_id,
            "exp": now + 3600,
            "nbf": now + 300,
            "iat": now,
            "client_id": client_id,
            "response_type": "vp_token",
            "response_mode": "direct_post",
            "nonce": "test-nonce",
            "scope": "openid",
        });
        let mut header = Header::new(Algorithm::HS256);
        header.typ = Some(REQUEST_OBJECT_TYP.to_string());
        let jwt = encode(&header, &payload, &EncodingKey::from_secret(TEST_SECRET)).unwrap();
        let resolver = MockResolver {
            key: DecodingKey::from_secret(TEST_SECRET),
        };
        let result =
            RequestObject::decode_and_validate(&jwt, client_id, DiscoveryMode::Dynamic, &resolver)
                .await;
        assert!(result.is_err(), "should fail for invalid nbf");
    }

    #[tokio::test]
    async fn invalid_aud_static() {
        let client_id = "redirect_uri:https://verifier.example.com";
        let jwt = create_signed_jwt(client_id, "https://wrong-wallet.example.com");
        let resolver = MockResolver {
            key: DecodingKey::from_secret(TEST_SECRET),
        };
        let result =
            RequestObject::decode_and_validate(&jwt, client_id, DiscoveryMode::Static, &resolver)
                .await;
        assert!(
            result.is_err(),
            "should fail for invalid aud in static mode"
        );
    }

    #[tokio::test]
    async fn invalid_aud_dynamic() {
        let client_id = "redirect_uri:https://verifier.example.com";
        let jwt = create_signed_jwt(client_id, "https://wrong-aud.example.com");
        let resolver = MockResolver {
            key: DecodingKey::from_secret(TEST_SECRET),
        };
        let result =
            RequestObject::decode_and_validate(&jwt, client_id, DiscoveryMode::Dynamic, &resolver)
                .await;
        assert!(
            result.is_err(),
            "should fail for invalid aud in dynamic mode"
        );
    }

    #[tokio::test]
    async fn missing_iss_dynamic() {
        let now = jsonwebtoken::get_current_timestamp() as i64;
        let client_id = "redirect_uri:https://verifier.example.com";
        let payload = serde_json::json!({
            "aud": client_id,
            "exp": now + 300,
            "iat": now,
            "client_id": client_id,
            "response_type": "vp_token",
            "response_mode": "direct_post",
            "nonce": "test-nonce",
            "scope": "openid",
        });
        let mut header = Header::new(Algorithm::HS256);
        header.typ = Some(REQUEST_OBJECT_TYP.to_string());
        let jwt = encode(&header, &payload, &EncodingKey::from_secret(TEST_SECRET)).unwrap();
        let resolver = MockResolver {
            key: DecodingKey::from_secret(TEST_SECRET),
        };
        let result =
            RequestObject::decode_and_validate(&jwt, client_id, DiscoveryMode::Dynamic, &resolver)
                .await;
        assert!(
            result.is_err(),
            "should fail for missing iss in dynamic mode"
        );
    }

    #[tokio::test]
    async fn malformed_jwt() {
        let resolver = MockResolver {
            key: DecodingKey::from_secret(TEST_SECRET),
        };
        let result = RequestObject::decode_and_validate(
            "not-a-jwt",
            "redirect_uri:https://verifier.example.com",
            DiscoveryMode::Dynamic,
            &resolver,
        )
        .await;
        assert!(result.is_err(), "should fail for malformed JWT");
    }

    #[tokio::test]
    async fn unsupported_jose_header() {
        let now = jsonwebtoken::get_current_timestamp() as i64;
        let client_id = "redirect_uri:https://verifier.example.com";
        let payload = serde_json::json!({
            "iss": client_id,
            "aud": client_id,
            "exp": now + 300,
            "iat": now,
            "client_id": client_id,
            "response_type": "vp_token",
            "response_mode": "direct_post",
            "nonce": "test-nonce",
            "scope": "openid",
        });
        let mut header = Header::new(Algorithm::HS256);
        header.typ = Some("wrong-type".to_string());
        let jwt = encode(&header, &payload, &EncodingKey::from_secret(TEST_SECRET)).unwrap();
        let resolver = MockResolver {
            key: DecodingKey::from_secret(TEST_SECRET),
        };
        let result =
            RequestObject::decode_and_validate(&jwt, client_id, DiscoveryMode::Dynamic, &resolver)
                .await;
        assert!(result.is_err(), "should fail for unsupported typ");
        assert!(matches!(
            result.unwrap_err(),
            RequestObjectError::InvalidHeader(_)
        ));
    }

    #[tokio::test]
    async fn unsigned_request_object_rejected() {
        let client_id = "redirect_uri:https://verifier.example.com";
        let header = serde_json::json!({
            "alg": "none",
            "typ": REQUEST_OBJECT_TYP,
        });
        let payload = serde_json::json!({
            "iss": client_id,
            "aud": client_id,
            "exp": jsonwebtoken::get_current_timestamp() as i64 + 300,
            "iat": jsonwebtoken::get_current_timestamp() as i64,
            "client_id": client_id,
            "response_type": "vp_token",
            "response_mode": "direct_post",
            "nonce": "test-nonce",
            "response_uri": "https://verifier.example.com/response",
            "scope": "openid",
        });
        let header_b64 = Base64UrlUnpadded::encode_string(header.to_string().as_bytes());
        let payload_b64 = Base64UrlUnpadded::encode_string(payload.to_string().as_bytes());
        let jwt = format!("{header_b64}.{payload_b64}.");

        let resolver = MockResolver {
            key: DecodingKey::from_secret(TEST_SECRET),
        };
        let result =
            RequestObject::decode_and_validate(&jwt, client_id, DiscoveryMode::Dynamic, &resolver)
                .await;
        assert!(result.is_err(), "should fail for unsigned request object");
        assert!(matches!(result.unwrap_err(), RequestObjectError::Unsigned));
    }

    #[tokio::test]
    async fn mismatched_client_id() {
        let now = jsonwebtoken::get_current_timestamp() as i64;
        let outer_client_id = "redirect_uri:https://verifier.example.com";
        let wrong_iss = "redirect_uri:https://other-verifier.example.com";
        let payload = serde_json::json!({
            "iss": wrong_iss,
            "aud": wrong_iss,
            "exp": now + 300,
            "iat": now,
            "client_id": wrong_iss,
            "response_type": "vp_token",
            "response_mode": "direct_post",
            "nonce": "test-nonce",
            "response_uri": "https://verifier.example.com/response",
            "scope": "openid",
        });
        let mut header = Header::new(Algorithm::HS256);
        header.typ = Some(REQUEST_OBJECT_TYP.to_string());
        let jwt = encode(&header, &payload, &EncodingKey::from_secret(TEST_SECRET)).unwrap();
        let resolver = MockResolver {
            key: DecodingKey::from_secret(TEST_SECRET),
        };
        let result = RequestObject::decode_and_validate(
            &jwt,
            outer_client_id,
            DiscoveryMode::Dynamic,
            &resolver,
        )
        .await;
        assert!(
            result.is_err(),
            "should fail when Request Object client_id does not match outer client_id"
        );
        assert!(matches!(
            result.unwrap_err(),
            RequestObjectError::InvalidClientId(_)
        ));
    }

    #[tokio::test]
    async fn valid_without_iat() {
        let now = jsonwebtoken::get_current_timestamp() as i64;
        let client_id = "redirect_uri:https://verifier.example.com";
        let payload = serde_json::json!({
            "iss": client_id,
            "aud": client_id,
            "exp": now + 300,
            "client_id": client_id,
            "response_type": "vp_token",
            "response_mode": "direct_post",
            "nonce": "test-nonce",
            "response_uri": "https://verifier.example.com/response",
            "scope": "openid",
        });
        let mut header = Header::new(Algorithm::HS256);
        header.typ = Some(REQUEST_OBJECT_TYP.to_string());
        let jwt = encode(&header, &payload, &EncodingKey::from_secret(TEST_SECRET)).unwrap();
        let resolver = MockResolver {
            key: DecodingKey::from_secret(TEST_SECRET),
        };
        let result =
            RequestObject::decode_and_validate(&jwt, client_id, DiscoveryMode::Dynamic, &resolver)
                .await;
        assert!(
            result.is_ok(),
            "should succeed without iat: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn expired_request_object_maps_to_invalid_claims() {
        let now = jsonwebtoken::get_current_timestamp() as i64;
        let client_id = "redirect_uri:https://verifier.example.com";
        let payload = serde_json::json!({
            "iss": client_id,
            "aud": client_id,
            "exp": now - 1,
            "iat": now - 100,
            "client_id": client_id,
            "response_type": "vp_token",
            "response_mode": "direct_post",
            "nonce": "test-nonce",
            "response_uri": "https://verifier.example.com/response",
            "scope": "openid",
        });
        let mut header = Header::new(Algorithm::HS256);
        header.typ = Some(REQUEST_OBJECT_TYP.to_string());
        let jwt = encode(&header, &payload, &EncodingKey::from_secret(TEST_SECRET)).unwrap();
        let resolver = MockResolver {
            key: DecodingKey::from_secret(TEST_SECRET),
        };
        let result =
            RequestObject::decode_and_validate(&jwt, client_id, DiscoveryMode::Dynamic, &resolver)
                .await;
        assert!(
            matches!(result.unwrap_err(), RequestObjectError::InvalidClaims(_)),
            "expected InvalidClaims for expired token"
        );
    }

    #[tokio::test]
    async fn invalid_signature_maps_to_signature_verification_failed() {
        let client_id = "redirect_uri:https://verifier.example.com";
        let jwt = create_signed_jwt(client_id, client_id);
        let resolver = MockResolver {
            key: DecodingKey::from_secret(b"wrong-secret"),
        };
        let result =
            RequestObject::decode_and_validate(&jwt, client_id, DiscoveryMode::Dynamic, &resolver)
                .await;
        assert!(
            matches!(
                result.unwrap_err(),
                RequestObjectError::SignatureVerificationFailed(_)
            ),
            "expected SignatureVerificationFailed for invalid signature"
        );
    }

    #[tokio::test]
    async fn invalid_nbf_maps_to_invalid_claims() {
        let now = jsonwebtoken::get_current_timestamp() as i64;
        let client_id = "redirect_uri:https://verifier.example.com";
        let payload = serde_json::json!({
            "iss": client_id,
            "aud": client_id,
            "exp": now + 3600,
            "nbf": now + 300,
            "iat": now,
            "client_id": client_id,
            "response_type": "vp_token",
            "response_mode": "direct_post",
            "nonce": "test-nonce",
            "response_uri": "https://verifier.example.com/response",
            "scope": "openid",
        });
        let mut header = Header::new(Algorithm::HS256);
        header.typ = Some(REQUEST_OBJECT_TYP.to_string());
        let jwt = encode(&header, &payload, &EncodingKey::from_secret(TEST_SECRET)).unwrap();
        let resolver = MockResolver {
            key: DecodingKey::from_secret(TEST_SECRET),
        };
        let result =
            RequestObject::decode_and_validate(&jwt, client_id, DiscoveryMode::Dynamic, &resolver)
                .await;
        assert!(
            matches!(result.unwrap_err(), RequestObjectError::InvalidClaims(_)),
            "expected InvalidClaims for invalid nbf"
        );
    }

    #[tokio::test]
    async fn malformed_authorization_request_after_valid_signature_maps_to_invalid_format() {
        let now = jsonwebtoken::get_current_timestamp() as i64;
        let client_id = "redirect_uri:https://verifier.example.com";
        // Both scope and dcql_query are present, which violates the XOR rule in
        // AuthorizationRequest::validate(). Because that validation is invoked
        // inside Deserialize, decode::<RequestObjectClaims> will fail with a Json
        // error which we map to InvalidFormat.
        let payload = serde_json::json!({
            "iss": client_id,
            "aud": client_id,
            "exp": now + 300,
            "client_id": client_id,
            "response_type": "vp_token",
            "response_mode": "direct_post",
            "nonce": "test-nonce",
            "response_uri": "https://verifier.example.com/response",
            "scope": "openid",
            "dcql_query": {
                "credentials": [{
                    "id": "test-cred",
                    "format": "ldp_vc"
                }]
            },
        });
        let mut header = Header::new(Algorithm::HS256);
        header.typ = Some(REQUEST_OBJECT_TYP.to_string());
        let jwt = encode(&header, &payload, &EncodingKey::from_secret(TEST_SECRET)).unwrap();
        let resolver = MockResolver {
            key: DecodingKey::from_secret(TEST_SECRET),
        };
        let result =
            RequestObject::decode_and_validate(&jwt, client_id, DiscoveryMode::Dynamic, &resolver)
                .await;
        assert!(
            matches!(result.unwrap_err(), RequestObjectError::InvalidFormat(_)),
            "expected InvalidFormat for malformed AuthorizationRequest payload"
        );
    }
}
