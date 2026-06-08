//! JWT-Secured Authorization Request (JAR) parsing and validation.
//!
//! Implements parsing and validation of Request Objects per OpenID4VP Section 5.8
//! and RFC 9101. Verifiers send Authorization Requests as signed JWTs; the Wallet
//! verifies the signature and validates claims.

use super::authorization::AuthorizationRequest;
use super::client_id::ParsedClientId;
use crate::core::rfc7519::RFC7519Claims;
use crate::errors::{Error, ErrorKind, Result};
use jsonwebtoken::{DecodingKey, Header, Validation, dangerous, decode, decode_header};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

/// Async trait for resolving verifier public keys for signature verification.
#[async_trait::async_trait]
pub trait VerifierKeyResolver: Send + Sync {
    /// Resolves the decoding key for signature verification.
    async fn resolve_key(&self, client_id: &ParsedClientId, header: &Header)
    -> Result<DecodingKey>;
}

const REQUEST_OBJECT_TYP: &str = "oauth-authz-req+jwt";
const SELF_ISSUED_AUDIENCE: &str = "https://self-issued.me/v2";

/// Returns `true` if the client_id scheme requires a signed Request Object.
///
/// Per OpenID4VP Section 5.6, only `redirect_uri` scheme permits unsigned requests.
pub fn client_id_requires_signature(client_id: &ParsedClientId) -> bool {
    !client_id.is_redirect_uri()
}

/// Validates the JWT header for a Request Object per RFC 9101.
fn validate_header(header: &Header) -> Result<()> {
    let typ = header.typ.as_deref().ok_or_else(|| {
        Error::message(
            ErrorKind::InvalidPresentationRequest,
            "Request Object typ claim is missing",
        )
    })?;
    if typ.to_lowercase() != REQUEST_OBJECT_TYP.to_lowercase() {
        return Err(Error::message(
            ErrorKind::InvalidPresentationRequest,
            format!("Request Object typ must be '{REQUEST_OBJECT_TYP}', got '{typ}'"),
        ));
    }

    Ok(())
}

/// Claims in a Request Object JWT (OpenID4VP Section 5.8 / RFC 9101).
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RequestObjectClaims {
    /// Standard JWT registered claims.
    #[serde(flatten)]
    pub rfc7519: RFC7519Claims,

    #[serde(flatten)]
    pub params: AuthorizationRequest,
}

/// A decoded and validated Request Object JWT.
#[derive(Debug, Clone)]
pub struct RequestObject {
    pub header: Header,
    pub claims: RequestObjectClaims,
    pub client_id: ParsedClientId,
}

impl RequestObject {
    /// Decodes and validates a signed Request Object JWT.
    pub async fn decode_and_validate(
        jwt: &str,
        wallet_id: &str,
        resolver: &dyn VerifierKeyResolver,
    ) -> Result<Self> {
        let header = decode_header(jwt).map_err(|e| {
            Error::message(
                ErrorKind::InvalidPresentationRequest,
                format!("failed to decode JWT header: {e}"),
            )
        })?;
        validate_header(&header)?;

        let claims: RequestObjectClaims = dangerous::insecure_decode::<RequestObjectClaims>(jwt)
            .map_err(|e| {
                Error::message(
                    ErrorKind::InvalidPresentationRequest,
                    format!("failed to decode JWT payload: {e}"),
                )
            })?
            .claims;
        let client_id_str = claims.params.client_id.as_str();
        let parsed_client_id = ParsedClientId::parse(client_id_str)
            .map_err(|e| Error::message(ErrorKind::InvalidPresentationRequest, e.to_string()))?;

        let decoding_key = resolver.resolve_key(&parsed_client_id, &header).await?;

        let algorithm = header.alg;
        let mut validation = Validation::new(algorithm);
        validation.set_audience(&[wallet_id, SELF_ISSUED_AUDIENCE]);
        validation.set_required_spec_claims(&["exp", "iat"]);

        let _token_data = decode::<serde_json::Value>(jwt, &decoding_key, &validation)
            .map_err(|e| Error::message(ErrorKind::InvalidPresentationRequest, e.to_string()))?;

        validate_claims(&claims, wallet_id)?;

        Ok(Self {
            header,
            claims,
            client_id: parsed_client_id,
        })
    }

    /// Decodes a Request Object without verifying the signature.
    ///
    /// Used for `redirect_uri` client_id schemes where unsigned requests are permitted.
    pub async fn decode_unsigned(jwt: &str, wallet_id: &str) -> Result<Self> {
        let header = decode_header(jwt).map_err(|e| {
            Error::message(
                ErrorKind::InvalidPresentationRequest,
                format!("failed to decode JWT header: {e}"),
            )
        })?;
        validate_header(&header)?;

        let claims: RequestObjectClaims = dangerous::insecure_decode::<RequestObjectClaims>(jwt)
            .map_err(|e| {
                Error::message(
                    ErrorKind::InvalidPresentationRequest,
                    format!("failed to decode JWT payload: {e}"),
                )
            })?
            .claims;
        let client_id_str = claims.params.client_id.as_str();
        let parsed_client_id = ParsedClientId::parse(client_id_str)
            .map_err(|e| Error::message(ErrorKind::InvalidPresentationRequest, e.to_string()))?;

        if client_id_requires_signature(&parsed_client_id) {
            return Err(Error::message(
                ErrorKind::InvalidPresentationRequest,
                format!(
                    "client_id scheme '{}' requires a signed Request Object but decode_unsigned was called",
                    client_id_str
                ),
            ));
        }

        validate_claims(&claims, wallet_id)?;

        Ok(Self {
            header,
            claims,
            client_id: parsed_client_id,
        })
    }
}

fn validate_claims(claims: &RequestObjectClaims, wallet_id: &str) -> Result<()> {
    let aud_valid = match &claims.rfc7519.aud {
        Some(aud) => aud == wallet_id || aud == SELF_ISSUED_AUDIENCE,
        None => false,
    };
    if !aud_valid {
        let aud_msg = claims.rfc7519.aud.as_deref().unwrap_or("missing");
        return Err(Error::message(
            ErrorKind::InvalidPresentationRequest,
            format!(
                "Request Object aud claim must be '{wallet_id}' or '{SELF_ISSUED_AUDIENCE}', got '{aud_msg}'"
            ),
        ));
    }

    if let Some(exp) = claims.rfc7519.exp {
        let now: i64 = jsonwebtoken::get_current_timestamp() as i64;
        if exp <= now {
            return Err(Error::message(
                ErrorKind::InvalidPresentationRequest,
                "Request Object is expired",
            ));
        }
    } else {
        return Err(Error::message(
            ErrorKind::InvalidPresentationRequest,
            "Request Object must contain 'exp' claim",
        ));
    }

    if let Some(iat) = claims.rfc7519.iat {
        let now: i64 = jsonwebtoken::get_current_timestamp() as i64;
        const MAX_AGE_SECONDS: i64 = 60 * 60;
        if iat < now.saturating_sub(MAX_AGE_SECONDS) {
            return Err(Error::message(
                ErrorKind::InvalidPresentationRequest,
                "Request Object 'iat' claim is too old (more than 1 hour)",
            ));
        }
        if iat > now {
            return Err(Error::message(
                ErrorKind::InvalidPresentationRequest,
                "Request Object 'iat' claim is in the future",
            ));
        }
    } else {
        return Err(Error::message(
            ErrorKind::InvalidPresentationRequest,
            "Request Object must contain 'iat' claim",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::{Algorithm, EncodingKey, encode};
    use url::Url;

    use super::super::authorization::{AuthorizationRequest, ResponseMode, ResponseType};
    use super::super::client_id::{ClientIdPrefix, ParsedClientId};
    use super::*;

    const TEST_SECRET: &[u8] = b"test-secret-for-testing-only";

    fn make_test_auth_request() -> AuthorizationRequest {
        AuthorizationRequest {
            response_type: ResponseType::VpToken,
            client_id: "https://verifier.example.com".to_string(),
            redirect_uri: None,
            scope: None,
            state: None,
            nonce: "test-nonce".to_string(),
            response_mode: ResponseMode::DirectPost,
            response_uri: Some(Url::parse("https://verifier.example.com/response").unwrap()),
            request_uri: None,
            request_uri_method: None,
            dcql_query: None,
            client_metadata: None,
            client_metadata_uri: None,
            request: None,
            transaction_data: None,
            verifier_info: None,
            expected_origins: None,
        }
    }

    #[test]
    fn parse_client_id_x509_san_dns() {
        let parsed = ParsedClientId::parse("x509_san_dns:verifier.example.com").unwrap();
        assert_eq!(parsed.prefix(), Some(ClientIdPrefix::X509SanDns));
        assert!(client_id_requires_signature(&parsed));
    }

    #[test]
    fn parse_client_id_x509_hash() {
        // Valid base64url-unpadded encoding of 32 bytes (SHA-256 hash)
        let parsed =
            ParsedClientId::parse("x509_hash:Uvo3HtuIxuhC92rShpgqcT3YXwrqRxWEviRiA0OZszk").unwrap();
        assert_eq!(parsed.prefix(), Some(ClientIdPrefix::X509Hash));
        assert!(client_id_requires_signature(&parsed));
    }

    #[test]
    fn parse_client_id_did() {
        let parsed =
            ParsedClientId::parse("decentralized_identifier:did:jwk:eyBrZXkiIDogInZhbHVlIiB9")
                .unwrap();
        assert_eq!(
            parsed.prefix(),
            Some(ClientIdPrefix::DecentralizedIdentifier)
        );
        assert!(client_id_requires_signature(&parsed));
    }

    #[test]
    fn parse_client_id_verifier_attestation() {
        let parsed = ParsedClientId::parse(
            "verifier_attestation:eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
        )
        .unwrap();
        assert_eq!(parsed.prefix(), Some(ClientIdPrefix::VerifierAttestation));
        assert!(client_id_requires_signature(&parsed));
    }

    #[test]
    fn parse_client_id_redirect_uri() {
        let parsed =
            ParsedClientId::parse("redirect_uri:https://verifier.example.com/callback").unwrap();
        assert_eq!(parsed.prefix(), Some(ClientIdPrefix::RedirectUri));
        assert!(!client_id_requires_signature(&parsed));
    }

    #[test]
    fn parse_client_id_empty() {
        let result = ParsedClientId::parse("");
        // Empty string is treated as pre-registered client with empty value
        assert!(result.is_ok());
    }

    #[test]
    fn parse_client_id_invalid() {
        let result = ParsedClientId::parse("not-a-valid-client-id");
        // Unknown prefix is treated as pre-registered client
        assert!(result.is_ok());
    }

    #[test]
    fn validate_header_typ() {
        let mut header = Header::new(jsonwebtoken::Algorithm::ES256);
        header.typ = Some("oauth-authz-req+jwt".to_string());
        assert!(validate_header(&header).is_ok());

        let mut header_invalid_typ = Header::new(jsonwebtoken::Algorithm::ES256);
        header_invalid_typ.typ = Some("invalid".to_string());
        assert!(validate_header(&header_invalid_typ).is_err());
    }

    #[test]
    fn validate_claims_aud_mismatch() {
        let claims = RequestObjectClaims {
            rfc7519: RFC7519Claims {
                iss: Some("https://verifier.example.com".to_string()),
                sub: None,
                aud: Some("https://wrong-wallet.example.com".to_string()),
                exp: Some((jsonwebtoken::get_current_timestamp() as i64) + 300),
                nbf: None,
                iat: Some(jsonwebtoken::get_current_timestamp() as i64),
                jti: None,
            },
            params: make_test_auth_request(),
        };

        let result = validate_claims(&claims, "https://wallet.example.com");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("aud claim"));
    }

    #[test]
    fn validate_claims_aud_self_issued() {
        let claims = RequestObjectClaims {
            rfc7519: RFC7519Claims {
                iss: Some("https://verifier.example.com".to_string()),
                sub: None,
                aud: Some("https://self-issued.me/v2".to_string()),
                exp: Some((jsonwebtoken::get_current_timestamp() as i64) + 300),
                nbf: None,
                iat: Some(jsonwebtoken::get_current_timestamp() as i64),
                jti: None,
            },
            params: make_test_auth_request(),
        };

        let result = validate_claims(&claims, "https://wallet.example.com");
        assert!(
            result.is_ok(),
            "aud=https://self-issued.me/v2 should be valid"
        );
    }

    #[test]
    fn validate_claims_iss_ignored() {
        let claims = RequestObjectClaims {
            rfc7519: RFC7519Claims {
                iss: Some("https://wrong-verifier.example.com".to_string()),
                sub: None,
                aud: Some("https://wallet.example.com".to_string()),
                exp: Some((jsonwebtoken::get_current_timestamp() as i64) + 300),
                nbf: None,
                iat: Some(jsonwebtoken::get_current_timestamp() as i64),
                jti: None,
            },
            params: make_test_auth_request(),
        };

        let result = validate_claims(&claims, "https://wallet.example.com");
        assert!(
            result.is_ok(),
            "iss claim should be ignored per OpenID4VP §5.8"
        );
    }

    #[test]
    fn validate_claims_expired() {
        let claims = RequestObjectClaims {
            rfc7519: RFC7519Claims {
                iss: Some("https://verifier.example.com".to_string()),
                sub: None,
                aud: Some("https://wallet.example.com".to_string()),
                exp: Some((jsonwebtoken::get_current_timestamp() as i64) - 1),
                nbf: None,
                iat: Some(jsonwebtoken::get_current_timestamp() as i64 - 7200),
                jti: None,
            },
            params: make_test_auth_request(),
        };

        let result = validate_claims(&claims, "https://wallet.example.com");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("expired"));
    }

    #[test]
    fn validate_claims_missing_exp() {
        let claims = RequestObjectClaims {
            rfc7519: RFC7519Claims {
                iss: Some("https://verifier.example.com".to_string()),
                sub: None,
                aud: Some("https://wallet.example.com".to_string()),
                exp: None,
                nbf: None,
                iat: Some(jsonwebtoken::get_current_timestamp() as i64),
                jti: None,
            },
            params: make_test_auth_request(),
        };

        let result = validate_claims(&claims, "https://wallet.example.com");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("exp"));
    }

    #[test]
    fn validate_claims_iat_future() {
        let claims = RequestObjectClaims {
            rfc7519: RFC7519Claims {
                iss: Some("https://verifier.example.com".to_string()),
                sub: None,
                aud: Some("https://wallet.example.com".to_string()),
                exp: Some((jsonwebtoken::get_current_timestamp() as i64) + 300),
                nbf: None,
                iat: Some((jsonwebtoken::get_current_timestamp() as i64) + 3600),
                jti: None,
            },
            params: make_test_auth_request(),
        };

        let result = validate_claims(&claims, "https://wallet.example.com");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("future"));
    }

    #[test]
    fn validate_claims_valid() {
        let claims = RequestObjectClaims {
            rfc7519: RFC7519Claims {
                iss: Some("https://verifier.example.com".to_string()),
                sub: None,
                aud: Some("https://wallet.example.com".to_string()),
                exp: Some((jsonwebtoken::get_current_timestamp() as i64) + 300),
                nbf: None,
                iat: Some(jsonwebtoken::get_current_timestamp() as i64),
                jti: None,
            },
            params: make_test_auth_request(),
        };

        let result = validate_claims(&claims, "https://wallet.example.com");
        assert!(result.is_ok());
    }

    #[test]
    fn validate_claims_missing_iss() {
        let claims = RequestObjectClaims {
            rfc7519: RFC7519Claims {
                iss: None,
                sub: None,
                aud: Some("https://wallet.example.com".to_string()),
                exp: Some((jsonwebtoken::get_current_timestamp() as i64) + 300),
                nbf: None,
                iat: Some(jsonwebtoken::get_current_timestamp() as i64),
                jti: None,
            },
            params: make_test_auth_request(),
        };

        let result = validate_claims(&claims, "https://wallet.example.com");
        assert!(
            result.is_ok(),
            "missing iss should be allowed for unsigned requests"
        );
    }

    fn create_unsigned_jwt_payload(client_id: &str, wallet_id: &str) -> String {
        let now = jsonwebtoken::get_current_timestamp() as i64;
        let payload = serde_json::json!({
            "iss": client_id,
            "aud": wallet_id,
            "exp": now + 300,
            "iat": now,
            "client_id": client_id,
            "response_type": "vp_token",
            "response_mode": "direct_post",
            "nonce": "test-nonce",
            "response_uri": "https://verifier.example.com/response",
            "scope": "openid"
        });
        let mut header = Header::new(Algorithm::HS256);
        header.typ = Some("oauth-authz-req+jwt".to_string());
        encode(&header, &payload, &EncodingKey::from_secret(TEST_SECRET)).unwrap()
    }

    fn create_signed_jwt(client_id: &str, wallet_id: &str) -> String {
        let now = jsonwebtoken::get_current_timestamp() as i64;
        let payload = serde_json::json!({
            "iss": client_id,
            "aud": wallet_id,
            "exp": now + 300,
            "iat": now,
            "client_id": client_id,
            "response_type": "vp_token",
            "response_mode": "direct_post",
            "nonce": "test-nonce",
            "response_uri": "https://verifier.example.com/response",
            "scope": "openid"
        });
        let mut header = Header::new(Algorithm::HS256);
        header.typ = Some("oauth-authz-req+jwt".to_string());
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
        ) -> Result<DecodingKey> {
            Ok(self.key.clone())
        }
    }

    #[tokio::test]
    async fn decode_unsigned_valid() {
        let jwt = create_unsigned_jwt_payload(
            "redirect_uri:https://verifier.example.com",
            "https://wallet.example.com",
        );
        let result = RequestObject::decode_unsigned(&jwt, "https://wallet.example.com").await;
        assert!(
            result.is_ok(),
            "decode_unsigned should succeed for valid unsigned request"
        );
        let request_object = result.unwrap();
        assert_eq!(
            request_object.client_id,
            ParsedClientId::parse("redirect_uri:https://verifier.example.com").unwrap()
        );
        assert!(!client_id_requires_signature(&request_object.client_id));
    }

    #[tokio::test]
    async fn decode_unsigned_rejects_signed_client_id_schemes() {
        let test_cases = [
            "decentralized_identifier:did:jwk:eyBrZXkiIDogInZhbHVlIiB9",
            "x509_san_dns:verifier.example.com",
            "x509_hash:Uvo3HtuIxuhC92rShpgqcT3YXwrqRxWEviRiA0OZszk",
            "verifier_attestation:eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
        ];

        for client_id in test_cases {
            let jwt = create_unsigned_jwt_payload(client_id, "https://wallet.example.com");
            let result = RequestObject::decode_unsigned(&jwt, "https://wallet.example.com").await;
            assert!(
                result.is_err(),
                "decode_unsigned should reject client_id scheme '{}' which requires signature",
                client_id
            );
            let err = result.unwrap_err();
            assert!(
                err.to_string().contains("requires a signed Request Object"),
                "error message should mention signature requirement,got: {}",
                err
            );
        }
    }

    #[tokio::test]
    async fn decode_unsigned_missing_client_id() {
        let now = jsonwebtoken::get_current_timestamp() as i64;
        let payload = serde_json::json!({
            "iss": "redirect_uri:https://verifier.example.com",
            "aud": "https://wallet.example.com",
            "exp": now + 300,
            "iat": now,
            "response_type": "vp_token",
            "response_mode": "direct_post",
            "nonce": "test-nonce",
            "response_uri": "https://verifier.example.com/response",
            "scope": "openid"
        });
        let mut header = Header::new(Algorithm::HS256);
        header.typ = Some("oauth-authz-req+jwt".to_string());
        let jwt = encode(&header, &payload, &EncodingKey::from_secret(TEST_SECRET)).unwrap();

        let result = RequestObject::decode_unsigned(&jwt, "https://wallet.example.com").await;
        assert!(
            result.is_err(),
            "decode_unsigned should fail when client_id is missing"
        );
    }

    #[tokio::test]
    async fn decode_unsigned_expired() {
        let jwt = {
            let now = jsonwebtoken::get_current_timestamp() as i64;
            let payload = serde_json::json!({
                "iss": "redirect_uri:https://verifier.example.com",
                "aud": "https://wallet.example.com",
                "exp": now - 100,
                "iat": now - 200,
                "client_id": "redirect_uri:https://verifier.example.com",
                "response_type": "vp_token",
                "response_mode": "direct_post",
                "nonce": "test-nonce",
                "response_uri": "https://verifier.example.com/response",
                "scope": "openid"
            });
            let mut header = Header::new(Algorithm::HS256);
            header.typ = Some("oauth-authz-req+jwt".to_string());
            encode(&header, &payload, &EncodingKey::from_secret(TEST_SECRET)).unwrap()
        };

        let result = RequestObject::decode_unsigned(&jwt, "https://wallet.example.com").await;
        assert!(
            result.is_err(),
            "decode_unsigned should fail when exp is in the past"
        );
    }

    #[tokio::test]
    async fn decode_unsigned_self_issued_audience() {
        let jwt = create_unsigned_jwt_payload(
            "redirect_uri:https://verifier.example.com",
            "https://self-issued.me/v2",
        );
        let result = RequestObject::decode_unsigned(&jwt, "https://wallet.example.com").await;
        assert!(
            result.is_ok(),
            "decode_unsigned should succeed with self-issued audience"
        );
    }

    #[tokio::test]
    async fn decode_and_validate_valid() {
        let jwt = create_signed_jwt(
            "redirect_uri:https://verifier.example.com",
            "https://wallet.example.com",
        );
        let resolver = MockResolver {
            key: DecodingKey::from_secret(TEST_SECRET),
        };
        let result =
            RequestObject::decode_and_validate(&jwt, "https://wallet.example.com", &resolver).await;
        assert!(
            result.is_ok(),
            "decode_and_validate should succeed for valid signed JWT: {:?}",
            result.err()
        );
        let request_object = result.unwrap();
        assert_eq!(
            request_object.client_id,
            ParsedClientId::parse("redirect_uri:https://verifier.example.com").unwrap()
        );
    }

    #[tokio::test]
    async fn decode_and_validate_invalid_signature() {
        let jwt = create_signed_jwt(
            "redirect_uri:https://verifier.example.com",
            "https://wallet.example.com",
        );
        let resolver = MockResolver {
            key: DecodingKey::from_secret(b"wrong-secret"),
        };
        let result =
            RequestObject::decode_and_validate(&jwt, "https://wallet.example.com", &resolver).await;
        assert!(
            result.is_err(),
            "decode_and_validate should fail with invalid signature"
        );
    }

    #[tokio::test]
    async fn decode_and_validate_wrong_audience() {
        let jwt = create_signed_jwt(
            "redirect_uri:https://verifier.example.com",
            "https://wrong-wallet.example.com",
        );
        let resolver = MockResolver {
            key: DecodingKey::from_secret(TEST_SECRET),
        };
        let result =
            RequestObject::decode_and_validate(&jwt, "https://wallet.example.com", &resolver).await;
        assert!(
            result.is_err(),
            "decode_and_validate should fail with wrong audience"
        );
    }

    #[tokio::test]
    async fn decode_and_validate_self_issued_audience() {
        let jwt = create_signed_jwt(
            "redirect_uri:https://verifier.example.com",
            "https://self-issued.me/v2",
        );
        let resolver = MockResolver {
            key: DecodingKey::from_secret(TEST_SECRET),
        };
        let result =
            RequestObject::decode_and_validate(&jwt, "https://wallet.example.com", &resolver).await;
        assert!(
            result.is_ok(),
            "decode_and_validate should succeed with self-issued audience"
        );
    }
}
