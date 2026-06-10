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

const REQUEST_OBJECT_TYP: &str = "oauth-authz-req+jwt";
const SELF_ISSUED_AUDIENCE: &str = "https://self-issued.me/v2";
const MAX_IAT_AGE_SECONDS: i64 = 60 * 60;

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
    async fn resolve_key(&self, client_id: &ParsedClientId, header: &Header)
    -> Result<DecodingKey>;
}

pub fn client_id_requires_signature(client_id: &ParsedClientId) -> bool {
    !client_id.is_redirect_uri()
}

#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RequestObjectClaims {
    #[serde(flatten)]
    pub rfc7519: RFC7519Claims,

    #[serde(flatten)]
    pub params: AuthorizationRequest,
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
        outer_client_id: Option<&str>,
        discovery_mode: DiscoveryMode,
        resolver: &dyn VerifierKeyResolver,
    ) -> Result<Self> {
        let header = decode_header(jwt).map_err(|e| {
            Error::message(
                ErrorKind::InvalidPresentationRequest,
                format!("malformed JWT: failed to decode header: {e}"),
            )
        })?;
        validate_header(&header)?;

        let claims_unverified: RequestObjectClaims =
            dangerous::insecure_decode::<RequestObjectClaims>(jwt)
                .map_err(|e| {
                    Error::message(
                        ErrorKind::InvalidPresentationRequest,
                        format!("malformed JWT: {e}"),
                    )
                })?
                .claims;

        let client_id_str = claims_unverified.params.client_id.as_str();
        let parsed_client_id = ParsedClientId::parse(client_id_str)
            .map_err(|e| Error::message(ErrorKind::InvalidPresentationRequest, e.to_string()))?;

        if let Some(outer) = outer_client_id
            && outer != client_id_str
        {
            return Err(Error::message(
                ErrorKind::InvalidPresentationRequest,
                format!(
                    "Request Object client_id '{client_id_str}' does not match outer client_id '{outer}'"
                ),
            ));
        }

        let decoding_key = resolver.resolve_key(&parsed_client_id, &header).await?;

        let algorithm = header.alg;
        let mut validation = Validation::new(algorithm);
        match discovery_mode {
            DiscoveryMode::Static => {
                validation.set_audience(&[SELF_ISSUED_AUDIENCE]);
            }
            DiscoveryMode::Dynamic => {
                let iss = claims_unverified.rfc7519.iss.as_deref().ok_or_else(|| {
                    Error::message(
                        ErrorKind::InvalidPresentationRequest,
                        "missing required claim: iss (required for dynamic discovery)",
                    )
                })?;
                validation.set_audience(&[iss]);
            }
        }
        validation.set_required_spec_claims(&["exp", "iat"]);

        let token_data = decode::<RequestObjectClaims>(jwt, &decoding_key, &validation)
            .map_err(|e| Error::message(ErrorKind::InvalidPresentationRequest, e.to_string()))?;

        validate_claims(&token_data.claims, discovery_mode)?;
        token_data
            .claims
            .params
            .validate()
            .map_err(|e| Error::message(ErrorKind::InvalidPresentationRequest, e.to_string()))?;

        Ok(Self {
            header,
            claims: token_data.claims,
            client_id: parsed_client_id,
        })
    }
}

fn validate_header(header: &Header) -> Result<()> {
    let typ = header.typ.as_deref().ok_or_else(|| {
        Error::message(
            ErrorKind::InvalidPresentationRequest,
            "unsupported JOSE header: missing typ",
        )
    })?;
    if typ.to_lowercase() != REQUEST_OBJECT_TYP.to_lowercase() {
        return Err(Error::message(
            ErrorKind::InvalidPresentationRequest,
            format!("unsupported JOSE header: typ must be '{REQUEST_OBJECT_TYP}', got '{typ}'"),
        ));
    }
    Ok(())
}

fn validate_claims(claims: &RequestObjectClaims, discovery_mode: DiscoveryMode) -> Result<()> {
    match discovery_mode {
        DiscoveryMode::Static => {
            let aud = claims.rfc7519.aud.as_deref().ok_or_else(|| {
                Error::message(
                    ErrorKind::InvalidPresentationRequest,
                    "missing required claim: aud",
                )
            })?;
            if aud != SELF_ISSUED_AUDIENCE {
                return Err(Error::message(
                    ErrorKind::InvalidPresentationRequest,
                    format!(
                        "invalid aud for static discovery: expected '{SELF_ISSUED_AUDIENCE}', got '{aud}'"
                    ),
                ));
            }
        }
        DiscoveryMode::Dynamic => {
            let iss = claims.rfc7519.iss.as_deref().ok_or_else(|| {
                Error::message(
                    ErrorKind::InvalidPresentationRequest,
                    "missing required claim: iss (required for dynamic discovery)",
                )
            })?;
            let aud = claims.rfc7519.aud.as_deref().ok_or_else(|| {
                Error::message(
                    ErrorKind::InvalidPresentationRequest,
                    "missing required claim: aud",
                )
            })?;
            if aud != iss {
                return Err(Error::message(
                    ErrorKind::InvalidPresentationRequest,
                    format!(
                        "invalid aud for dynamic discovery: expected '{iss}' (must equal iss), got '{aud}'"
                    ),
                ));
            }
        }
    }

    let now: i64 = jsonwebtoken::get_current_timestamp() as i64;

    match claims.rfc7519.exp {
        Some(exp) if exp <= now => {
            return Err(Error::message(
                ErrorKind::InvalidPresentationRequest,
                "expired Request Object",
            ));
        }
        None => {
            return Err(Error::message(
                ErrorKind::InvalidPresentationRequest,
                "missing required claim: exp",
            ));
        }
        _ => {}
    }

    if let Some(nbf) = claims.rfc7519.nbf
        && nbf > now
    {
        return Err(Error::message(
            ErrorKind::InvalidPresentationRequest,
            "invalid nbf: token not yet active",
        ));
    }

    match claims.rfc7519.iat {
        Some(iat) => {
            if iat < now.saturating_sub(MAX_IAT_AGE_SECONDS) {
                return Err(Error::message(
                    ErrorKind::InvalidPresentationRequest,
                    "invalid iat: too old",
                ));
            }
            if iat > now {
                return Err(Error::message(
                    ErrorKind::InvalidPresentationRequest,
                    "invalid iat: in the future",
                ));
            }
        }
        None => {
            return Err(Error::message(
                ErrorKind::InvalidPresentationRequest,
                "missing required claim: iat",
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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
        ) -> Result<DecodingKey> {
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
        let result = RequestObject::decode_and_validate(
            &jwt,
            Some(client_id),
            DiscoveryMode::Dynamic,
            &resolver,
        )
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
        let result = RequestObject::decode_and_validate(
            &jwt,
            Some(client_id),
            DiscoveryMode::Static,
            &resolver,
        )
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
        let result = RequestObject::decode_and_validate(
            &jwt,
            Some(client_id),
            DiscoveryMode::Dynamic,
            &resolver,
        )
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
        let result = RequestObject::decode_and_validate(
            &jwt,
            Some(client_id),
            DiscoveryMode::Dynamic,
            &resolver,
        )
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
        let result = RequestObject::decode_and_validate(
            &jwt,
            Some(client_id),
            DiscoveryMode::Dynamic,
            &resolver,
        )
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
        let result = RequestObject::decode_and_validate(
            &jwt,
            Some(client_id),
            DiscoveryMode::Static,
            &resolver,
        )
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
        let result = RequestObject::decode_and_validate(
            &jwt,
            Some(client_id),
            DiscoveryMode::Dynamic,
            &resolver,
        )
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
        let result = RequestObject::decode_and_validate(
            &jwt,
            Some(client_id),
            DiscoveryMode::Dynamic,
            &resolver,
        )
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
            None,
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
        let result = RequestObject::decode_and_validate(
            &jwt,
            Some(client_id),
            DiscoveryMode::Dynamic,
            &resolver,
        )
        .await;
        assert!(result.is_err(), "should fail for unsupported typ");
        assert!(result.unwrap_err().to_string().contains("typ"));
    }
}
