//! JWT-Secured Authorization Request (JAR) parsing and validation.
//!
//! Implements parsing and validation of Request Objects per OpenID4VP Section 5.8
//! and RFC 9101. Verifiers send Authorization Requests as signed JWTs; the Wallet
//! verifies the signature and validates claims.

use super::authorization::AuthorizationRequest;
use super::client_id::ParsedClientId;
use crate::core::rfc7519::RFC7519Claims;
use crate::errors::{Error, ErrorKind, Result};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{DecodingKey, Header, Validation, dangerous, decode, decode_header};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

const REQUEST_OBJECT_TYP: &str = "oauth-authz-req+jwt";
const SELF_ISSUED_AUDIENCE: &str = "https://self-issued.me/v2";
const MAX_IAT_AGE_SECONDS: i64 = 60 * 60;

/// Discovery mode for audience validation.
///
/// Per OpenID4VP Section 5.8:
/// - In **static discovery mode**, the `aud` claim MUST be the Wallet's identifier
/// - In **dynamic discovery mode**, the `aud` claim MAY be any value (self-issued is accepted)
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
pub enum RequestObjectHeader {
    Signed(Box<Header>),
    Unsigned { typ: String },
}

#[derive(Debug, Clone)]
pub struct RequestObject {
    pub header: RequestObjectHeader,
    pub claims: RequestObjectClaims,
    pub client_id: ParsedClientId,
}

impl RequestObject {
    pub async fn decode_and_validate(
        jwt: &str,
        outer_client_id: Option<&str>,
        wallet_id: &str,
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
        if discovery_mode == DiscoveryMode::Static {
            validation.set_audience(&[wallet_id]);
        } else {
            validation.set_audience(&[wallet_id, SELF_ISSUED_AUDIENCE]);
        }
        validation.set_required_spec_claims(&["exp", "iat"]);

        let token_data = decode::<RequestObjectClaims>(jwt, &decoding_key, &validation)
            .map_err(|e| Error::message(ErrorKind::InvalidPresentationRequest, e.to_string()))?;

        validate_claims(&token_data.claims, wallet_id, discovery_mode)?;

        Ok(Self {
            header: RequestObjectHeader::Signed(Box::new(header)),
            claims: token_data.claims,
            client_id: parsed_client_id,
        })
    }

    pub async fn decode_unsigned(
        jwt: &str,
        outer_client_id: Option<&str>,
        wallet_id: &str,
        discovery_mode: DiscoveryMode,
    ) -> Result<Self> {
        let header_str = jwt.split('.').next().ok_or_else(|| {
            Error::message(
                ErrorKind::InvalidPresentationRequest,
                "malformed JWT: missing header",
            )
        })?;

        let header_json = URL_SAFE_NO_PAD.decode(header_str.as_bytes()).map_err(|e| {
            Error::message(
                ErrorKind::InvalidPresentationRequest,
                format!("malformed JWT: {e}"),
            )
        })?;
        let header_json_str = String::from_utf8(header_json).map_err(|e| {
            Error::message(
                ErrorKind::InvalidPresentationRequest,
                format!("malformed JWT: {e}"),
            )
        })?;

        let header_value: serde_json::Value =
            serde_json::from_str(&header_json_str).map_err(|e| {
                Error::message(
                    ErrorKind::InvalidPresentationRequest,
                    format!("malformed JWT: {e}"),
                )
            })?;

        let algo = header_value
            .get("alg")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                Error::message(
                    ErrorKind::InvalidPresentationRequest,
                    "malformed JWT: missing alg",
                )
            })?;

        if algo.to_lowercase() != "none" {
            return Err(Error::message(
                ErrorKind::InvalidPresentationRequest,
                format!("unsupported JOSE header: expected alg 'none' for unsigned, got '{algo}'"),
            ));
        }

        let typ = header_value
            .get("typ")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
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

        let claims_json_bytes = URL_SAFE_NO_PAD
            .decode(
                jwt.split('.')
                    .nth(1)
                    .ok_or_else(|| {
                        Error::message(
                            ErrorKind::InvalidPresentationRequest,
                            "malformed JWT: missing payload",
                        )
                    })?
                    .as_bytes(),
            )
            .map_err(|e| {
                Error::message(
                    ErrorKind::InvalidPresentationRequest,
                    format!("malformed JWT: {e}"),
                )
            })?;

        let claims: RequestObjectClaims =
            serde_json::from_slice(&claims_json_bytes).map_err(|e| {
                Error::message(
                    ErrorKind::InvalidPresentationRequest,
                    format!("malformed JWT: {e}"),
                )
            })?;

        let client_id_str = claims.params.client_id.as_str();
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

        if client_id_requires_signature(&parsed_client_id) {
            return Err(Error::message(
                ErrorKind::InvalidPresentationRequest,
                format!(
                    "client_id scheme '{}' requires a signed Request Object",
                    client_id_str
                ),
            ));
        }

        validate_claims(&claims, wallet_id, discovery_mode)?;

        Ok(Self {
            header: RequestObjectHeader::Unsigned {
                typ: typ.to_string(),
            },
            claims,
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

fn validate_claims(
    claims: &RequestObjectClaims,
    wallet_id: &str,
    discovery_mode: DiscoveryMode,
) -> Result<()> {
    let aud_valid = match &claims.rfc7519.aud {
        Some(aud) => match discovery_mode {
            DiscoveryMode::Static => aud == wallet_id,
            DiscoveryMode::Dynamic => aud == wallet_id || aud == SELF_ISSUED_AUDIENCE,
        },
        None => false,
    };
    if !aud_valid {
        let aud_msg = claims.rfc7519.aud.as_deref().unwrap_or("missing");
        return Err(Error::message(
            ErrorKind::InvalidPresentationRequest,
            format!("invalid aud: '{aud_msg}'"),
        ));
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

    fn create_unsigned_jwt(client_id: &str, aud: &str) -> String {
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
        let header_b64 = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"oauth-authz-req+jwt"}"#);
        let payload_b64 = URL_SAFE_NO_PAD.encode(&payload.to_string().as_bytes());
        format!("{}.{}.", header_b64, payload_b64)
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
    async fn valid_signed_request_object() {
        let jwt = create_signed_jwt(
            "redirect_uri:https://verifier.example.com",
            "https://wallet.example.com",
        );
        let resolver = MockResolver {
            key: DecodingKey::from_secret(TEST_SECRET),
        };
        let result = RequestObject::decode_and_validate(
            &jwt,
            Some("redirect_uri:https://verifier.example.com"),
            "https://wallet.example.com",
            DiscoveryMode::Dynamic,
            &resolver,
        )
        .await;
        assert!(result.is_ok(), "should succeed: {:?}", result.err());
    }

    #[tokio::test]
    async fn valid_unsigned_request_object() {
        let jwt = create_unsigned_jwt(
            "redirect_uri:https://verifier.example.com",
            "https://wallet.example.com",
        );
        let result = RequestObject::decode_unsigned(
            &jwt,
            Some("redirect_uri:https://verifier.example.com"),
            "https://wallet.example.com",
            DiscoveryMode::Dynamic,
        )
        .await;
        assert!(result.is_ok(), "should succeed: {:?}", result.err());
    }

    #[tokio::test]
    async fn invalid_signature() {
        let jwt = create_signed_jwt(
            "redirect_uri:https://verifier.example.com",
            "https://wallet.example.com",
        );
        let resolver = MockResolver {
            key: DecodingKey::from_secret(b"wrong-secret"),
        };
        let result = RequestObject::decode_and_validate(
            &jwt,
            Some("redirect_uri:https://verifier.example.com"),
            "https://wallet.example.com",
            DiscoveryMode::Dynamic,
            &resolver,
        )
        .await;
        assert!(result.is_err(), "should fail with invalid signature");
    }

    #[tokio::test]
    async fn expired_request_object() {
        let now = jsonwebtoken::get_current_timestamp() as i64;
        let payload = serde_json::json!({
            "iss": "redirect_uri:https://verifier.example.com",
            "aud": "https://wallet.example.com",
            "exp": now - 1,
            "iat": now - 100,
            "client_id": "redirect_uri:https://verifier.example.com",
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
            Some("redirect_uri:https://verifier.example.com"),
            "https://wallet.example.com",
            DiscoveryMode::Dynamic,
            &resolver,
        )
        .await;
        assert!(result.is_err(), "should fail for expired");
    }

    #[tokio::test]
    async fn invalid_nbf() {
        let now = jsonwebtoken::get_current_timestamp() as i64;
        let payload = serde_json::json!({
            "iss": "redirect_uri:https://verifier.example.com",
            "aud": "https://wallet.example.com",
            "exp": now + 3600,
            "nbf": now + 300,
            "iat": now,
            "client_id": "redirect_uri:https://verifier.example.com",
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
            Some("redirect_uri:https://verifier.example.com"),
            "https://wallet.example.com",
            DiscoveryMode::Dynamic,
            &resolver,
        )
        .await;
        assert!(result.is_err(), "should fail for invalid nbf");
    }

    #[tokio::test]
    async fn invalid_aud_static() {
        let jwt = create_signed_jwt(
            "redirect_uri:https://verifier.example.com",
            "https://wrong-wallet.example.com",
        );
        let resolver = MockResolver {
            key: DecodingKey::from_secret(TEST_SECRET),
        };
        let result = RequestObject::decode_and_validate(
            &jwt,
            Some("redirect_uri:https://verifier.example.com"),
            "https://wallet.example.com",
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
    async fn missing_required_claims_exp() {
        let now = jsonwebtoken::get_current_timestamp() as i64;
        let payload = serde_json::json!({
            "iss": "redirect_uri:https://verifier.example.com",
            "aud": "https://wallet.example.com",
            "iat": now,
            "client_id": "redirect_uri:https://verifier.example.com",
            "response_type": "vp_token",
            "response_mode": "direct_post",
            "nonce": "test-nonce",
            "scope": "openid",
        });
        let header_json = serde_json::json!({"alg":"none","typ":"oauth-authz-req+jwt"});
        let header_b64 = URL_SAFE_NO_PAD.encode(&header_json.to_string().as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(&payload.to_string().as_bytes());
        let jwt = format!("{}.{}.", header_b64, payload_b64);
        let result = RequestObject::decode_unsigned(
            &jwt,
            Some("redirect_uri:https://verifier.example.com"),
            "https://wallet.example.com",
            DiscoveryMode::Dynamic,
        )
        .await;
        assert!(result.is_err(), "should fail for missing exp");
    }

    #[tokio::test]
    async fn malformed_jwt() {
        let result = RequestObject::decode_unsigned(
            "not-a-jwt",
            None,
            "https://wallet.example.com",
            DiscoveryMode::Dynamic,
        )
        .await;
        assert!(result.is_err(), "should fail for malformed JWT");
    }

    #[tokio::test]
    async fn unsupported_jose_header() {
        let now = jsonwebtoken::get_current_timestamp() as i64;
        let payload = serde_json::json!({
            "iss": "redirect_uri:https://verifier.example.com",
            "aud": "https://wallet.example.com",
            "exp": now + 300,
            "iat": now,
            "client_id": "redirect_uri:https://verifier.example.com",
            "response_type": "vp_token",
            "response_mode": "direct_post",
            "nonce": "test-nonce",
            "scope": "openid",
        });
        let header_b64 = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"wrong-type"}"#);
        let payload_b64 = URL_SAFE_NO_PAD.encode(&payload.to_string().as_bytes());
        let jwt = format!("{}.{}.", header_b64, payload_b64);
        let result = RequestObject::decode_unsigned(
            &jwt,
            Some("redirect_uri:https://verifier.example.com"),
            "https://wallet.example.com",
            DiscoveryMode::Dynamic,
        )
        .await;
        assert!(result.is_err(), "should fail for unsupported typ");
        assert!(result.unwrap_err().to_string().contains("typ"));
    }
}
