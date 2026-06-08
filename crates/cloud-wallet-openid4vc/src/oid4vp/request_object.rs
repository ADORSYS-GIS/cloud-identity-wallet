//! JWT-Secured Authorization Request (JAR) parsing and validation.
//!
//! Implements parsing and validation of Request Objects per OpenID4VP Section 5.8
//! and RFC 9101. Verifiers send Authorization Requests as signed JWTs; the Wallet
//! verifies the signature and validates claims.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::Header;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::skip_serializing_none;
use url::Url;

use super::authorization::AuthorizationRequest;
use crate::core::rfc7519::RFC7519Claims;
use crate::errors::{Error, ErrorKind, Result};

const REQUEST_OBJECT_TYP: &str = "oauth-authz-req+jwt";
const SELF_ISSUED_AUDIENCE: &str = "https://self-issued.me/v2";

/// Parsed `client_id` identifying the key resolution strategy.
///
/// Per OpenID4VP Section 5.6, the `client_id` prefix determines how the verifier's
/// public key is obtained for signature verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedClientId {
    /// X.509 certificate with SAN DNS. Format: `x509_san_dns:<san-dns-name>`.
    X509SanDns { san_dns: String },

    /// X.509 certificate verified by hash. Format: `x509_hash:<algorithm>:<hash-value>`.
    X509Hash { algorithm: String, hash: String },

    /// Decentralized Identifier. Format: `did:<method>:<identifier>`.
    DecentralizedIdentifier { did: String },

    /// Verifier attestation. Format: `verifier_attestation:<attestation-jwt>`.
    VerifierAttestation { attestation: String },

    /// Redirect URI (unsigned requests). Format: `redirect_uri:<uri>`.
    RedirectUri { uri: Url },
}

impl ParsedClientId {
    /// Parses a `client_id` string into its variant.
    pub fn parse(client_id: &str) -> Result<Self> {
        if client_id.trim().is_empty() {
            return Err(Error::message(
                ErrorKind::InvalidPresentationRequest,
                "client_id must not be empty",
            ));
        }

        if let Some(san_dns) = client_id.strip_prefix("x509_san_dns:") {
            if san_dns.trim().is_empty() {
                return Err(Error::message(
                    ErrorKind::InvalidPresentationRequest,
                    "x509_san_dns scheme requires a non-empty SAN DNS name",
                ));
            }
            return Ok(Self::X509SanDns {
                san_dns: san_dns.to_string(),
            });
        }

        if let Some(rest) = client_id.strip_prefix("x509_hash:") {
            let parts: Vec<&str> = rest.splitn(2, ':').collect();
            if parts.len() != 2 {
                return Err(Error::message(
                    ErrorKind::InvalidPresentationRequest,
                    "x509_hash scheme requires format: x509_hash:<algorithm>:<hash>",
                ));
            }
            let algorithm = parts[0].trim();
            let hash = parts[1].trim();
            if algorithm.is_empty() || hash.is_empty() {
                return Err(Error::message(
                    ErrorKind::InvalidPresentationRequest,
                    "x509_hash scheme requires non-empty algorithm and hash",
                ));
            }
            return Ok(Self::X509Hash {
                algorithm: algorithm.to_string(),
                hash: hash.to_string(),
            });
        }

        if let Some(attestation) = client_id.strip_prefix("verifier_attestation:") {
            if attestation.trim().is_empty() {
                return Err(Error::message(
                    ErrorKind::InvalidPresentationRequest,
                    "verifier_attestation scheme requires a non-empty attestation JWT",
                ));
            }
            return Ok(Self::VerifierAttestation {
                attestation: attestation.to_string(),
            });
        }

        if client_id.starts_with("did:") {
            return Ok(Self::DecentralizedIdentifier {
                did: client_id.to_string(),
            });
        }

        if let Some(uri_str) = client_id.strip_prefix("redirect_uri:") {
            let uri = Url::parse(uri_str).map_err(|e| {
                Error::message(
                    ErrorKind::InvalidPresentationRequest,
                    format!("redirect_uri contains invalid URL: {e}"),
                )
            })?;
            if uri.scheme() != "https" {
                return Err(Error::message(
                    ErrorKind::InvalidPresentationRequest,
                    "redirect_uri must use https scheme",
                ));
            }
            return Ok(Self::RedirectUri { uri });
        }

        Err(Error::message(
            ErrorKind::InvalidPresentationRequest,
            format!("unrecognized client_id scheme: {client_id}"),
        ))
    }

    /// Returns `true` if this client_id scheme requires a signed Request Object.
    pub fn requires_signature(&self) -> bool {
        !matches!(self, Self::RedirectUri { .. })
    }
}

/// JWT header fields extracted from a Request Object.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RequestObjectHeader {
    /// Signing algorithm. Must not be "none".
    pub alg: String,

    /// Type. Must be `oauth-authz-req+jwt` per RFC 9101.
    pub typ: Option<String>,

    /// Key ID for key resolution.
    pub kid: Option<String>,

    /// Embedded JSON Web Key.
    pub jwk: Option<Value>,

    /// X.509 certificate chain (base64-encoded DER, leaf first).
    pub x5c: Option<Vec<String>>,
}

impl RequestObjectHeader {
    /// Validates `typ` and `alg` per RFC 9101.
    pub fn validate(&self) -> Result<()> {
        let typ = self.typ.as_deref().ok_or_else(|| {
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

        if self.alg.eq_ignore_ascii_case("none") {
            return Err(Error::message(
                ErrorKind::InvalidPresentationRequest,
                "Request Object alg must not be 'none'",
            ));
        }

        Ok(())
    }
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
    pub header: RequestObjectHeader,
    pub claims: RequestObjectClaims,
    pub client_id: ParsedClientId,
}

impl RequestObject {
    /// Decodes a Request Object without verifying the signature.
    ///
    /// Usedfor `redirect_uri` client_id schemes where unsigned requests are permitted.
    pub async fn decode_unsigned(jwt: &str, wallet_id: &str) -> Result<Self> {
        validate_compact_jws(jwt)?;

        let header = decode_header(jwt)?;
        let request_header = parse_header_claims(&header)?;

        let claims: RequestObjectClaims = decode_unverified_payload(jwt)?;
        let client_id_str = claims.params.client_id.as_str();
        let parsed_client_id = ParsedClientId::parse(client_id_str)?;

        if parsed_client_id.requires_signature() {
            return Err(Error::message(
                ErrorKind::InvalidPresentationRequest,
                format!(
                    "client_id scheme '{}' requires a signed Request Object butdecode_unsigned was called",
                    client_id_str
                ),
            ));
        }

        validate_claims(&claims, wallet_id)?;

        Ok(Self {
            header: request_header,
            claims,
            client_id: parsed_client_id,
        })
    }
}

fn validate_compact_jws(raw: &str) -> Result<()> {
    let parts: Vec<&str> = raw.split('.').collect();
    if parts.len() != 3 {
        return Err(Error::message(
            ErrorKind::InvalidPresentationRequest,
            "Request Object must be a compact JWS (3 parts separated by '.')",
        ));
    }
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            return Err(Error::message(
                ErrorKind::InvalidPresentationRequest,
                format!(
                    "Request Object {} segment must not be empty",
                    match i {
                        0 => "header",
                        1 => "payload",
                        2 => "signature",
                        _ => "unknown",
                    }
                ),
            ));
        }
    }
    Ok(())
}

fn decode_header(jwt: &str) -> Result<Header> {
    let header_b64 = jwt.split('.').next().ok_or_else(|| {
        Error::message(
            ErrorKind::InvalidPresentationRequest,
            "JWT has no header segment",
        )
    })?;

    let header_json = URL_SAFE_NO_PAD.decode(header_b64.as_bytes()).map_err(|e| {
        Error::message(
            ErrorKind::InvalidPresentationRequest,
            format!("failed to decode header base64: {e}"),
        )
    })?;

    let header: Header = serde_json::from_slice(&header_json).map_err(|e| {
        Error::message(
            ErrorKind::InvalidPresentationRequest,
            format!("failed to parse header JSON: {e}"),
        )
    })?;

    Ok(header)
}

fn parse_header_claims(header: &Header) -> Result<RequestObjectHeader> {
    let header_json = serde_json::to_value(header).map_err(|e| {
        Error::message(
            ErrorKind::InvalidPresentationRequest,
            format!("failed to serialize header: {e}"),
        )
    })?;

    serde_json::from_value(header_json).map_err(|e| {
        Error::message(
            ErrorKind::InvalidPresentationRequest,
            format!("failed to parse header fields: {e}"),
        )
    })
}

fn decode_unverified_payload<T: for<'de> Deserialize<'de>>(jwt: &str) -> Result<T> {
    let payload_b64 = jwt.split('.').nth(1).ok_or_else(|| {
        Error::message(
            ErrorKind::InvalidPresentationRequest,
            "JWT has no payload segment",
        )
    })?;

    let payload_json = URL_SAFE_NO_PAD
        .decode(payload_b64.as_bytes())
        .map_err(|e| {
            Error::message(
                ErrorKind::InvalidPresentationRequest,
                format!("failed to decode payload base64: {e}"),
            )
        })?;

    serde_json::from_slice(&payload_json).map_err(|e| {
        Error::message(
            ErrorKind::InvalidPresentationRequest,
            format!("failed to parse payload JSON: {e}"),
        )
    })
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
    use super::super::authorization::{AuthorizationRequest, ResponseMode, ResponseType};
    use super::*;

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
        assert_eq!(
            parsed,
            ParsedClientId::X509SanDns {
                san_dns: "verifier.example.com".to_string()
            }
        );
        assert!(parsed.requires_signature());
    }

    #[test]
    fn parse_client_id_x509_hash() {
        let parsed = ParsedClientId::parse("x509_hash:sha256:abc123").unwrap();
        assert_eq!(
            parsed,
            ParsedClientId::X509Hash {
                algorithm: "sha256".to_string(),
                hash: "abc123".to_string()
            }
        );
        assert!(parsed.requires_signature());
    }

    #[test]
    fn parse_client_id_did() {
        let parsed = ParsedClientId::parse("did:jwk:eyBrZXkiIDogInZhbHVlIiB9").unwrap();
        assert_eq!(
            parsed,
            ParsedClientId::DecentralizedIdentifier {
                did: "did:jwk:eyBrZXkiIDogInZhbHVlIiB9".to_string()
            }
        );
        assert!(parsed.requires_signature());
    }

    #[test]
    fn parse_client_id_verifier_attestation() {
        let parsed = ParsedClientId::parse(
            "verifier_attestation:eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
        )
        .unwrap();
        assert_eq!(
            parsed,
            ParsedClientId::VerifierAttestation {
                attestation: "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
                    .to_string()
            }
        );
        assert!(parsed.requires_signature());
    }

    #[test]
    fn parse_client_id_redirect_uri() {
        let parsed =
            ParsedClientId::parse("redirect_uri:https://verifier.example.com/callback").unwrap();
        if let ParsedClientId::RedirectUri { ref uri } = parsed {
            assert_eq!(uri.as_str(), "https://verifier.example.com/callback");
            assert!(!parsed.requires_signature());
        } else {
            panic!("Expected RedirectUri variant");
        }
    }

    #[test]
    fn parse_client_id_empty() {
        let result = ParsedClientId::parse("");
        assert!(result.is_err());
    }

    #[test]
    fn parse_client_id_invalid() {
        let result = ParsedClientId::parse("not-a-valid-client-id");
        assert!(result.is_err());
    }

    #[test]
    fn request_object_header_validate_typ() {
        let header = RequestObjectHeader {
            alg: "ES256".to_string(),
            typ: Some("oauth-authz-req+jwt".to_string()),
            kid: None,
            jwk: None,
            x5c: None,
        };
        assert!(header.validate().is_ok());

        let header_invalid_typ = RequestObjectHeader {
            alg: "ES256".to_string(),
            typ: Some("invalid".to_string()),
            kid: None,
            jwk: None,
            x5c: None,
        };
        assert!(header_invalid_typ.validate().is_err());
    }

    #[test]
    fn request_object_header_validate_alg_none() {
        let header = RequestObjectHeader {
            alg: "none".to_string(),
            typ: None,
            kid: None,
            jwk: None,
            x5c: None,
        };
        assert!(header.validate().is_err());
    }

    #[test]
    fn validate_compact_jws_valid() {
        let valid_jwt = "header.payload.signature";
        assert!(validate_compact_jws(valid_jwt).is_ok());
    }

    #[test]
    fn validate_compact_jws_invalid_parts() {
        let too_few_parts = "header.payload";
        assert!(validate_compact_jws(too_few_parts).is_err());

        let empty_part = "header..signature";
        assert!(validate_compact_jws(empty_part).is_err());
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
        let payload_bytes = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let header_bytes =
            URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","typ":"oauth-authz-req+jwt"}"#);
        format!("{}.{}.signature", header_bytes, payload_bytes)
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
            ParsedClientId::RedirectUri {
                uri: Url::parse("https://verifier.example.com").unwrap()
            }
        );
        assert!(!request_object.client_id.requires_signature());
    }

    #[tokio::test]
    async fn decode_unsigned_rejects_signed_client_id_schemes() {
        let test_cases = [
            "did:jwk:eyBrZXkiIDogInZhbHVlIiB9",
            "x509_san_dns:verifier.example.com",
            "x509_hash:sha256:abc123",
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
        let payload_bytes = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let header_bytes =
            URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","typ":"oauth-authz-req+jwt"}"#);
        let jwt = format!("{}.{}.signature", header_bytes, payload_bytes);

        let result = RequestObject::decode_unsigned(&jwt, "https://wallet.example.com").await;
        assert!(
            result.is_err(),
            "decode_unsigned should fail when client_id is missing"
        );
    }

    #[tokio::test]
    async fn decode_unsigned_expired() {
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
        let payload_bytes = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let header_bytes =
            URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","typ":"oauth-authz-req+jwt"}"#);
        let jwt = format!("{}.{}.signature", header_bytes, payload_bytes);

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
}
