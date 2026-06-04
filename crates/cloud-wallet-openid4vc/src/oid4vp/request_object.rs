//! JWT-Secured Authorization Request (JAR) parsing and validation.
//!
//! Implements parsing and validation of Request Objects per OpenID4VP Section 5.8
//! and RFC 9101. Verifiers send Authorization Requests as signed JWTs; the Wallet
//! verifies the signature and validates claims.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, Header, Validation, decode as decode_jwt};
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

    /// Redirect URI (unsigned requests). Format: HTTPS URL.
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
            return Ok(Self::X509SanDns { san_dns: san_dns.to_string() });
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
            return Ok(Self::VerifierAttestation { attestation: attestation.to_string() });
        }

        if client_id.starts_with("did:") {
            return Ok(Self::DecentralizedIdentifier { did: client_id.to_string() });
        }

        if let Ok(uri) = Url::parse(client_id) {
            if uri.scheme() == "https" {
                return Ok(Self::RedirectUri { uri });
            }
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

    /// OAuth 2.0 response_type.
    #[serde(rename = "response_type")]
    pub response_type: Option<String>,

    /// OAuth 2.0 client_id.
    #[serde(rename = "client_id")]
    pub client_id: Option<String>,

    /// OAuth 2.0 redirect_uri.
    #[serde(rename = "redirect_uri")]
    pub redirect_uri: Option<String>,

    /// OAuth 2.0 scope.
    #[serde(rename = "scope")]
    pub scope: Option<String>,

    /// OAuth 2.0 state.
    #[serde(rename = "state")]
    pub state: Option<String>,

    /// OIDC nonce.
    #[serde(rename = "nonce")]
    pub nonce: Option<String>,

    /// OID4VP response_mode.
    #[serde(rename = "response_mode")]
    pub response_mode: Option<String>,

    /// OID4VP response_uri.
    #[serde(rename = "response_uri")]
    pub response_uri: Option<String>,

    /// OID4VP request_uri.
    #[serde(rename = "request_uri")]
    pub request_uri: Option<String>,

    /// OID4VP request_uri_method.
    #[serde(rename = "request_uri_method")]
    pub request_uri_method: Option<String>,

    /// OID4VP dcql_query.
    #[serde(rename = "dcql_query")]
    pub dcql_query: Option<Value>,

    /// OID4VP client_metadata.
    #[serde(rename = "client_metadata")]
    pub client_metadata: Option<Value>,

    /// OID4VP client_metadata_uri.
    #[serde(rename = "client_metadata_uri")]
    pub client_metadata_uri: Option<String>,

    /// OID4VP transaction_data.
    #[serde(rename = "transaction_data")]
    pub transaction_data: Option<Vec<String>>,

    /// OID4VP verifier_info.
    #[serde(rename = "verifier_info")]
    pub verifier_info: Option<Vec<Value>>,

    /// OID4VP expected_origins.
    #[serde(rename = "expected_origins")]
    pub expected_origins: Option<Vec<String>>,

    /// Additional claims.
    #[serde(flatten)]
    pub additional: serde_json::Map<String, Value>,
}

/// A decoded and validated Request Object JWT.
#[derive(Debug, Clone)]
pub struct RequestObject {
    pub header: RequestObjectHeader,
    pub claims: RequestObjectClaims,
    pub client_id: ParsedClientId,
    raw: String,
}

impl RequestObject {
    /// Decodes and validates a signed Request Object JWT.
    ///
    /// Steps:
    /// 1. Extract header and validate `typ`/`alg`.
    /// 2. Decode payload (unverified) to get `client_id`.
    /// 3. Resolve verification key via `resolver`.
    /// 4. Verify signature and decode claims.
    /// 5. Validate `aud`, `iss`, `exp`, and `iat`.
    pub async fn decode_and_validate(
        jwt: &str,
        wallet_id: &str,
        resolver: &dyn VerifierKeyResolver,
    ) -> Result<Self> {
        validate_compact_jws(jwt)?;

        let header = decode_header(jwt)?;
        let request_header = parse_header_claims(&header)?;
        request_header.validate()?;

        let unverified_claims: RequestObjectClaims = decode_unverified_payload(jwt)?;
        let client_id_str = unverified_claims.client_id.as_deref().ok_or_else(|| {
            Error::message(
                ErrorKind::InvalidPresentationRequest,
                "Request Object must contain 'client_id' claim",
            )
        })?;
        let parsed_client_id = ParsedClientId::parse(client_id_str)?;

        let decoding_key = resolver
            .resolve_key(&parsed_client_id, &request_header)
            .await
            .map_err(|e| Error::message(ErrorKind::InvalidPresentationRequest, e.to_string()))?;

        let algorithm = parse_algorithm(&request_header.alg)?;
        let verified_claims = verify_and_decode(jwt, &decoding_key, algorithm)?;

        validate_claims(&verified_claims, wallet_id, client_id_str)?;

        Ok(Self {
            header: request_header,
            claims: verified_claims,
            client_id: parsed_client_id,
            raw: jwt.to_string(),
        })
    }

    /// Decodes a Request Object without verifying the signature.
    ///
    /// Used for `redirect_uri` client_id schemes where unsigned requests are permitted.
    pub async fn decode_unsigned(jwt: &str, wallet_id: &str) -> Result<Self> {
        validate_compact_jws(jwt)?;

        let header = decode_header(jwt)?;
        let request_header = parse_header_claims(&header)?;

        let claims: RequestObjectClaims = decode_unverified_payload(jwt)?;
        let client_id_str = claims.client_id.as_deref().ok_or_else(|| {
            Error::message(
                ErrorKind::InvalidPresentationRequest,
                "Request Object must contain 'client_id' claim",
            )
        })?;
        let parsed_client_id = ParsedClientId::parse(client_id_str)?;

        validate_claims(&claims, wallet_id, client_id_str)?;

        Ok(Self {
            header: request_header,
            claims,
            client_id: parsed_client_id,
            raw: jwt.to_string(),
        })
    }

    /// Returns the raw JWT string.
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// Converts this `RequestObject` into an `AuthorizationRequest`.
    pub fn into_authorization_request(self) -> Result<AuthorizationRequest> {
        let claims_value = serde_json::to_value(&self.claims)
            .map_err(|e| Error::new(ErrorKind::InvalidPresentationRequest, e))?;

        serde_json::from_value(claims_value).map_err(|e| {
            Error::message(
                ErrorKind::InvalidPresentationRequest,
                format!("failed to parse AuthorizationRequest from Request Object: {e}"),
            )
        })
    }
}

/// Trait for resolving verifier public keys.
#[async_trait::async_trait]
pub trait VerifierKeyResolver: Send + Sync {
    /// Resolves the verification key for a verifier.
    async fn resolve_key(
        &self,
        client_id: &ParsedClientId,
        header: &RequestObjectHeader,
    ) -> std::result::Result<DecodingKey, Box<dyn std::error::Error + Send + Sync>>;
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

fn parse_algorithm(alg: &str) -> Result<Algorithm> {
    match alg.to_uppercase().as_str() {
        "RS256" => Ok(Algorithm::RS256),
        "RS384" => Ok(Algorithm::RS384),
        "RS512" => Ok(Algorithm::RS512),
        "PS256" => Ok(Algorithm::PS256),
        "PS384" => Ok(Algorithm::PS384),
        "PS512" => Ok(Algorithm::PS512),
        "ES256" => Ok(Algorithm::ES256),
        "ES384" => Ok(Algorithm::ES384),
        "EDDSA" => Ok(Algorithm::EdDSA),
        _ => Err(Error::message(
            ErrorKind::InvalidPresentationRequest,
            format!("unsupported algorithm: {alg}"),
        )),
    }
}

fn verify_and_decode<T: for<'de> Deserialize<'de>>(
    jwt: &str,
    key: &DecodingKey,
    algorithm: Algorithm,
) -> Result<T> {
    let mut validation = Validation::new(algorithm);
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;

    decode_jwt::<T>(jwt, key, &validation)
        .map(|token| token.claims)
        .map_err(|e| {
            Error::message(
                ErrorKind::InvalidPresentationRequest,
                format!("JWT signature verification failed: {e}"),
            )
        })
}

fn validate_claims(claims: &RequestObjectClaims, wallet_id: &str, client_id: &str) -> Result<()> {
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

    if let Some(ref iss) = claims.rfc7519.iss {
        if iss != client_id {
            return Err(Error::message(
                ErrorKind::InvalidPresentationRequest,
                format!("Request Object iss claim '{iss}' does not match client_id '{client_id}'"),
            ));
        }
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
    use super::*;

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
        let parsed = ParsedClientId::parse("https://verifier.example.com/callback").unwrap();
        if let ParsedClientId::RedirectUri { uri } = parsed {
            assert_eq!(uri.as_str(), "https://verifier.example.com/callback");
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
    fn parse_algorithm_supported() {
        assert_eq!(parse_algorithm("RS256").unwrap(), Algorithm::RS256);
        assert_eq!(parse_algorithm("ES256").unwrap(), Algorithm::ES256);
        assert_eq!(parse_algorithm("EdDSA").unwrap(), Algorithm::EdDSA);
        assert_eq!(parse_algorithm("PS256").unwrap(), Algorithm::PS256);
    }

    #[test]
    fn parse_algorithm_unsupported() {
        assert!(parse_algorithm("HS256").is_err());
        assert!(parse_algorithm("unknown").is_err());
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
            response_type: Some("vp_token".to_string()),
            client_id: Some("https://verifier.example.com".to_string()),
            redirect_uri: None,
            scope: None,
            state: None,
            nonce: Some("test-nonce".to_string()),
            response_mode: None,
            response_uri: None,
            request_uri: None,
            request_uri_method: None,
            dcql_query: None,
            client_metadata: None,
            client_metadata_uri: None,
            transaction_data: None,
            verifier_info: None,
            expected_origins: None,
            additional: serde_json::Map::new(),
        };

        let result = validate_claims(
            &claims,
            "https://wallet.example.com",
            "https://verifier.example.com",
        );
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
            response_type: Some("vp_token".to_string()),
            client_id: Some("https://verifier.example.com".to_string()),
            redirect_uri: None,
            scope: None,
            state: None,
            nonce: Some("test-nonce".to_string()),
            response_mode: None,
            response_uri: None,
            request_uri: None,
            request_uri_method: None,
            dcql_query: None,
            client_metadata: None,
            client_metadata_uri: None,
            transaction_data: None,
            verifier_info: None,
            expected_origins: None,
            additional: serde_json::Map::new(),
        };

        let result = validate_claims(
            &claims,
            "https://wallet.example.com",
            "https://verifier.example.com",
        );
        assert!(
            result.is_ok(),
            "aud=https://self-issued.me/v2 should be valid"
        );
    }

    #[test]
    fn validate_claims_iss_mismatch() {
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
            response_type: Some("vp_token".to_string()),
            client_id: Some("https://verifier.example.com".to_string()),
            redirect_uri: None,
            scope: None,
            state: None,
            nonce: Some("test-nonce".to_string()),
            response_mode: None,
            response_uri: None,
            request_uri: None,
            request_uri_method: None,
            dcql_query: None,
            client_metadata: None,
            client_metadata_uri: None,
            transaction_data: None,
            verifier_info: None,
            expected_origins: None,
            additional: serde_json::Map::new(),
        };

        let result = validate_claims(
            &claims,
            "https://wallet.example.com",
            "https://verifier.example.com",
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("iss claim"));
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
            response_type: Some("vp_token".to_string()),
            client_id: Some("https://verifier.example.com".to_string()),
            redirect_uri: None,
            scope: None,
            state: None,
            nonce: Some("test-nonce".to_string()),
            response_mode: None,
            response_uri: None,
            request_uri: None,
            request_uri_method: None,
            dcql_query: None,
            client_metadata: None,
            client_metadata_uri: None,
            transaction_data: None,
            verifier_info: None,
            expected_origins: None,
            additional: serde_json::Map::new(),
        };

        let result = validate_claims(
            &claims,
            "https://wallet.example.com",
            "https://verifier.example.com",
        );
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
            response_type: Some("vp_token".to_string()),
            client_id: Some("https://verifier.example.com".to_string()),
            redirect_uri: None,
            scope: None,
            state: None,
            nonce: Some("test-nonce".to_string()),
            response_mode: None,
            response_uri: None,
            request_uri: None,
            request_uri_method: None,
            dcql_query: None,
            client_metadata: None,
            client_metadata_uri: None,
            transaction_data: None,
            verifier_info: None,
            expected_origins: None,
            additional: serde_json::Map::new(),
        };

        let result = validate_claims(
            &claims,
            "https://wallet.example.com",
            "https://verifier.example.com",
        );
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
            response_type: Some("vp_token".to_string()),
            client_id: Some("https://verifier.example.com".to_string()),
            redirect_uri: None,
            scope: None,
            state: None,
            nonce: Some("test-nonce".to_string()),
            response_mode: None,
            response_uri: None,
            request_uri: None,
            request_uri_method: None,
            dcql_query: None,
            client_metadata: None,
            client_metadata_uri: None,
            transaction_data: None,
            verifier_info: None,
            expected_origins: None,
            additional: serde_json::Map::new(),
        };

        let result = validate_claims(
            &claims,
            "https://wallet.example.com",
            "https://verifier.example.com",
        );
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
            response_type: Some("vp_token".to_string()),
            client_id: Some("https://verifier.example.com".to_string()),
            redirect_uri: None,
            scope: None,
            state: None,
            nonce: Some("test-nonce".to_string()),
            response_mode: None,
            response_uri: None,
            request_uri: None,
            request_uri_method: None,
            dcql_query: None,
            client_metadata: None,
            client_metadata_uri: None,
            transaction_data: None,
            verifier_info: None,
            expected_origins: None,
            additional: serde_json::Map::new(),
        };

        let result = validate_claims(
            &claims,
            "https://wallet.example.com",
            "https://verifier.example.com",
        );
        assert!(result.is_ok());
    }
}
