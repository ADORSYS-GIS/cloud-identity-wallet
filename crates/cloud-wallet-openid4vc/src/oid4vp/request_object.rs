//! JWT-Secured Authorization Request (JAR) parsing and validation.
//!
//! This module implements parsing and validation of Request Objects as specified in:
//! - OpenID4VP Section 5.8 (Request Object)
//! - RFC 9101 (JWT-Secured Authorization Request)
//!
//! Verifiers typically send the Authorization Request as a signed JWT (Request Object)
//! rather than plain query parameters. The Wallet must verify the JWT signature, extract
//! the payload, and validate claims like `aud`.

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

/// Parsed client_id identifying the key resolution strategy.
///
/// Per OpenID4VP Section 5.6, the client_id prefix determines how to obtain
/// the verifier's public key for signature verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedClientId {
    /// X.509 certificate with SAN DNS entry.
    ///
    /// The key is extracted from the leaf certificate in the `x5c` header.
    /// Format: `x509_san_dns:<san-dns-name>`
    X509SanDns {
        /// The SAN DNS name from the certificate.
        san_dns: String,
    },

    /// X.509 certificate verified by hash.
    ///
    /// The key is extracted from the leaf certificate in the `x5c` header,
    /// and the certificate hash must match the client_id.
    /// Format: `x509_hash:<algorithm>:<hash-value>`
    X509Hash {
        /// Hash algorithm (e.g., "sha256").
        algorithm: String,
        /// Base64url-encoded hash of the certificate.
        hash: String,
    },

    /// Decentralized Identifier.
    ///
    /// The key must be resolved from the DID Document associated with this identifier.
    /// Format: `did:<method>:<identifier>` (e.g., `did:jwk:...`, `did:key:...`)
    DecentralizedIdentifier {
        /// The full DID string.
        did: String,
    },

    /// Verifier attestation.
    ///
    /// The key matches the `cnf` claim in the Verifier attestation JWT provided
    /// in the request header.
    /// Format: `verifier_attestation:<attestation-jwt>`
    VerifierAttestation {
        /// The attestation JWT.
        attestation: String,
    },

    /// Redirect URI (unsigned requests).
    ///
    /// Requests using this client_id scheme cannot be signed because there's
    /// no trusted method to obtain a verification key.
    /// Format: A valid HTTPS URL used as redirect_uri.
    RedirectUri {
        /// The redirect URI.
        uri: Url,
    },
}

impl ParsedClientId {
    /// Parses a client_id string to determine the key resolution strategy.
    ///
    /// # Client ID Schemes (per OpenID4VP Section 5.6)
    ///
    /// - `x509_san_dns:<san-dns-name>` - X.509 certificate with SAN DNS
    /// - `x509_hash:<algorithm>:<hash>` - X.509 certificate verified by hash
    /// - `did:<method>:<identifier>` - Decentralized Identifier
    /// - `verifier_attestation:<attestation>` - Verifier attestation JWT
    /// - HTTPS URLs - Redirect URI (unsigned requests)
    pub fn parse(client_id: &str) -> Result<Self> {
        if client_id.trim().is_empty() {
            return Err(Error::message(
                ErrorKind::InvalidPresentationRequest,
                "client_id must not be empty",
            ));
        }

        // Check for x509_san_dns prefix
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

        // Check for x509_hash prefix
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

        // Check for verifier_attestation prefix
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

        // Check for DID prefix
        if client_id.starts_with("did:") {
            return Ok(Self::DecentralizedIdentifier {
                did: client_id.to_string(),
            });
        }

        // Check for HTTPS URL (redirect_uri scheme)
        if let Ok(uri) = Url::parse(client_id) {
            if uri.scheme() == "https" {
                return Ok(Self::RedirectUri { uri });
            }
        }

        // If it's not a recognized scheme but is a valid HTTPS URL, treat as redirect_uri
        // This matches the spec behavior for backward compatibility
        Err(Error::message(
            ErrorKind::InvalidPresentationRequest,
            format!("unrecognized client_id scheme: {client_id}"),
        ))
    }

    /// Returns true if this client_id scheme requires a signed Request Object.
    pub fn requires_signature(&self) -> bool {
        !matches!(self, Self::RedirectUri { .. })
    }
}

/// JWT header fields extracted from a Request Object.
///
/// This struct captures the standard JOSE header fields required for
/// signature verification and key resolution.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RequestObjectHeader {
    /// The algorithm used to sign the JWT.
    ///
    /// Required. Must be a supported signing algorithm (not "none").
    pub alg: String,

    /// The type of the JWT.
    ///
    /// MUST be `oauth-authz-req+jwt` per RFC 9101.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,

    /// Key ID for key resolution.
    ///
    /// Used to select a specific key from a JWKS or other key store.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    /// Embedded JSON Web Key.
    ///
    /// The public key to use for verification, embedded directly in the header.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<Value>,

    /// X.509 certificate chain.
    ///
    /// Base64-encoded DER certificates starting with the leaf certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,
}

impl RequestObjectHeader {
    /// Validates the JWT header for a Request Object.
    ///
    /// Per RFC 9101:
    /// - `typ` MUST be `oauth-authz-req+jwt`
    /// - `alg` MUST NOT be "none"
    pub fn validate(&self) -> Result<()> {
        // Validate typ
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

        // Validate alg
        if self.alg.eq_ignore_ascii_case("none") {
            return Err(Error::message(
                ErrorKind::InvalidPresentationRequest,
                "Request Object alg must not be 'none'",
            ));
        }

        Ok(())
    }
}

/// Claims in a Request Object JWT.
///
/// Per OpenID4VP Section 5.8 and RFC 9101.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RequestObjectClaims {
    /// Standard JWT registered claims.
    #[serde(flatten)]
    pub rfc7519: RFC7519Claims,

    /// OAuth 2.0 response_type parameter.
    #[serde(rename = "response_type")]
    pub response_type: Option<String>,

    /// OAuth 2.0 client_id parameter.
    ///
    /// MUST match the client_id used for key resolution.
    #[serde(rename = "client_id")]
    pub client_id: Option<String>,

    /// OAuth 2.0 redirect_uri parameter.
    #[serde(rename = "redirect_uri")]
    pub redirect_uri: Option<String>,

    /// OAuth 2.0 scope parameter.
    #[serde(rename = "scope")]
    pub scope: Option<String>,

    /// OAuth 2.0 state parameter.
    #[serde(rename = "state")]
    pub state: Option<String>,

    /// OIDC nonce parameter.
    #[serde(rename = "nonce")]
    pub nonce: Option<String>,

    /// OID4VP response_mode parameter.
    #[serde(rename = "response_mode")]
    pub response_mode: Option<String>,

    /// OID4VP response_uri parameter.
    #[serde(rename = "response_uri")]
    pub response_uri: Option<String>,

    /// OID4VP request_uri parameter.
    #[serde(rename = "request_uri")]
    pub request_uri: Option<String>,

    /// OID4VP request_uri_method parameter.
    #[serde(rename = "request_uri_method")]
    pub request_uri_method: Option<String>,

    /// OID4VP dcql_query parameter.
    #[serde(rename = "dcql_query")]
    pub dcql_query: Option<Value>,

    /// OID4VP client_metadata parameter.
    #[serde(rename = "client_metadata")]
    pub client_metadata: Option<Value>,

    /// OID4VP client_metadata_uri parameter.
    #[serde(rename = "client_metadata_uri")]
    pub client_metadata_uri: Option<String>,

    /// OID4VP transaction_data parameter.
    #[serde(rename = "transaction_data")]
    pub transaction_data: Option<Vec<String>>,

    /// OID4VP verifier_info parameter.
    #[serde(rename = "verifier_info")]
    pub verifier_info: Option<Vec<Value>>,

    /// OID4VP expected_origins parameter.
    #[serde(rename = "expected_origins")]
    pub expected_origins: Option<Vec<String>>,

    /// Additional claims not explicitly defined.
    #[serde(flatten)]
    pub additional: serde_json::Map<String, Value>,
}

/// A decoded and validated Request Object JWT.
///
/// This struct wraps the decoded JWT claims after signature verification
/// and validation have been performed.
#[derive(Debug, Clone)]
pub struct RequestObject {
    /// The decoded JWT header.
    pub header: RequestObjectHeader,

    /// The decoded JWT claims.
    pub claims: RequestObjectClaims,

    /// The parsed client_id and its resolution strategy.
    pub client_id: ParsedClientId,

    /// The raw JWT string.
    raw: String,
}

impl RequestObject {
    /// Decodes and validates a Request Object JWT.
    ///
    /// This method performs the following steps:
    ///
    /// 1. **Header Extraction**: Decode the JWT header to check `typ` and `alg`.
    /// 2. **Unverified Payload Extraction**: Decode the payload without verification
    ///    to extract `client_id` for key resolution.
    /// 3. **Key Resolution**: Use the `VerifierKeyResolver` to obtain the verification key.
    /// 4. **Signature Verification**: Verify the JWT signature with the resolved key.
    /// 5. **Claim Validation**: Validate `aud`, `iss`, `exp`, and `iat` claims.
    /// 6. **Parameter Extraction**: Extract AuthorizationRequest fields.
    ///
    /// # Arguments
    ///
    /// * `jwt` - The raw JWT string.
    /// * `wallet_id` - The wallet identifier for `aud` validation.
    /// * `resolver` - Implementation of `VerifierKeyResolver` for key resolution.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The JWT is malformed
    /// - The signature is invalid
    /// - Required claims are missing or invalid
    /// - The `aud` claim doesn't match the wallet identifier
    /// - The `iss` claim doesn't match `client_id`
    /// - The JWT is expired or issued too far in the past
    pub async fn decode_and_validate(
        jwt: &str,
        wallet_id: &str,
        resolver: &dyn VerifierKeyResolver,
    ) -> Result<Self> {
        // Step 1: Validate JWT structure (must be compact JWS)
        validate_compact_jws(jwt)?;

        // Step 2: Decode header (unverified)
        let header = decode_header(jwt)?;
        let request_header = parse_header_claims(&header)?;

        // Step 3: Validate header
        request_header.validate()?;

        // Step 4: Decode payload (unverified) to get client_id
        let unverified_claims: RequestObjectClaims = decode_unverified_payload(jwt)?;

        // Step 5: Parse client_id from unverified claims
        // Use the client_id from the JWT payload, not from query parameters
        let client_id_str = unverified_claims.client_id.as_deref().ok_or_else(|| {
            Error::message(
                ErrorKind::InvalidPresentationRequest,
                "Request Object must contain 'client_id' claim",
            )
        })?;

        let parsed_client_id = ParsedClientId::parse(client_id_str)?;

        // Step 6: Resolve verification key
        let decoding_key = resolver
            .resolve_key(&parsed_client_id, &request_header)
            .await
            .map_err(|e| Error::message(ErrorKind::InvalidPresentationRequest, e.to_string()))?;

        // Step 7: Verify signature and decode claims
        let algorithm = parse_algorithm(&request_header.alg)?;
        let verified_claims = verify_and_decode(jwt, &decoding_key, algorithm)?;

        // Step 8: Validate claims
        validate_claims(&verified_claims, wallet_id, client_id_str)?;

        // Step 9: Build RequestObject
        Ok(Self {
            header: request_header,
            claims: verified_claims,
            client_id: parsed_client_id,
            raw: jwt.to_string(),
        })
    }

    /// Attempts to decode a Request Object that may be unsigned.
    ///
    /// For `redirect_uri` client_id schemes, unsigned requests are allowed.
    /// This method will skip signature verification for those cases.
    pub async fn decode_unsigned(jwt: &str, wallet_id: &str) -> Result<Self> {
        // Validate JWT structure
        validate_compact_jws(jwt)?;

        // Decode header
        let header = decode_header(jwt)?;
        let request_header = parse_header_claims(&header)?;

        // Decode payload (unverified)
        let claims: RequestObjectClaims = decode_unverified_payload(jwt)?;

        // Parse client_id
        let client_id_str = claims.client_id.as_deref().ok_or_else(|| {
            Error::message(
                ErrorKind::InvalidPresentationRequest,
                "Request Object must contain 'client_id' claim",
            )
        })?;

        let parsed_client_id = ParsedClientId::parse(client_id_str)?;

        // Validate claims (without signature verification)
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

    /// Converts this RequestObject into an AuthorizationRequest.
    ///
    /// Per the spec, if a parameter appears in both the Request Object and
    /// the query string, the Request Object value takes precedence.
    pub fn into_authorization_request(self) -> Result<AuthorizationRequest> {
        // Use serde to convert claims to AuthorizationRequest
        // This ensures proper deserialization of complex types like dcql_query
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
///
/// This trait abstracts key resolution for testability. Implementations
/// determine how to obtain the verification key based on the client_id scheme.
#[async_trait::async_trait]
pub trait VerifierKeyResolver: Send + Sync {
    /// Resolves the verification key for a verifier.
    ///
    /// # Arguments
    ///
    /// * `client_id` - The parsed client_id identifying the key resolution strategy.
    /// * `header` - The JWT header containing optional key hints (kid, jwk, x5c).
    ///
    /// # Returns
    ///
    /// A `DecodingKey` suitable for JWT signature verification.
    ///
    /// # Errors
    ///
    /// Returns an error if the key cannot be resolved or is invalid.
    async fn resolve_key(
        &self,
        client_id: &ParsedClientId,
        header: &RequestObjectHeader,
    ) -> std::result::Result<DecodingKey, Box<dyn std::error::Error + Send + Sync>>;
}

/// Validates JWT structure (must be compact JWS with 3 parts).
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

/// Decodes the JWT header without verification.
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

/// Parses the JWT header into RequestObjectHeader.
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

/// Decodes the JWT payload without verification.
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

/// Parses the algorithm string into a jsonwebtoken::Algorithm.
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

/// Verifies the JWT signature and decodes the claims.
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

/// Validates the JWT claims.
fn validate_claims(claims: &RequestObjectClaims, wallet_id: &str, client_id: &str) -> Result<()> {
    // Validate aud claim (Section 5.8)
    // aud MUST be the wallet identifier or https://self-issued.me/v2
    let aud_valid = match &claims.rfc7519.aud {
        Some(aud) => {
            // aud can be a string or array, but we serialized it as Option<String>
            aud == wallet_id || aud == SELF_ISSUED_AUDIENCE
        }
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

    // Validate iss claim (Section 5.8)
    // iss MUST match client_id or be absent
    if let Some(ref iss) = claims.rfc7519.iss {
        if iss != client_id {
            return Err(Error::message(
                ErrorKind::InvalidPresentationRequest,
                format!("Request Object iss claim '{iss}' does not match client_id '{client_id}'"),
            ));
        }
    }

    // Validate exp claim
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

    // Validate iat claim (not too far in the past)
    if let Some(iat) = claims.rfc7519.iat {
        let now: i64 = jsonwebtoken::get_current_timestamp() as i64;
        const MAX_AGE_SECONDS: i64 = 60 * 60; // 1 hour
        if iat < now.saturating_sub(MAX_AGE_SECONDS) {
            return Err(Error::message(
                ErrorKind::InvalidPresentationRequest,
                "Request Object 'iat' claim is too old (more than 1 hour)",
            ));
        }
        // Also check that iat is not in the future
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
