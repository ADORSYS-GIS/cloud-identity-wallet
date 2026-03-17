//! Credential Offer resolution utilities per OpenID4VCI specification.
//!
//! This module provides types and utilities for resolving credential offers
//! received by the wallet. Credential offers may be provided directly in the
//! request (by value) or referenced via a URL (by reference).
//!
//! # Specification Reference
//!
//! See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer>

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::errors::{Error, ErrorKind};

/// Transaction code configuration for pre-authorized code flow.
///
/// Describes the requirements for the transaction code that the user must provide
/// during the pre-authorized code flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TxCode {
    /// Whether the transaction code is required.
    #[serde(default)]
    pub required: bool,

    /// Length of the transaction code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<u8>,

    /// Description of the transaction code input method.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_mode: Option<String>,

    /// Human-readable description of what the code represents.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Grant type for authorization code flow.
///
/// Contains issuer-specific parameters for the OAuth 2.0 authorization code flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AuthorizationCodeGrant {
    /// The issuer's authorization endpoint URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_state: Option<String>,
}

/// Grant type for pre-authorized code flow.
///
/// Contains the pre-authorized code and optional transaction code requirements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PreAuthorizedCodeGrant {
    /// The pre-authorized code to exchange for an access token.
    pub pre_authorized_code: String,

    /// Transaction code requirements, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_code: Option<TxCode>,
}

/// Grant types supported by a credential offer.
///
/// A credential offer may support one or more grant types for obtaining
/// an access token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Grant {
    /// Authorization code grant.
    AuthorizationCode {
        /// Authorization code grant parameters.
        authorization_code: AuthorizationCodeGrant,
    },
    /// Pre-authorized code grant.
    PreAuthorizedCode {
        /// Pre-authorized code grant parameters.
        #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
        pre_authorized_code: PreAuthorizedCodeGrant,
    },
}

/// The grants object in a credential offer.
///
/// Maps grant type identifiers to their respective parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grants {
    /// Authorization code grant parameters, if supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_code: Option<AuthorizationCodeGrant>,

    /// Pre-authorized code grant parameters, if supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    pub pre_authorized_code: Option<PreAuthorizedCodeGrant>,
}

/// A credential offer as defined by OpenID4VCI.
///
/// The credential offer contains information about the credentials being offered
/// and the grant types available for obtaining them.
///
/// # Required Fields
///
/// - `credential_issuer`: MUST be a valid HTTPS URL
/// - `credential_configuration_ids`: MUST be a non-empty array of unique strings
///
/// # Example
///
/// ```json
/// {
///   "credential_issuer": "https://issuer.example.com",
///   "credential_configuration_ids": ["UniversityDegreeCredential"],
///   "grants": {
///     "authorization_code": {}
///   }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialOffer {
    /// The credential issuer's identifier URL.
    ///
    /// REQUIRED. MUST be a valid URL using the `https` scheme.
    pub credential_issuer: String,

    /// IDs of the credential configurations being offered.
    ///
    /// REQUIRED. MUST be a non-empty array of unique strings.
    pub credential_configuration_ids: Vec<String>,

    /// Grant types supported for this offer.
    ///
    /// OPTIONAL. If absent, the wallet must determine supported grants
    /// from the issuer's metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grants: Option<Grants>,
}

impl CredentialOffer {
    /// Validates the credential offer according to OpenID4VCI requirements.
    ///
    /// # Validation Rules
    ///
    /// - `credential_issuer` must be a valid HTTPS URL
    /// - `credential_configuration_ids` must be non-empty
    /// - `credential_configuration_ids` must contain unique values
    /// - If `grants` is present, at least one grant type must be valid
    /// - Pre-authorized code grant requires `pre_authorized_code` field
    ///
    /// # Errors
    ///
    /// Returns [`Error`] with appropriate [`ErrorKind`] for validation failures.
    pub fn validate(&self) -> Result<(), Error> {
        // Validate credential_issuer is a valid HTTPS URL
        self.validate_credential_issuer()?;

        // Validate credential_configuration_ids
        self.validate_credential_configuration_ids()?;

        // Validate grants if present
        self.validate_grants()?;

        Ok(())
    }

    fn validate_credential_issuer(&self) -> Result<(), Error> {
        if self.credential_issuer.trim().is_empty() {
            return Err(Error::message(
                ErrorKind::InvalidCredentialOffer,
                "credential_issuer must not be empty",
            ));
        }

        let parsed = Url::parse(&self.credential_issuer).map_err(|e| {
            Error::new(ErrorKind::InvalidCredentialOffer, e)
        })?;

        if parsed.scheme() != "https" {
            return Err(Error::message(
                ErrorKind::InvalidCredentialOffer,
                format!(
                    "credential_issuer must use https scheme, got '{}'",
                    parsed.scheme()
                ),
            ));
        }

        Ok(())
    }

    fn validate_credential_configuration_ids(&self) -> Result<(), Error> {
        if self.credential_configuration_ids.is_empty() {
            return Err(Error::message(
                ErrorKind::InvalidCredentialOffer,
                "credential_configuration_ids must not be empty",
            ));
        }

        // Check for unique values
        let unique_count = self
            .credential_configuration_ids
            .iter()
            .collect::<HashSet<_>>()
            .len();

        if unique_count != self.credential_configuration_ids.len() {
            return Err(Error::message(
                ErrorKind::InvalidCredentialOffer,
                "credential_configuration_ids must contain unique values",
            ));
        }

        // Check for non-empty strings
        for id in &self.credential_configuration_ids {
            if id.trim().is_empty() {
                return Err(Error::message(
                    ErrorKind::InvalidCredentialOffer,
                    "credential_configuration_ids must not contain empty strings",
                ));
            }
        }

        Ok(())
    }

    fn validate_grants(&self) -> Result<(), Error> {
        let Some(grants) = &self.grants else {
            return Ok(());
        };

        // At least one grant type must be present
        if grants.authorization_code.is_none() && grants.pre_authorized_code.is_none() {
            return Err(Error::message(
                ErrorKind::InvalidCredentialOffer,
                "grants object must contain at least one grant type",
            ));
        }

        // Validate pre-authorized code grant has required field
        if let Some(pre_auth) = &grants.pre_authorized_code {
            if pre_auth.pre_authorized_code.trim().is_empty() {
                return Err(Error::message(
                    ErrorKind::InvalidCredentialOffer,
                    "pre_authorized_code must not be empty",
                ));
            }
        }

        Ok(())
    }
}

/// Resolves a credential offer provided by value.
///
/// When an offer is passed by value, the entire content is embedded directly
/// in the URL query string (e.g., `openid-credential-offer://?credential_offer={JSON}`).
///
/// # Arguments
///
/// * `encoded_offer` - URL-encoded JSON string containing the credential offer.
///
/// # Process
///
/// 1. URL-decode the string to get the raw JSON
/// 2. Parse the JSON into a [`CredentialOffer`]
/// 3. Validate the credential offer
///
/// # Errors
///
/// Returns [`Error`] with [`ErrorKind::MalformedCredentialOffer`] for:
/// - URL decoding failures
/// - JSON parsing failures
///
/// Returns [`Error`] with [`ErrorKind::InvalidCredentialOffer`] for:
/// - Validation failures (see [`CredentialOffer::validate`])
pub fn resolve_by_value(encoded_offer: &str) -> Result<CredentialOffer, Error> {
    // URL decode
    let decoded = urlencoding_decode(encoded_offer)?;

    // Parse JSON
    let offer: CredentialOffer = serde_json::from_str(&decoded).map_err(|e| {
        Error::new(ErrorKind::MalformedCredentialOffer, e)
    })?;

    // Validate
    offer.validate()?;

    Ok(offer)
}

/// Resolves a credential offer provided by reference.
///
/// When an offer is passed by reference, the URL contains a pointer to an
/// external resource that must be fetched.
///
/// # Arguments
///
/// * `uri` - The URI pointing to the credential offer.
/// * `http_client` - HTTP client for fetching the offer.
///
/// # Security Considerations
///
/// Per the specification, the wallet SHOULD require user interaction or
/// establish trust in the issuer before fetching to prevent tracking/fingerprinting.
///
/// The retrieved offer MUST:
/// - Use media type `application/json`
/// - NOT be a signed JWT with `"alg": "none"`
///
/// # Errors
///
/// Returns [`Error`] with [`ErrorKind::InvalidCredentialOfferUri`] for:
/// - Non-HTTPS URIs
///
/// Returns [`Error`] with [`ErrorKind::CredentialOfferFetchFailed`] for:
/// - HTTP request failures
/// - Non-200 responses
///
/// Returns [`Error`] with [`ErrorKind::InvalidCredentialOfferMediaType`] for:
/// - Response with non-`application/json` media type
///
/// Returns [`Error`] with [`ErrorKind::MalformedCredentialOffer`] for:
/// - JSON parsing failures
///
/// Returns [`Error`] with [`ErrorKind::InvalidCredentialOffer`] for:
/// - Validation failures
#[cfg(feature = "http")]
pub async fn resolve_by_reference(
    uri: &str,
    http_client: &reqwest::Client,
) -> Result<CredentialOffer, Error> {
    // Validate URI scheme
    let parsed = Url::parse(uri).map_err(|e| {
        Error::new(ErrorKind::InvalidCredentialOfferUri, e)
    })?;

    if parsed.scheme() != "https" {
        return Err(Error::message(
            ErrorKind::InvalidCredentialOfferUri,
            format!("credential_offer_uri must use https scheme, got '{}'", parsed.scheme()),
        ));
    }

    // Fetch the offer
    let response = http_client
        .get(uri)
        .send()
        .await
        .map_err(|e| Error::new(ErrorKind::CredentialOfferFetchFailed, e))?;

    // Check response status
    if !response.status().is_success() {
        return Err(Error::message(
            ErrorKind::CredentialOfferFetchFailed,
            format!("HTTP request failed with status: {}", response.status()),
        ));
    }

    // Validate content type
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !content_type.starts_with("application/json") {
        return Err(Error::message(
            ErrorKind::InvalidCredentialOfferMediaType,
            format!("expected application/json, got '{}'", content_type),
        ));
    }

    // Get response body
    let body = response.text().await.map_err(|e| {
        Error::new(ErrorKind::CredentialOfferFetchFailed, e)
    })?;

    // Security check: reject JWT with "alg": "none"
    if looks_like_jwt_with_none(&body) {
        return Err(Error::message(
            ErrorKind::InvalidCredentialOffer,
            "credential offer must not be a signed JWT with 'alg': 'none'",
        ));
    }

    // Parse JSON
    let offer: CredentialOffer = serde_json::from_str(&body).map_err(|e| {
        Error::new(ErrorKind::MalformedCredentialOffer, e)
    })?;

    // Validate
    offer.validate()?;

    Ok(offer)
}

/// URL decodes a string without allocating for already-decoded content.
fn urlencoding_decode(encoded: &str) -> Result<String, Error> {
    // Simple URL decode implementation
    let mut result = String::with_capacity(encoded.len());
    let mut chars = encoded.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '%' => {
                let hex: String = chars.by_ref().take(2).collect();
                if hex.len() != 2 {
                    return Err(Error::message(
                        ErrorKind::MalformedCredentialOffer,
                        "invalid URL encoding: incomplete percent-encoding",
                    ));
                }
                let byte = u8::from_str_radix(&hex, 16).map_err(|e| {
                    Error::new(ErrorKind::MalformedCredentialOffer, e)
                })?;
                result.push(byte as char);
            }
            '+' => result.push(' '),
            _ => result.push(c),
        }
    }

    Ok(result)
}

/// Checks if the content looks like a JWT with "alg": "none".
///
/// This is a security check per the specification.
#[cfg(feature = "http")]
fn looks_like_jwt_with_none(content: &str) -> bool {
    let trimmed = content.trim();

    // JWTs have three base64url-encoded parts separated by dots
    let parts: Vec<&str> = trimmed.split('.').collect();
    if parts.len() != 3 {
        return false;
    }

    // Try to decode the header (first part)
    if let Ok(header_bytes) = base64url_decode_no_padding(parts[0]) {
        if let Ok(header_str) = String::from_utf8(header_bytes) {
            // Check for "alg":"none" pattern (case-insensitive)
            let header_lower = header_str.to_lowercase();
            if header_lower.contains(r#""alg":"none""#)
                || header_lower.contains(r#""alg" : "none""#)
            {
                return true;
            }
        }
    }

    false
}

/// Decodes base64url without padding.
#[cfg(feature = "http")]
fn base64url_decode_no_padding(input: &str) -> Result<Vec<u8>, ()> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    URL_SAFE_NO_PAD.decode(input).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_offer() -> CredentialOffer {
        CredentialOffer {
            credential_issuer: "https://issuer.example.com".to_string(),
            credential_configuration_ids: vec!["UniversityDegreeCredential".to_string()],
            grants: None,
        }
    }

    // CredentialOffer validation tests

    #[test]
    fn valid_offer_passes_validation() {
        let offer = valid_offer();
        assert!(offer.validate().is_ok());
    }

    #[test]
    fn rejects_empty_credential_issuer() {
        let offer = CredentialOffer {
            credential_issuer: "".to_string(),
            credential_configuration_ids: vec!["cred".to_string()],
            grants: None,
        };
        let err = offer.validate().expect_err("should reject empty issuer");
        assert_eq!(err.kind(), ErrorKind::InvalidCredentialOffer);
        assert!(err.to_string().contains("credential_issuer"));
    }

    #[test]
    fn rejects_non_https_issuer() {
        let offer = CredentialOffer {
            credential_issuer: "http://issuer.example.com".to_string(),
            credential_configuration_ids: vec!["cred".to_string()],
            grants: None,
        };
        let err = offer.validate().expect_err("should reject non-https issuer");
        assert_eq!(err.kind(), ErrorKind::InvalidCredentialOffer);
        assert!(err.to_string().contains("https"));
    }

    #[test]
    fn rejects_invalid_url_issuer() {
        let offer = CredentialOffer {
            credential_issuer: "not-a-url".to_string(),
            credential_configuration_ids: vec!["cred".to_string()],
            grants: None,
        };
        let err = offer.validate().expect_err("should reject invalid URL");
        assert_eq!(err.kind(), ErrorKind::InvalidCredentialOffer);
    }

    #[test]
    fn rejects_empty_credential_configuration_ids() {
        let offer = CredentialOffer {
            credential_issuer: "https://issuer.example.com".to_string(),
            credential_configuration_ids: vec![],
            grants: None,
        };
        let err = offer.validate().expect_err("should reject empty ids");
        assert_eq!(err.kind(), ErrorKind::InvalidCredentialOffer);
        assert!(err.to_string().contains("credential_configuration_ids"));
    }

    #[test]
    fn rejects_duplicate_credential_configuration_ids() {
        let offer = CredentialOffer {
            credential_issuer: "https://issuer.example.com".to_string(),
            credential_configuration_ids: vec!["cred".to_string(), "cred".to_string()],
            grants: None,
        };
        let err = offer.validate().expect_err("should reject duplicates");
        assert_eq!(err.kind(), ErrorKind::InvalidCredentialOffer);
        assert!(err.to_string().contains("unique"));
    }

    #[test]
    fn accepts_multiple_unique_credential_configuration_ids() {
        let offer = CredentialOffer {
            credential_issuer: "https://issuer.example.com".to_string(),
            credential_configuration_ids: vec!["cred1".to_string(), "cred2".to_string()],
            grants: None,
        };
        assert!(offer.validate().is_ok());
    }

    #[test]
    fn rejects_grants_with_no_grant_types() {
        let offer = CredentialOffer {
            credential_issuer: "https://issuer.example.com".to_string(),
            credential_configuration_ids: vec!["cred".to_string()],
            grants: Some(Grants {
                authorization_code: None,
                pre_authorized_code: None,
            }),
        };
        let err = offer.validate().expect_err("should reject empty grants");
        assert_eq!(err.kind(), ErrorKind::InvalidCredentialOffer);
        assert!(err.to_string().contains("at least one grant type"));
    }

    #[test]
    fn accepts_authorization_code_grant() {
        let offer = CredentialOffer {
            credential_issuer: "https://issuer.example.com".to_string(),
            credential_configuration_ids: vec!["cred".to_string()],
            grants: Some(Grants {
                authorization_code: Some(AuthorizationCodeGrant { issuer_state: None }),
                pre_authorized_code: None,
            }),
        };
        assert!(offer.validate().is_ok());
    }

    #[test]
    fn accepts_pre_authorized_code_grant() {
        let offer = CredentialOffer {
            credential_issuer: "https://issuer.example.com".to_string(),
            credential_configuration_ids: vec!["cred".to_string()],
            grants: Some(Grants {
                authorization_code: None,
                pre_authorized_code: Some(PreAuthorizedCodeGrant {
                    pre_authorized_code: "abc123".to_string(),
                    tx_code: None,
                }),
            }),
        };
        assert!(offer.validate().is_ok());
    }

    #[test]
    fn rejects_pre_authorized_code_with_empty_code() {
        let offer = CredentialOffer {
            credential_issuer: "https://issuer.example.com".to_string(),
            credential_configuration_ids: vec!["cred".to_string()],
            grants: Some(Grants {
                authorization_code: None,
                pre_authorized_code: Some(PreAuthorizedCodeGrant {
                    pre_authorized_code: "".to_string(),
                    tx_code: None,
                }),
            }),
        };
        let err = offer.validate().expect_err("should reject empty pre_authorized_code");
        assert_eq!(err.kind(), ErrorKind::InvalidCredentialOffer);
        assert!(err.to_string().contains("pre_authorized_code"));
    }

    // resolve_by_value tests

    #[test]
    fn resolves_valid_offer_by_value() {
        let json = r#"{"credential_issuer":"https://issuer.example.com","credential_configuration_ids":["cred"]}"#;
        let encoded = urlencoding_encode(json);
        let offer = resolve_by_value(&encoded).expect("should resolve valid offer");
        assert_eq!(offer.credential_issuer, "https://issuer.example.com");
        assert_eq!(offer.credential_configuration_ids, vec!["cred"]);
    }

    #[test]
    fn resolves_offer_with_grants_by_value() {
        let json = r#"{"credential_issuer":"https://issuer.example.com","credential_configuration_ids":["cred"],"grants":{"authorization_code":{}}}"#;
        let encoded = urlencoding_encode(json);
        let offer = resolve_by_value(&encoded).expect("should resolve offer with grants");
        assert!(offer.grants.is_some());
        assert!(offer.grants.unwrap().authorization_code.is_some());
    }

    #[test]
    fn rejects_malformed_json_by_value() {
        let encoded = urlencoding_encode("{not json}");
        let err = resolve_by_value(&encoded).expect_err("should reject malformed JSON");
        assert_eq!(err.kind(), ErrorKind::MalformedCredentialOffer);
    }

    #[test]
    fn rejects_invalid_url_encoding_by_value() {
        let err = resolve_by_value("%ZZ").expect_err("should reject invalid URL encoding");
        assert_eq!(err.kind(), ErrorKind::MalformedCredentialOffer);
    }

    #[test]
    fn rejects_offer_missing_issuer_by_value() {
        let json = r#"{"credential_configuration_ids":["cred"]}"#;
        let encoded = urlencoding_encode(json);
        let err = resolve_by_value(&encoded).expect_err("should reject missing issuer");
        assert_eq!(err.kind(), ErrorKind::MalformedCredentialOffer);
    }

    #[test]
    fn rejects_offer_with_non_https_issuer_by_value() {
        let json = r#"{"credential_issuer":"http://issuer.example.com","credential_configuration_ids":["cred"]}"#;
        let encoded = urlencoding_encode(json);
        let err = resolve_by_value(&encoded).expect_err("should reject non-https issuer");
        assert_eq!(err.kind(), ErrorKind::InvalidCredentialOffer);
    }

    // JSON serialization/deserialization tests

    #[test]
    fn serializes_and_deserializes_credential_offer() {
        let offer = CredentialOffer {
            credential_issuer: "https://issuer.example.com".to_string(),
            credential_configuration_ids: vec!["cred1".to_string(), "cred2".to_string()],
            grants: Some(Grants {
                authorization_code: Some(AuthorizationCodeGrant {
                    issuer_state: Some("state123".to_string()),
                }),
                pre_authorized_code: None,
            }),
        };
        let json = serde_json::to_string(&offer).expect("should serialize");
        let parsed: CredentialOffer = serde_json::from_str(&json).expect("should deserialize");
        assert_eq!(offer, parsed);
    }

    #[test]
    fn deserializes_pre_authorized_code_grant() {
        let json = r#"{
            "credential_issuer": "https://issuer.example.com",
            "credential_configuration_ids": ["cred"],
            "grants": {
                "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                    "pre_authorized_code": "abc123",
                    "tx_code": {
                        "required": true,
                        "length": 6,
                        "description": "Enter the code sent to your email"
                    }
                }
            }
        }"#;
        let offer: CredentialOffer = serde_json::from_str(json).expect("should deserialize");
        let grants = offer.grants.expect("should have grants");
        let pre_auth = grants.pre_authorized_code.expect("should have pre-auth grant");
        assert_eq!(pre_auth.pre_authorized_code, "abc123");
        let tx_code = pre_auth.tx_code.expect("should have tx_code");
        assert!(tx_code.required);
        assert_eq!(tx_code.length, Some(6));
    }

    // JWT security check tests

    #[test]
    #[cfg(feature = "http")]
    fn detects_jwt_with_alg_none() {
        // Header with "alg": "none" encoded in base64url
        let jwt = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature";
        assert!(looks_like_jwt_with_none(jwt));
    }

    #[test]
    #[cfg(feature = "http")]
    fn does_not_detect_normal_jwt() {
        // Header with "alg": "RS256" encoded in base64url
        let jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature";
        assert!(!looks_like_jwt_with_none(jwt));
    }

    #[test]
    #[cfg(feature = "http")]
    fn does_not_detect_non_jwt() {
        let json = r#"{"credential_issuer":"https://issuer.example.com"}"#;
        assert!(!looks_like_jwt_with_none(json));
    }

    // Helper for tests
    fn urlencoding_encode(s: &str) -> String {
        let mut result = String::new();
        for c in s.chars() {
            match c {
                ' ' => result.push('+'),
                'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => result.push(c),
                _ => {
                    result.push('%');
                    for byte in c.to_string().as_bytes() {
                        result.push_str(&format!("{:02X}", byte));
                    }
                }
            }
        }
        result
    }
}
