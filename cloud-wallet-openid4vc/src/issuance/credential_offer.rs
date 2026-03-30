//! Credential Offer data models for OpenID4VCI.
//!
//! This module implements the data models as defined in
//! [OpenID4VCI Section 4.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer).

use std::collections::HashMap;

use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::errors::{Error, ErrorKind};

/// Maximum allowed length for transaction code description.
const MAX_DESCRIPTION_LENGTH: usize = 300;

/// Input mode for transaction code.
///
/// Specifies the character set expected for the transaction code input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum InputMode {
    /// Only digits are accepted (default).
    #[default]
    Numeric,
    /// Any characters are accepted.
    Text,
}

/// Transaction code requirements.
///
/// Describes the requirements for a Transaction Code that the Authorization Server
/// expects the End-User to present along with the Token Request in a Pre-Authorized Code Flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct TxCode {
    /// String specifying the input character set.
    ///
    /// Possible values are `numeric` (only digits) and `text` (any characters).
    /// The default is `numeric`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_mode: Option<InputMode>,

    /// Integer specifying the length of the Transaction Code.
    ///
    /// This helps the Wallet to render the input screen and improve the user experience.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<u32>,

    /// String containing guidance for the Holder of the Wallet on how to obtain the Transaction Code.
    ///
    /// The length of the string MUST NOT exceed 300 characters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl TxCode {
    /// Validates the transaction code requirements.
    ///
    /// # Errors
    ///
    /// Returns an error if the description exceeds 300 characters.
    pub fn validate(&self) -> Result<(), Error> {
        if let Some(ref desc) = self.description
            && desc.len() > MAX_DESCRIPTION_LENGTH
        {
            return Err(Error::message(
                ErrorKind::InvalidCredentialOffer,
                format!("tx_code description must not exceed {MAX_DESCRIPTION_LENGTH} characters"),
            ));
        }
        Ok(())
    }
}

/// Authorization Code Grant parameters.
///
/// Parameters for the authorization code grant type as defined in
/// [OpenID4VCI Section 4.1.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer-parameters).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct AuthorizationCodeGrant {
    /// String value created by the Credential Issuer and opaque to the Wallet.
    ///
    /// Used to bind the subsequent Authorization Request with a context set up
    /// during previous process steps.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_state: Option<String>,

    /// String identifying the Authorization Server to use.
    ///
    /// Used when the `authorization_servers` parameter in the Credential Issuer metadata
    /// has multiple entries. The value MUST match one of the values in the
    /// `authorization_servers` array.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_server: Option<String>,
}

/// Pre-Authorized Code Grant parameters.
///
/// Parameters for the pre-authorized code grant type as defined in
/// [OpenID4VCI Section 4.1.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer-parameters).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreAuthorizedCodeGrant {
    /// The code representing the Credential Issuer's authorization for the Wallet
    /// to obtain Credentials of a certain type.
    ///
    /// This code MUST be short lived and single use.
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,

    /// Transaction code requirements.
    ///
    /// Indicates that a Transaction Code is required if present, even if empty.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_code: Option<TxCode>,

    /// String identifying the Authorization Server to use.
    ///
    /// Used when the `authorization_servers` parameter in the Credential Issuer metadata
    /// has multiple entries. The value MUST match one of the values in the
    /// `authorization_servers` array.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_server: Option<String>,
}

impl PreAuthorizedCodeGrant {
    /// Validates the pre-authorized code grant parameters.
    ///
    /// # Errors
    ///
    /// Returns an error if the tx_code description exceeds 300 characters.
    pub fn validate(&self) -> Result<(), Error> {
        if let Some(ref tx_code) = self.tx_code {
            tx_code.validate()?;
        }
        Ok(())
    }
}

/// Grant types supported in a Credential Offer.
///
/// Object indicating to the Wallet the Grant Types the Credential Issuer's
/// Authorization Server is prepared to process for this Credential Offer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Grants {
    /// Authorization code grant parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_code: Option<AuthorizationCodeGrant>,

    /// Pre-authorized code grant parameters.
    ///
    /// The key is the full grant type URN: `urn:ietf:params:oauth:grant-type:pre-authorized_code`.
    #[serde(
        rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        skip_serializing_if = "Option::is_none"
    )]
    pub pre_authorized_code: Option<PreAuthorizedCodeGrant>,
}

impl Grants {
    /// Validates all grant parameters.
    ///
    /// Per OpenID4VCI Section 4.1.1, an empty grants object is valid - the wallet
    /// must determine supported grant types from issuer metadata in that case.
    ///
    /// # Errors
    ///
    /// Returns an error if any grant has invalid parameters.
    pub fn validate(&self) -> Result<(), Error> {
        if let Some(ref grant) = self.pre_authorized_code {
            grant.validate()?;
        }
        Ok(())
    }
}

/// Credential Offer object.
///
/// A JSON-encoded object containing information about which credentials can be issued
/// and which authorization mechanisms should be used, as defined in
/// [OpenID4VCI Section 4.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CredentialOffer {
    /// The URL of the Credential Issuer from which the Wallet is requested to obtain credentials.
    ///
    /// The Wallet uses it to obtain the Credential Issuer's Metadata.
    pub credential_issuer: String,

    /// A non-empty array of unique strings identifying credential configurations.
    ///
    /// Each string identifies one of the keys in the name/value pairs stored in the
    /// `credential_configurations_supported` Credential Issuer metadata.
    pub credential_configuration_ids: Vec<String>,

    /// Object indicating the Grant Types the Credential Issuer's Authorization Server
    /// is prepared to process for this Credential Offer.
    ///
    /// If not present or empty, the Wallet MUST determine the Grant Types using
    /// the respective metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grants: Option<Grants>,
}

impl CredentialOffer {
    /// Validates the credential offer.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `credential_issuer` is not a valid HTTPS URL
    /// - `credential_configuration_ids` is empty or contains duplicates
    /// - Any grant has invalid parameters (e.g., tx_code description too long)
    ///
    /// Per OpenID4VCI Section 4.1.1:
    /// - If `grants` is absent or empty, the wallet must determine grant types from issuer metadata
    /// - When multiple grants are present, it's at the wallet's discretion which one to use
    pub fn validate(&self) -> Result<(), Error> {
        let parsed = Url::parse(&self.credential_issuer).map_err(|_| {
            Error::message(
                ErrorKind::InvalidCredentialOffer,
                format!(
                    "credential_issuer '{}' is not a valid URL",
                    self.credential_issuer
                ),
            )
        })?;

        if parsed.scheme() != "https" {
            return Err(Error::message(
                ErrorKind::InvalidCredentialOffer,
                "credential_issuer must use the https scheme",
            ));
        }

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
            .collect::<std::collections::HashSet<_>>()
            .len();

        if unique_count != self.credential_configuration_ids.len() {
            return Err(Error::message(
                ErrorKind::InvalidCredentialOffer,
                "credential_configuration_ids must contain unique values",
            ));
        }

        if let Some(ref grants) = self.grants {
            grants.validate()?;
        }

        Ok(())
    }

    /// Parses a credential offer from a URL query parameter value.
    ///
    /// The `credential_offer` parameter contains a URL-encoded JSON object.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - URL decoding or JSON parsing fails
    /// - The parsed offer fails validation (e.g., non-HTTPS issuer, empty configuration IDs)
    pub fn from_query_param(encoded: &str) -> Result<Self, Error> {
        let decoded = urlencoding_decode(encoded);
        let offer: Self = serde_json::from_str(&decoded).map_err(|e| {
            Error::message(
                ErrorKind::MalformedCredentialOffer,
                format!("invalid JSON: {e}"),
            )
        })?;
        offer.validate()?;
        Ok(offer)
    }
}

/// URL percent-decoding using `percent_encoding` crate.
///
/// Properly handles UTF-8 encoded bytes (e.g., `%C3%A9` for `é`).
fn urlencoding_decode(s: &str) -> String {
    percent_decode_str(s).decode_utf8_lossy().into_owned()
}

/// Source of a credential offer.
///
/// Credential offers can be passed by value or by reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialOfferSource {
    /// Credential offer passed by value (embedded JSON).
    ByValue(CredentialOffer),
    /// Credential offer passed by reference (URL to fetch).
    ByReference(String),
}

/// Parsed credential offer URI parameters.
///
/// Represents the parameters extracted from a credential offer URI
/// (e.g., `openid-credential-offer://?credential_offer=...`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialOfferUri {
    /// The credential offer source (by value or by reference).
    pub source: CredentialOfferSource,
}

impl CredentialOfferUri {
    /// Parses a credential offer from a full offer link URI.
    ///
    /// Accepts either:
    /// - A full URI like `openid-credential-offer://?credential_offer=...`
    /// - A query string like `credential_offer=...` (will prepend the scheme)
    ///
    /// # Mutual Exclusivity
    ///
    /// Per the OpenID4VCI specification, `credential_offer` and `credential_offer_uri`
    /// are mutually exclusive. If both are present, an error is returned.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Both `credential_offer` and `credential_offer_uri` are present
    /// - Neither parameter is present
    /// - The URI is malformed
    /// - Parsing or validation of the credential offer fails (for by-value)
    pub fn from_offer_link(link: &str) -> Result<Self, Error> {
        // Prepend scheme if not already present
        let uri = if link.contains("://") {
            link.to_string()
        } else {
            format!("openid-credential-offer://?{link}")
        };

        let parsed_url = Url::parse(&uri).map_err(|e| {
            Error::message(
                ErrorKind::MalformedCredentialOffer,
                format!("invalid offer link: {e}"),
            )
        })?;

        let params: HashMap<String, String> = parsed_url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();

        let has_by_value = params.contains_key("credential_offer");
        let has_by_reference = params.contains_key("credential_offer_uri");

        // Mutual exclusivity check
        if has_by_value && has_by_reference {
            return Err(Error::message(
                ErrorKind::MalformedCredentialOffer,
                "credential_offer and credential_offer_uri are mutually exclusive",
            ));
        }

        if let Some(encoded) = params.get("credential_offer") {
            let offer = CredentialOffer::from_query_param(encoded)?;
            return Ok(Self {
                source: CredentialOfferSource::ByValue(offer),
            });
        }

        if let Some(uri) = params.get("credential_offer_uri") {
            return Ok(Self {
                source: CredentialOfferSource::ByReference(uri.clone()),
            });
        }

        Err(Error::message(
            ErrorKind::MalformedCredentialOffer,
            "missing credential_offer or credential_offer_uri parameter",
        ))
    }

    /// Parses credential offer URI parameters from a query string.
    ///
    /// Supports both `credential_offer` (by value) and `credential_offer_uri` (by reference).
    ///
    /// # Mutual Exclusivity
    ///
    /// Per the OpenID4VCI specification, `credential_offer` and `credential_offer_uri`
    /// are mutually exclusive. If both are present, an error is returned.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Both `credential_offer` and `credential_offer_uri` are present
    /// - Neither parameter is present
    /// - Parsing the credential offer fails (for by-value)
    pub fn from_query(query: &str) -> Result<Self, Error> {
        // Strip leading '?' if present (common when parsing raw query strings)
        let query = query.strip_prefix('?').unwrap_or(query);

        let params: HashMap<String, String> = url::form_urlencoded::parse(query.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();

        let has_by_value = params.contains_key("credential_offer");
        let has_by_reference = params.contains_key("credential_offer_uri");

        // Mutual exclusivity check
        if has_by_value && has_by_reference {
            return Err(Error::message(
                ErrorKind::MalformedCredentialOffer,
                "credential_offer and credential_offer_uri are mutually exclusive",
            ));
        }

        if let Some(encoded) = params.get("credential_offer") {
            let offer = CredentialOffer::from_query_param(encoded)?;
            return Ok(Self {
                source: CredentialOfferSource::ByValue(offer),
            });
        }

        if let Some(uri) = params.get("credential_offer_uri") {
            return Ok(Self {
                source: CredentialOfferSource::ByReference(uri.clone()),
            });
        }

        Err(Error::message(
            ErrorKind::MalformedCredentialOffer,
            "missing credential_offer or credential_offer_uri parameter",
        ))
    }
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
/// ## SSRF Hardening (Caller Responsibilities)
///
/// The passed `http_client` is responsible for SSRF protections. Callers should configure:
/// - **Redirect policy**: Restrict or disable redirects to prevent redirection attacks.
///   Consider using [`reqwest::redirect::Policy::none()`] or a custom policy that
///   validates redirect targets.
/// - **Localhost/private IP filtering**: Consider rejecting requests to localhost,
///   loopback addresses (127.0.0.0/8, ::1), link-local (169.254.0.0/16), and private
///   IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) unless explicitly allowed.
/// - **Timeouts**: Ensure the client has reasonable connect and request timeouts
///   to prevent hanging on unresponsive servers.
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
/// - Invalid JSON in response body
///
/// Returns [`Error`] with [`ErrorKind::InvalidCredentialOffer`] for:
/// - JWT with `"alg": "none"` (security violation)
/// - Validation failures
pub async fn resolve_by_reference(
    uri: &str,
    http_client: &reqwest::Client,
) -> Result<CredentialOffer, Error> {
    // Validate URI scheme
    let parsed =
        Url::parse(uri).map_err(|e| Error::new(ErrorKind::InvalidCredentialOfferUri, e))?;

    if parsed.scheme() != "https" {
        return Err(Error::message(
            ErrorKind::InvalidCredentialOfferUri,
            format!(
                "credential_offer_uri must use https scheme, got '{}'",
                parsed.scheme()
            ),
        ));
    }

    // Fetch the offer
    // Note: Redirect policy is configured at the Client level, not per-request.
    // We re-validate the final URL after the request to detect redirect attacks.
    let response = http_client
        .get(uri)
        .send()
        .await
        .map_err(|e| Error::new(ErrorKind::CredentialOfferFetchFailed, e))?;

    // Re-validate the final URL to detect redirect attacks.
    // If the caller passed a redirect-following client, a 30x could bounce
    // this request to a different host. We check that the final URL still
    // uses HTTPS and matches the originally validated host.
    let final_url = response.url().clone();
    if final_url.scheme() != "https" {
        return Err(Error::message(
            ErrorKind::InvalidCredentialOfferUri,
            format!(
                "redirect changed scheme from https to '{}'",
                final_url.scheme()
            ),
        ));
    }
    if final_url.host() != parsed.host() {
        return Err(Error::message(
            ErrorKind::InvalidCredentialOfferUri,
            format!(
                "redirect changed host from '{}' to '{}'",
                parsed.host().map(|h| h.to_string()).unwrap_or_default(),
                final_url.host().map(|h| h.to_string()).unwrap_or_default()
            ),
        ));
    }

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

    // Get response body with size limit to prevent unbounded memory allocation.
    // Credential offers are typically small JSON objects; a 64KB limit is generous
    // while protecting against malicious endpoints returning arbitrarily large payloads.
    const MAX_CREDENTIAL_OFFER_SIZE: u64 = 64 * 1024; // 64 KB

    // Check Content-Length header before reading body
    if let Some(content_length) = response.content_length()
        && content_length > MAX_CREDENTIAL_OFFER_SIZE
    {
        return Err(Error::message(
            ErrorKind::CredentialOfferFetchFailed,
            format!(
                "credential offer body size {} bytes exceeds maximum allowed {} bytes",
                content_length, MAX_CREDENTIAL_OFFER_SIZE
            ),
        ));
    }

    // Get body as bytes and verify actual size (in case Content-Length was absent/wrong)
    let bytes = response
        .bytes()
        .await
        .map_err(|e| Error::new(ErrorKind::CredentialOfferFetchFailed, e))?;

    if bytes.len() > MAX_CREDENTIAL_OFFER_SIZE as usize {
        return Err(Error::message(
            ErrorKind::CredentialOfferFetchFailed,
            format!(
                "credential offer body size {} bytes exceeds maximum allowed {} bytes",
                bytes.len(),
                MAX_CREDENTIAL_OFFER_SIZE
            ),
        ));
    }

    // Convert bytes to text
    let body = String::from_utf8_lossy(&bytes).into_owned();

    // Security check: reject JWT with "alg": "none"
    if looks_like_jwt_with_none(&body) {
        return Err(Error::message(
            ErrorKind::InvalidCredentialOffer,
            "credential offer must not be a signed JWT with 'alg': 'none'",
        ));
    }

    // Parse JSON
    let offer: CredentialOffer = serde_json::from_str(&body).map_err(|e| {
        Error::message(
            ErrorKind::MalformedCredentialOffer,
            format!("invalid JSON: {e}"),
        )
    })?;

    // Validate
    offer.validate()?;

    Ok(offer)
}

/// Checks if the content looks like a JWT with "alg": "none".
///
/// This is a security check per the specification to reject insecure JWTs.
/// Uses proper JSON parsing to robustly detect the algorithm regardless of
/// JSON formatting (whitespace, key ordering, etc.).
fn looks_like_jwt_with_none(content: &str) -> bool {
    let trimmed = content.trim();

    // JWTs have three base64url-encoded parts separated by dots
    let parts: Vec<&str> = trimmed.split('.').collect();
    if parts.len() != 3 {
        return false;
    }

    // Try to decode and parse the header (first part) as JSON
    if let Ok(header_bytes) = base64url_decode_no_padding(parts[0])
        && let Ok(header_str) = String::from_utf8(header_bytes)
        && let Ok(header_json) = serde_json::from_str::<serde_json::Value>(&header_str)
    {
        // Check if "alg" field exists and equals "none" (case-insensitive)
        if let Some(alg) = header_json.get("alg").and_then(|v| v.as_str())
            && alg.to_lowercase() == "none"
        {
            return true;
        }
    }

    false
}

/// Decodes base64url without padding.
fn base64url_decode_no_padding(input: &str) -> Result<Vec<u8>, ()> {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    URL_SAFE_NO_PAD.decode(input).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_valid_credential_offer_with_pre_authorized_code() {
        let json = r#"{
            "credential_issuer": "https://credential-issuer.example.com",
            "credential_configuration_ids": ["UniversityDegreeCredential", "org.iso.18013.5.1.mDL"],
            "grants": {
                "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                    "pre-authorized_code": "oaKazRN8I0IbtZ0C7JuMn5",
                    "tx_code": {
                        "length": 4,
                        "input_mode": "numeric",
                        "description": "Please provide the one-time code that was sent via e-mail"
                    }
                }
            }
        }"#;

        let offer: CredentialOffer = serde_json::from_str(json).expect("Failed to deserialize");

        assert_eq!(
            offer.credential_issuer,
            "https://credential-issuer.example.com"
        );
        assert_eq!(offer.credential_configuration_ids.len(), 2);
        assert!(offer.grants.is_some());

        let grants = offer.grants.unwrap();
        assert!(grants.authorization_code.is_none());
        assert!(grants.pre_authorized_code.is_some());

        let pre_auth = grants.pre_authorized_code.unwrap();
        assert_eq!(pre_auth.pre_authorized_code, "oaKazRN8I0IbtZ0C7JuMn5");
        assert!(pre_auth.tx_code.is_some());

        let tx_code = pre_auth.tx_code.unwrap();
        assert_eq!(tx_code.length, Some(4));
        assert_eq!(tx_code.input_mode, Some(InputMode::Numeric));
        assert_eq!(
            tx_code.description,
            Some("Please provide the one-time code that was sent via e-mail".to_string())
        );
    }

    #[test]
    fn deserialize_valid_credential_offer_with_authorization_code() {
        let json = r#"{
            "credential_issuer": "https://credential-issuer.example.com",
            "credential_configuration_ids": ["UniversityDegreeCredential"],
            "grants": {
                "authorization_code": {
                    "issuer_state": "eyJhbGciOiJSU0Et...FYUaBy"
                }
            }
        }"#;

        let offer: CredentialOffer = serde_json::from_str(json).expect("Failed to deserialize");

        let grants = offer.grants.unwrap();
        assert!(grants.authorization_code.is_some());
        assert!(grants.pre_authorized_code.is_none());

        let auth_code = grants.authorization_code.unwrap();
        assert_eq!(
            auth_code.issuer_state,
            Some("eyJhbGciOiJSU0Et...FYUaBy".to_string())
        );
        assert!(auth_code.authorization_server.is_none());
    }

    #[test]
    fn deserialize_minimal_credential_offer() {
        let json = r#"{
            "credential_issuer": "https://issuer.example.com",
            "credential_configuration_ids": ["MyCredential"]
        }"#;

        let offer: CredentialOffer = serde_json::from_str(json).expect("Failed to deserialize");

        assert_eq!(offer.credential_issuer, "https://issuer.example.com");
        assert_eq!(offer.credential_configuration_ids, vec!["MyCredential"]);
        assert!(offer.grants.is_none());
    }

    #[test]
    fn serialize_credential_offer() {
        let offer = CredentialOffer {
            credential_issuer: "https://issuer.example.com".to_string(),
            credential_configuration_ids: vec!["MyCredential".to_string()],
            grants: None,
        };

        let json = serde_json::to_string(&offer).expect("Failed to serialize");

        // Parse and compare as JSON for canonical comparison
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("Failed to parse serialized JSON");
        let expected = serde_json::json!({
            "credential_issuer": "https://issuer.example.com",
            "credential_configuration_ids": ["MyCredential"]
        });
        assert_eq!(
            parsed, expected,
            "Serialized JSON should match expected structure"
        );
    }

    #[test]
    fn validate_empty_configuration_ids() {
        let offer = CredentialOffer {
            credential_issuer: "https://issuer.example.com".to_string(),
            credential_configuration_ids: vec![],
            grants: None,
        };

        let result = offer.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidCredentialOffer);
        assert!(
            err.to_string().contains("must not be empty"),
            "Error message should mention empty configuration ids"
        );
    }

    #[test]
    fn validate_empty_credential_issuer() {
        let offer = CredentialOffer {
            credential_issuer: String::new(),
            credential_configuration_ids: vec!["MyCredential".to_string()],
            grants: None,
        };

        let result = offer.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidCredentialOffer);
        assert!(
            err.to_string().contains("not a valid URL"),
            "Error message should mention invalid URL"
        );
    }

    #[test]
    fn validate_tx_code_description_too_long() {
        let long_desc = "x".repeat(301);
        let offer = CredentialOffer {
            credential_issuer: "https://issuer.example.com".to_string(),
            credential_configuration_ids: vec!["MyCredential".to_string()],
            grants: Some(Grants {
                authorization_code: None,
                pre_authorized_code: Some(PreAuthorizedCodeGrant {
                    pre_authorized_code: "code123".to_string(),
                    tx_code: Some(TxCode {
                        input_mode: None,
                        length: None,
                        description: Some(long_desc),
                    }),
                    authorization_server: None,
                }),
            }),
        };

        let result = offer.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidCredentialOffer);
        assert!(
            err.to_string().contains("300 characters"),
            "Error message should mention the 300 character limit"
        );
    }

    #[test]
    fn validate_valid_offer() {
        let offer = CredentialOffer {
            credential_issuer: "https://issuer.example.com".to_string(),
            credential_configuration_ids: vec!["MyCredential".to_string()],
            grants: Some(Grants {
                authorization_code: Some(AuthorizationCodeGrant {
                    issuer_state: Some("state123".to_string()),
                    authorization_server: None,
                }),
                pre_authorized_code: None,
            }),
        };

        assert!(offer.validate().is_ok());
    }

    #[test]
    fn parse_from_query_param() {
        let encoded = "%7B%22credential_issuer%22%3A%22https%3A%2F%2Fissuer.example.com%22%2C%22credential_configuration_ids%22%3A%5B%22MyCredential%22%5D%7D";

        let offer = CredentialOffer::from_query_param(encoded).expect("Failed to parse");

        assert_eq!(offer.credential_issuer, "https://issuer.example.com");
        assert_eq!(offer.credential_configuration_ids, vec!["MyCredential"]);
    }

    #[test]
    fn from_query_param_validates_offer() {
        // HTTP issuer should be rejected by validation in from_query_param
        let encoded = "%7B%22credential_issuer%22%3A%22http%3A%2F%2Fissuer.example.com%22%2C%22credential_configuration_ids%22%3A%5B%22MyCredential%22%5D%7D";

        let result = CredentialOffer::from_query_param(encoded);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidCredentialOffer);
        assert!(err.to_string().contains("https scheme"));
    }

    #[test]
    fn parse_credential_offer_uri_by_value() {
        // Test with query string only (scheme prepended automatically)
        let query_part = "credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fissuer.example.com%22%2C%22credential_configuration_ids%22%3A%5B%22MyCredential%22%5D%7D";

        let uri = CredentialOfferUri::from_query(query_part).expect("Failed to parse");

        match uri.source {
            CredentialOfferSource::ByValue(offer) => {
                assert_eq!(offer.credential_issuer, "https://issuer.example.com");
            }
            CredentialOfferSource::ByReference(_) => panic!("Expected by value"),
        }
    }

    #[test]
    fn parse_full_offer_link_uri() {
        // Test with full openid-credential-offer:// URI as typically received
        let full_uri = "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fissuer.example.com%22%2C%22credential_configuration_ids%22%3A%5B%22MyCredential%22%5D%7D";

        let uri = CredentialOfferUri::from_offer_link(full_uri).expect("Failed to parse");

        match uri.source {
            CredentialOfferSource::ByValue(offer) => {
                assert_eq!(offer.credential_issuer, "https://issuer.example.com");
                assert_eq!(offer.credential_configuration_ids, vec!["MyCredential"]);
            }
            CredentialOfferSource::ByReference(_) => panic!("Expected by value"),
        }
    }

    #[test]
    fn parse_credential_offer_uri_by_reference() {
        let query =
            "credential_offer_uri=https%3A%2F%2Fserver.example.com%2Fcredential-offer%2F123";

        let uri = CredentialOfferUri::from_query(query).expect("Failed to parse");

        match uri.source {
            CredentialOfferSource::ByReference(url) => {
                assert_eq!(url, "https://server.example.com/credential-offer/123");
            }
            CredentialOfferSource::ByValue(_) => panic!("Expected by reference"),
        }
    }

    #[test]
    fn parse_credential_offer_uri_rejects_both_parameters() {
        // Both credential_offer and credential_offer_uri present - must be rejected
        let query = "credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fissuer.example.com%22%2C%22credential_configuration_ids%22%3A%5B%22MyCredential%22%5D%7D&credential_offer_uri=https%3A%2F%2Fserver.example.com%2Foffer";

        let result = CredentialOfferUri::from_query(query);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::MalformedCredentialOffer);
        assert!(err.to_string().contains("mutually exclusive"));
    }

    #[test]
    fn from_offer_link_rejects_both_parameters() {
        // Both credential_offer and credential_offer_uri in full URI - must be rejected
        let full_uri = "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fissuer.example.com%22%2C%22credential_configuration_ids%22%3A%5B%22MyCredential%22%5D%7D&credential_offer_uri=https%3A%2F%2Fserver.example.com%2Foffer";

        let result = CredentialOfferUri::from_offer_link(full_uri);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::MalformedCredentialOffer);
        assert!(err.to_string().contains("mutually exclusive"));
    }

    #[test]
    fn parse_credential_offer_uri_missing_parameter() {
        let query = "some_other_param=value";

        let result = CredentialOfferUri::from_query(query);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::MalformedCredentialOffer);
        assert!(err.to_string().contains("missing"));
    }

    #[test]
    fn input_mode_serialization() {
        assert_eq!(
            serde_json::to_string(&InputMode::Numeric).unwrap(),
            "\"numeric\""
        );
        assert_eq!(serde_json::to_string(&InputMode::Text).unwrap(), "\"text\"");
    }

    #[test]
    fn input_mode_deserialization() {
        let mode: InputMode = serde_json::from_str("\"numeric\"").unwrap();
        assert_eq!(mode, InputMode::Numeric);

        let mode: InputMode = serde_json::from_str("\"text\"").unwrap();
        assert_eq!(mode, InputMode::Text);
    }

    #[test]
    fn serialize_pre_authorized_code_with_hyphen() {
        let grant = PreAuthorizedCodeGrant {
            pre_authorized_code: "test-code".to_string(),
            tx_code: None,
            authorization_server: None,
        };

        let json = serde_json::to_string(&grant).expect("Failed to serialize");

        // Must serialize with hyphen, not underscore
        assert!(json.contains("\"pre-authorized_code\":\"test-code\""));
        assert!(!json.contains("pre_authorized_code"));
    }

    #[test]
    fn validate_http_url_rejected() {
        let offer = CredentialOffer {
            credential_issuer: "http://issuer.example.com".to_string(), // http, not https
            credential_configuration_ids: vec!["MyCredential".to_string()],
            grants: None,
        };

        let result = offer.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidCredentialOffer);
        assert!(err.to_string().contains("https scheme"));
    }

    #[test]
    fn validate_invalid_url_rejected() {
        let offer = CredentialOffer {
            credential_issuer: "not-a-valid-url".to_string(),
            credential_configuration_ids: vec!["MyCredential".to_string()],
            grants: None,
        };

        let result = offer.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidCredentialOffer);
        assert!(err.to_string().contains("not a valid URL"));
    }

    #[test]
    fn url_decode_utf8() {
        // Test UTF-8 decoding: %C3%A9 = é (UTF-8 encoded as 0xC3 0xA9)
        let encoded = "%C3%A9";
        let decoded = urlencoding_decode(encoded);
        assert_eq!(decoded, "é");

        // Test in context of credential offer URL
        let description = "Code%20for%20%C3%A9%C3%A8%C3%AA"; // "Code for éèê"
        let decoded = urlencoding_decode(description);
        assert_eq!(decoded, "Code for éèê");
    }

    #[test]
    fn empty_tx_code_allowed() {
        let json = r#"{
            "credential_issuer": "https://issuer.example.com",
            "credential_configuration_ids": ["MyCredential"],
            "grants": {
                "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                    "pre-authorized_code": "code123",
                    "tx_code": {}
                }
            }
        }"#;

        let offer: CredentialOffer = serde_json::from_str(json).expect("Failed to deserialize");
        assert!(offer.validate().is_ok());
    }

    #[test]
    fn validate_duplicate_configuration_ids_rejected() {
        let offer = CredentialOffer {
            credential_issuer: "https://issuer.example.com".to_string(),
            credential_configuration_ids: vec![
                "MyCredential".to_string(),
                "MyCredential".to_string(),
            ],
            grants: None,
        };

        let result = offer.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidCredentialOffer);
        assert!(err.to_string().contains("unique"));
    }

    #[test]
    fn validate_empty_grants_allowed() {
        // Per OpenID4VCI Section 4.1.1, empty grants object is valid -
        // wallet must determine grant types from issuer metadata
        let offer = CredentialOffer {
            credential_issuer: "https://issuer.example.com".to_string(),
            credential_configuration_ids: vec!["MyCredential".to_string()],
            grants: Some(Grants {
                authorization_code: None,
                pre_authorized_code: None,
            }),
        };

        assert!(offer.validate().is_ok());
    }

    #[test]
    fn detects_jwt_with_alg_none() {
        // Header with "alg": "none" encoded in base64url
        let jwt = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature";
        assert!(looks_like_jwt_with_none(jwt));
    }

    #[test]
    fn does_not_detect_normal_jwt() {
        // Header with "alg": "RS256" encoded in base64url
        let jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature";
        assert!(!looks_like_jwt_with_none(jwt));
    }

    #[test]
    fn does_not_detect_non_jwt() {
        let json = r#"{"credential_issuer":"https://issuer.example.com"}"#;
        assert!(!looks_like_jwt_with_none(json));
    }

    #[test]
    fn does_not_detect_valid_credential_offer_json() {
        // Happy path: complete valid credential offer JSON should not be flagged
        let json = r#"{
            "credential_issuer": "https://credential-issuer.example.com",
            "credential_configuration_ids": ["UniversityDegreeCredential"],
            "grants": {
                "authorization_code": {
                    "issuer_state": "test-state"
                }
            }
        }"#;
        assert!(!looks_like_jwt_with_none(json));
    }
}
