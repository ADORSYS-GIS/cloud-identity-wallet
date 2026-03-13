//! Data models for OpenID4VCI Credential Offer handling.
//!
//! This module implements the data models as defined in
//! [OpenID4VCI Section 4.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Maximum allowed length for transaction code description.
const MAX_DESCRIPTION_LENGTH: usize = 300;

/// Error type for Credential Offer parsing and validation.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CredentialOfferError {
    /// The `credential_issuer` field is missing.
    #[error("credential_issuer is required")]
    MissingCredentialIssuer,

    /// The `credential_configuration_ids` field is missing.
    #[error("credential_configuration_ids is required")]
    MissingConfigurationIds,

    /// The `credential_configuration_ids` array is empty.
    #[error("credential_configuration_ids must not be empty")]
    EmptyConfigurationIds,

    /// The `pre_authorized_code` field is missing in a pre-authorized grant.
    #[error("pre_authorized_code is required for pre-authorized code grant")]
    MissingPreAuthorizedCode,

    /// The transaction code description exceeds the maximum length.
    #[error("tx_code description must not exceed {MAX_DESCRIPTION_LENGTH} characters")]
    DescriptionTooLong,

    /// Failed to parse JSON.
    #[error("invalid JSON: {0}")]
    InvalidJson(String),

    /// Failed to parse URL.
    #[error("invalid URL: {0}")]
    InvalidUrl(String),
}

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
    pub fn validate(&self) -> Result<(), CredentialOfferError> {
        if let Some(ref desc) = self.description
            && desc.len() > MAX_DESCRIPTION_LENGTH
        {
            return Err(CredentialOfferError::DescriptionTooLong);
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
#[serde(rename_all = "snake_case")]
pub struct PreAuthorizedCodeGrant {
    /// The code representing the Credential Issuer's authorization for the Wallet
    /// to obtain Credentials of a certain type.
    ///
    /// This code MUST be short lived and single use.
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
    pub fn validate(&self) -> Result<(), CredentialOfferError> {
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
    /// # Errors
    ///
    /// Returns an error if any grant has invalid parameters.
    pub fn validate(&self) -> Result<(), CredentialOfferError> {
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
    /// - `credential_issuer` is empty
    /// - `credential_configuration_ids` is empty
    /// - Any grant has invalid parameters
    pub fn validate(&self) -> Result<(), CredentialOfferError> {
        if self.credential_issuer.is_empty() {
            return Err(CredentialOfferError::MissingCredentialIssuer);
        }

        if self.credential_configuration_ids.is_empty() {
            return Err(CredentialOfferError::EmptyConfigurationIds);
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
    /// Returns an error if the URL decoding or JSON parsing fails.
    pub fn from_query_param(encoded: &str) -> Result<Self, CredentialOfferError> {
        let decoded = urlencoding_decode(encoded);
        serde_json::from_str(&decoded).map_err(|e| CredentialOfferError::InvalidJson(e.to_string()))
    }
}

/// Simple URL percent-decoding (to avoid adding a urlencoding dependency).
fn urlencoding_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                result.push(byte as char);
            } else {
                result.push('%');
                result.push_str(&hex);
            }
        } else if c == '+' {
            result.push(' ');
        } else {
            result.push(c);
        }
    }

    result
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
    /// Parses credential offer URI parameters from a query string.
    ///
    /// Supports both `credential_offer` (by value) and `credential_offer_uri` (by reference).
    ///
    /// # Errors
    ///
    /// Returns an error if neither parameter is present or parsing fails.
    pub fn from_query(query: &str) -> Result<Self, CredentialOfferError> {
        let params: HashMap<&str, &str> = query
            .split('&')
            .filter_map(|pair| {
                let mut parts = pair.splitn(2, '=');
                Some((parts.next()?, parts.next().unwrap_or("")))
            })
            .collect();

        if let Some(&encoded) = params.get("credential_offer") {
            let offer = CredentialOffer::from_query_param(encoded)?;
            return Ok(Self {
                source: CredentialOfferSource::ByValue(offer),
            });
        }

        if let Some(&uri) = params.get("credential_offer_uri") {
            let decoded = urlencoding_decode(uri);
            return Ok(Self {
                source: CredentialOfferSource::ByReference(decoded),
            });
        }

        Err(CredentialOfferError::InvalidUrl(
            "missing credential_offer or credential_offer_uri parameter".to_string(),
        ))
    }
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
                    "pre_authorized_code": "oaKazRN8I0IbtZ0C7JuMn5",
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

        assert!(json.contains("\"credential_issuer\":\"https://issuer.example.com\""));
        assert!(json.contains("\"credential_configuration_ids\":[\"MyCredential\"]"));
        assert!(!json.contains("\"grants\"")); // Should be skipped when None
    }

    #[test]
    fn validate_empty_configuration_ids() {
        let offer = CredentialOffer {
            credential_issuer: "https://issuer.example.com".to_string(),
            credential_configuration_ids: vec![],
            grants: None,
        };

        let result = offer.validate();
        assert!(matches!(
            result,
            Err(CredentialOfferError::EmptyConfigurationIds)
        ));
    }

    #[test]
    fn validate_empty_credential_issuer() {
        let offer = CredentialOffer {
            credential_issuer: String::new(),
            credential_configuration_ids: vec!["MyCredential".to_string()],
            grants: None,
        };

        let result = offer.validate();
        assert!(matches!(
            result,
            Err(CredentialOfferError::MissingCredentialIssuer)
        ));
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
        assert!(matches!(
            result,
            Err(CredentialOfferError::DescriptionTooLong)
        ));
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
    fn parse_credential_offer_uri_by_value() {
        let query = "credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fissuer.example.com%22%2C%22credential_configuration_ids%22%3A%5B%22MyCredential%22%5D%7D";

        let uri = CredentialOfferUri::from_query(query).expect("Failed to parse");

        match uri.source {
            CredentialOfferSource::ByValue(offer) => {
                assert_eq!(offer.credential_issuer, "https://issuer.example.com");
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
    fn empty_tx_code_allowed() {
        let json = r#"{
            "credential_issuer": "https://issuer.example.com",
            "credential_configuration_ids": ["MyCredential"],
            "grants": {
                "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                    "pre_authorized_code": "code123",
                    "tx_code": {}
                }
            }
        }"#;

        let offer: CredentialOffer = serde_json::from_str(json).expect("Failed to deserialize");
        assert!(offer.validate().is_ok());
    }
}
