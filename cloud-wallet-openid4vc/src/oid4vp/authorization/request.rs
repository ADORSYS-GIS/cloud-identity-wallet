//! OpenID4VP authorization request models.
//!
//! See OpenID4VP Section 5 and Appendix A.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use serde_with::skip_serializing_none;
use url::Url;

use crate::errors::{Error, ErrorKind};
use crate::oid4vp::dcql::query::DcqlQuery;
use crate::oid4vp::metadata::parameters::VerifierMetadata;

fn is_ascii_url_safe_token(value: &str) -> bool {
    !value.is_empty()
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '.' | '_' | '~')
        })
}

fn validate_ascii_url_safe_token(value: &str, field: &str) -> Result<(), Error> {
    if !is_ascii_url_safe_token(value) {
        return Err(Error::message(
            ErrorKind::InvalidPresentationRequest,
            format!("{field} must contain only ASCII URL-safe characters"),
        ));
    }

    Ok(())
}

fn validate_non_empty_string(value: &str, field: &str) -> Result<(), Error> {
    if value.trim().is_empty() {
        return Err(Error::message(
            ErrorKind::InvalidPresentationRequest,
            format!("{field} must not be empty"),
        ));
    }

    Ok(())
}

fn validate_string_list(values: &[String], field: &str) -> Result<(), Error> {
    if values.is_empty() {
        return Err(Error::message(
            ErrorKind::InvalidPresentationRequest,
            format!("{field} must not be empty"),
        ));
    }

    if values.iter().any(|value| value.trim().is_empty()) {
        return Err(Error::message(
            ErrorKind::InvalidPresentationRequest,
            format!("{field} must not contain empty strings"),
        ));
    }

    Ok(())
}

/// OpenID4VP response type values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseType {
    /// Request a VP Token in the authorization response.
    #[serde(rename = "vp_token")]
    VpToken,

    /// Request a VP Token and a SIOP ID Token together.
    #[serde(rename = "vp_token id_token")]
    VpTokenIdToken,

    /// Request the VP Token later at the token endpoint via authorization code flow.
    #[serde(rename = "code")]
    Code,
}

/// OpenID4VP response mode values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseMode {
    /// OAuth fragment response mode.
    #[serde(rename = "fragment")]
    Fragment,

    /// Direct POST response mode.
    #[serde(rename = "direct_post")]
    DirectPost,

    /// Direct POST with JWT-encrypted response.
    #[serde(rename = "direct_post.jwt")]
    DirectPostJwt,

    /// Digital Credentials API plain response mode.
    #[serde(rename = "dc_api")]
    DcApi,

    /// Digital Credentials API JWT-encrypted response mode.
    #[serde(rename = "dc_api.jwt")]
    DcApiJwt,
}

impl ResponseMode {
    fn is_direct_post(&self) -> bool {
        matches!(self, Self::DirectPost | Self::DirectPostJwt)
    }

    fn is_dc_api(&self) -> bool {
        matches!(self, Self::DcApi | Self::DcApiJwt)
    }
}

/// Method used to dereference a `request_uri`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequestUriMethod {
    /// HTTP GET as defined by RFC 9101.
    #[serde(rename = "get")]
    Get,

    /// OpenID4VP request URI POST method.
    #[serde(rename = "post")]
    Post,
}

/// Transaction data object in an authorization request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransactionData {
    /// Type discriminator for the transaction data payload.
    #[serde(rename = "type")]
    pub transaction_type: String,

    /// Referenced credential query identifiers.
    pub credential_ids: Vec<String>,

    /// Type-specific extension fields.
    #[serde(flatten, default)]
    pub extra: Map<String, Value>,
}

impl TransactionData {
    fn validate(&self) -> Result<(), Error> {
        validate_non_empty_string(&self.transaction_type, "transaction_data.type")?;
        validate_string_list(&self.credential_ids, "transaction_data.credential_ids")?;
        Ok(())
    }
}

/// Attested verifier information object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerifierInfo {
    /// Attestation format identifier.
    pub format: String,

    /// Attestation payload.
    pub data: Value,

    /// Optional credential query identifiers this attestation applies to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_ids: Option<Vec<String>>,
}

impl VerifierInfo {
    fn validate(&self) -> Result<(), Error> {
        validate_non_empty_string(&self.format, "verifier_info.format")?;

        if let Some(credential_ids) = &self.credential_ids {
            validate_string_list(credential_ids, "verifier_info.credential_ids")?;
        }

        Ok(())
    }
}

/// OpenID4VP authorization request.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    /// Verifier identifier, potentially with a client identifier prefix.
    pub client_id: String,

    /// Requested response type.
    pub response_type: ResponseType,

    /// Requested response mode.
    pub response_mode: ResponseMode,

    /// Redirect URI for same-device redirect-based flows.
    pub redirect_uri: Option<Url>,

    /// Response URI for direct-post flows.
    pub response_uri: Option<Url>,

    /// Request binding nonce.
    pub nonce: String,

    /// State parameter for CSRF/session binding.
    pub state: Option<String>,

    /// Optional scope alias for a DCQL query.
    pub scope: Option<String>,

    /// Optional inline DCQL query.
    pub dcql_query: Option<DcqlQuery>,

    /// Optional verifier metadata.
    pub client_metadata: Option<VerifierMetadata>,

    /// Optional request URI.
    pub request_uri: Option<Url>,

    /// Optional request URI dereference method.
    pub request_uri_method: Option<RequestUriMethod>,

    /// Optional by-value request object.
    pub request: Option<String>,

    /// Optional transaction data objects.
    pub transaction_data: Option<Vec<TransactionData>>,

    /// Optional verifier attestations.
    pub verifier_info: Option<Vec<VerifierInfo>>,

    /// Expected verifier origins for DC API signed requests.
    pub expected_origins: Option<Vec<String>>,
}

impl AuthorizationRequest {
    /// Returns the client identifier prefix if one is present.
    pub fn client_id_prefix(&self) -> Option<&str> {
        self.client_id.split_once(':').map(|(prefix, _)| prefix)
    }

    /// Validates the authorization request.
    pub fn validate(&self) -> Result<(), Error> {
        validate_non_empty_string(&self.client_id, "client_id")?;
        validate_ascii_url_safe_token(&self.nonce, "nonce")?;

        if let Some(state) = &self.state {
            validate_ascii_url_safe_token(state, "state")?;
        }

        if self.scope.is_some() && self.dcql_query.is_some() {
            return Err(Error::message(
                ErrorKind::InvalidPresentationRequest,
                "scope and dcql_query must not both be present",
            ));
        }

        if self.scope.is_none() && self.dcql_query.is_none() {
            return Err(Error::message(
                ErrorKind::InvalidPresentationRequest,
                "either scope or dcql_query must be present",
            ));
        }

        if let Some(scope) = &self.scope {
            validate_non_empty_string(scope, "scope")?;
        }

        if self.response_mode.is_direct_post() {
            let response_uri = self.response_uri.as_ref().ok_or_else(|| {
                Error::message(
                    ErrorKind::InvalidPresentationRequest,
                    "response_uri is required when response_mode is direct_post or direct_post.jwt",
                )
            })?;

            if response_uri.scheme() != "https" {
                return Err(Error::message(
                    ErrorKind::InvalidPresentationRequest,
                    "response_uri must use https for direct_post response modes",
                ));
            }

            if self.redirect_uri.is_some() {
                return Err(Error::message(
                    ErrorKind::InvalidPresentationRequest,
                    "redirect_uri must not be present when response_mode is direct_post or direct_post.jwt",
                ));
            }
        } else if self.response_uri.is_some() {
            return Err(Error::message(
                ErrorKind::InvalidPresentationRequest,
                "response_uri is only valid with direct_post response modes",
            ));
        }

        if let Some(request_uri) = &self.request_uri {
            if request_uri.scheme() != "https" {
                return Err(Error::message(
                    ErrorKind::InvalidPresentationRequest,
                    "request_uri must use https",
                ));
            }
        }

        if self.request_uri_method.is_some() && self.request_uri.is_none() {
            return Err(Error::message(
                ErrorKind::InvalidPresentationRequest,
                "request_uri_method must not be present without request_uri",
            ));
        }

        if let Some(query) = &self.dcql_query {
            query.validate()?;
            if query.requests_unbound_presentations()
                && !self.response_mode.is_dc_api()
                && self.state.is_none()
            {
                return Err(Error::message(
                    ErrorKind::InvalidPresentationRequest,
                    "state is required when presentations without holder binding are requested outside DC API flows",
                ));
            }
        }

        if let Some(metadata) = &self.client_metadata {
            metadata.validate()?;
        }

        if let Some(transaction_data) = &self.transaction_data {
            if transaction_data.is_empty() {
                return Err(Error::message(
                    ErrorKind::InvalidPresentationRequest,
                    "transaction_data must not be empty when present",
                ));
            }

            for entry in transaction_data {
                entry.validate()?;
            }
        }

        if let Some(verifier_info) = &self.verifier_info {
            if verifier_info.is_empty() {
                return Err(Error::message(
                    ErrorKind::InvalidPresentationRequest,
                    "verifier_info must not be empty when present",
                ));
            }

            for entry in verifier_info {
                entry.validate()?;
            }
        }

        if let Some(origins) = &self.expected_origins {
            validate_string_list(origins, "expected_origins")?;
        }

        if let Some(request) = &self.request {
            validate_non_empty_string(request, "request")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oid4vp::dcql::query::{ClaimQuery, CredentialQuery};
    use crate::shared::claim_path_pointer::ClaimPathPointer;

    fn valid_request() -> AuthorizationRequest {
        AuthorizationRequest {
            client_id: "redirect_uri:https://verifier.example.com/cb".to_string(),
            response_type: ResponseType::VpToken,
            response_mode: ResponseMode::Fragment,
            redirect_uri: Some(Url::parse("https://verifier.example.com/cb").unwrap()),
            response_uri: None,
            nonce: "n-0S6_WzA2Mj".to_string(),
            state: Some("state-123".to_string()),
            scope: None,
            dcql_query: Some(DcqlQuery {
                credentials: vec![CredentialQuery {
                    id: "pid".to_string(),
                    format: "dc+sd-jwt".to_string(),
                    multiple: None,
                    meta: Map::new(),
                    trusted_authorities: None,
                    require_cryptographic_holder_binding: Some(true),
                    claims: Some(vec![ClaimQuery {
                        id: Some("family_name".to_string()),
                        path: ClaimPathPointer::from_strings(["family_name"]),
                        values: None,
                        intent_to_retain: None,
                    }]),
                    claim_sets: None,
                }],
                credential_sets: None,
            }),
            client_metadata: None,
            request_uri: None,
            request_uri_method: None,
            request: None,
            transaction_data: None,
            verifier_info: None,
            expected_origins: None,
        }
    }

    #[test]
    fn minimal_request_is_valid() {
        valid_request().validate().unwrap();
    }

    #[test]
    fn direct_post_requires_response_uri() {
        let mut request = valid_request();
        request.response_mode = ResponseMode::DirectPost;
        request.redirect_uri = None;

        let err = request.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidPresentationRequest);
    }

    #[test]
    fn scope_and_dcql_cannot_both_be_present() {
        let mut request = valid_request();
        request.scope = Some("example.scope".to_string());

        let err = request.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidPresentationRequest);
    }

    #[test]
    fn unbound_presentations_require_state_outside_dc_api() {
        let mut request = valid_request();
        request.state = None;
        request.dcql_query.as_mut().unwrap().credentials[0].require_cryptographic_holder_binding =
            Some(false);

        let err = request.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidPresentationRequest);
    }
}
