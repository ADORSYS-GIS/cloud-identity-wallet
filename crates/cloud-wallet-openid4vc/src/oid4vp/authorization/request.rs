//! Authorization Request models for OpenID4VP.
//!
//! This module defines the data structures for OAuth 2.0 authorization requests
//! as extended by OpenID4VP (Section 5).
//!
//! # Spec References
//!
//! - [OpenID4VP §5 Authorization Request](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-authorization-request)
//! - [RFC 6749 §4.1.1 Authorization Request](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1)
//! - [RFC 9101 JWT-Secured Authorization Request (JAR)](https://www.rfc-editor.org/rfc/rfc9101.html)

use serde::{Deserialize, Deserializer, Serialize};
use serde_with::skip_serializing_none;
use url::Url;

use crate::errors::{Error, ErrorKind, Result};
use crate::oauth::authorization::OAuthAuthorizationRequest;
use crate::utils::is_unreserved_chars;

use super::super::dcql::DcqlQuery;
use super::super::metadata::verifier::VerifierMetadata;
use super::super::transaction_data::TransactionData;

/// The `response_type` parameter for OpenID4VP Authorization Requests.
///
/// Per [OpenID4VP §5.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-authorization-request),
/// valid values are `vp_token` and `vp_token id_token`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResponseType {
    #[serde(rename = "vp_token")]
    VpToken,

    #[serde(rename = "vp_token id_token")]
    VpTokenIdToken,
}

impl std::fmt::Display for ResponseType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VpToken => write!(f, "vp_token"),
            Self::VpTokenIdToken => write!(f, "vp_token id_token"),
        }
    }
}

/// The `response_mode` parameter for OpenID4VP Authorization Requests.
///
/// Per OpenID4VP §5.6, the default response mode for `vp_token` is `fragment`.
/// This enum includes the OpenID4VP-specific modes (`direct_post`, `direct_post.jwt`)
/// and DC API modes (`dc_api`, `dc_api.jwt`), as well as an extension variant for
/// other OAuth-registered response modes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ResponseMode {
    /// Direct POST response mode (OpenID4VP §5.1).
    DirectPost,

    /// Direct POST with JWT-secured response (OpenID4VP §5.1).
    DirectPostJwt,

    /// W3C Digital Credentials API response mode (Appendix A).
    DcApi,

    /// W3C Digital Credentials API with JWT-secured response (Appendix A).
    DcApiJwt,

    /// Extension response mode for other OAuth-registered values.
    Other(String),
}

impl ResponseMode {
    fn is_direct_post(&self) -> bool {
        matches!(self, Self::DirectPost | Self::DirectPostJwt)
    }
}

impl std::fmt::Display for ResponseMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DirectPost => write!(f, "direct_post"),
            Self::DirectPostJwt => write!(f, "direct_post.jwt"),
            Self::DcApi => write!(f, "dc_api"),
            Self::DcApiJwt => write!(f, "dc_api.jwt"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

impl Serialize for ResponseMode {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ResponseMode {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(match value.as_str() {
            "direct_post" => Self::DirectPost,
            "direct_post.jwt" => Self::DirectPostJwt,
            "dc_api" => Self::DcApi,
            "dc_api.jwt" => Self::DcApiJwt,
            _ => Self::Other(value),
        })
    }
}

/// The `request_uri_method` parameter controlling how the Wallet fetches the
/// Request Object when `request_uri` is present.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum RequestUriMethod {
    #[default]
    #[serde(rename = "get")]
    Get,

    #[serde(rename = "post")]
    Post,
}

impl std::fmt::Display for RequestUriMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Get => write!(f, "get"),
            Self::Post => write!(f, "post"),
        }
    }
}

/// A single Verifier Attestation object within `verifier_info`.
///
/// Section 5.1 defines `verifier_info` as a non-empty array of these objects.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerifierAttestation {
    /// REQUIRED. The attestation format identifier.
    pub format: String,

    /// REQUIRED. The attestation data (format-specific).
    pub data: serde_json::Value,

    /// OPTIONAL. Non-empty array of DCQL credential query IDs this attestation relates to.
    pub credential_ids: Option<Vec<String>>,
}

impl VerifierAttestation {
    fn validate(&self, idx: usize, valid_credential_ids: &[&str]) -> Result<()> {
        if self.format.trim().is_empty() {
            return Err(invalid_request(format!(
                "'verifier_info[{idx}].format' must not be empty"
            )));
        }
        if let Some(ref ids) = self.credential_ids {
            if ids.is_empty() {
                return Err(invalid_request(format!(
                    "'verifier_info[{idx}].credential_ids' must be a non-empty array when present"
                )));
            }
            for id_ref in ids {
                if !valid_credential_ids.contains(&id_ref.as_str()) {
                    return Err(invalid_request(format!(
                        "'verifier_info[{idx}].credential_ids' references unknown credential id '{id_ref}'"
                    )));
                }
            }
        }
        Ok(())
    }
}

fn invalid_request(message: impl Into<String>) -> Error {
    Error::message(ErrorKind::InvalidPresentationRequest, message.into())
}

/// An OpenID4VP Authorization Request.
///
/// Compliant with [OpenID4VP §5](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-authorization-request).
///
/// This struct flattens standard OAuth 2.0 authorization request parameters
/// from [`OAuthAuthorizationRequest`] and adds OpenID4VP-specific extensions.
///
/// # Architecture Note
///
/// The `nonce` field exists both as a top-level required `String` and within
/// `oauth.nonce` as `Option<String>`. This is intentional:
/// - OID4VP requires `nonce` to be present and validated
/// - The base OAuth model stores `nonce` as optional (appropriate for OIDC/OID4VCI)
/// - During deserialization, `nonce` is extracted to the top-level field and
///   `oauth.nonce` is set to `None` to avoid duplication
/// - Validation uses the top-level `nonce` field directly
///
/// # DC API Unsigned Requests (Appendix A.2/A.3.1)
///
/// For unsigned DC API requests, `client_id` MUST be omitted. The validation
/// logic handles this by making `client_id` optional in the raw deserialization
/// structure and validating the presence/absence based on `response_mode` and
/// whether a signed Request Object is present.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AuthorizationRequest {
    /// REQUIRED. The response type: `vp_token` or `vp_token id_token`.
    pub response_type: ResponseType,

    /// REQUIRED. The nonce for replay protection.
    ///
    /// Per OpenID4VP §5.2, this MUST contain only unreserved URI characters.
    pub nonce: String,

    /// REQUIRED. The response mode for the authorization response.
    pub response_mode: ResponseMode,

    /// Standard OAuth 2.0 authorization request parameters.
    ///
    /// Note: For unsigned DC API requests, `client_id` may be empty or absent.
    /// Validation enforces the correct presence based on context.
    #[serde(flatten)]
    pub oauth: OAuthAuthorizationRequest,

    /// OPTIONAL. Response URI for `direct_post` and `direct_post.jwt` modes.
    ///
    /// REQUIRED when `response_mode` is `direct_post` or `direct_post.jwt`.
    pub response_uri: Option<Url>,

    /// OPTIONAL. Request Object URI (JAR).
    pub request_uri: Option<Url>,

    /// OPTIONAL. Method for fetching the Request Object (`get` or `post`).
    ///
    /// MUST NOT be present when `request_uri` is absent.
    pub request_uri_method: Option<RequestUriMethod>,

    /// OPTIONAL. DCQL query for credential requirements.
    ///
    /// Mutually exclusive with `scope`.
    pub dcql_query: Option<DcqlQuery>,

    /// OPTIONAL. Client metadata as defined in OpenID Registration.
    ///
    /// Mutually exclusive with `client_metadata_uri`.
    pub client_metadata: Option<VerifierMetadata>,

    /// OPTIONAL. URI pointing to client metadata.
    ///
    /// Mutually exclusive with `client_metadata`.
    pub client_metadata_uri: Option<Url>,

    /// OPTIONAL. JWT-Secured Authorization Request object (JAR).
    pub request: Option<String>,

    /// OPTIONAL. Transaction data for user consent (Section 8.4).
    pub transaction_data: Option<Vec<String>>,

    /// OPTIONAL. Verifier attestations (non-empty array when present).
    pub verifier_info: Option<Vec<VerifierAttestation>>,

    /// OPTIONAL. Expected origins for DC API requests (Appendix A).
    ///
    /// Validation of this field for signed DC API requests should be done
    /// at the Request Object processing layer where the signed/unsigned context
    /// is available.
    pub expected_origins: Option<Vec<String>>,
}

impl AuthorizationRequest {
    /// Validates the authorization request according to OpenID4VP spec.
    ///
    /// This method orchestrates validation by delegating to focused
    /// validation functions for each logical group of rules.
    ///
    /// Note: DC API-specific validation for signed requests (e.g., `expected_origins`
    /// enforcement) should be performed at the Request Object / DC API processing
    /// layer where the signed/unsigned context is available.
    pub fn validate(&self) -> Result<()> {
        self.validate_core_fields()?;
        self.validate_request_uri_consistency()?;
        self.validate_query_mechanism()?;
        self.validate_response_routing()?;
        self.validate_client_metadata()?;
        self.validate_transaction_data()?;
        self.validate_verifier_info()?;

        Ok(())
    }

    /// Validates core required fields: response_type, client_id, nonce, and state.
    fn validate_core_fields(&self) -> Result<()> {
        // client_id validation: required for non-DC-API modes; may be empty for
        // unsigned DC API requests (per Appendix A.2/A.3.1)
        if !self.oauth.client_id.trim().is_empty() {
            // If client_id is present, it must be non-empty
            self.oauth.validate_client_id()?;
        }
        // Note: For DC API modes, client_id may be empty/absent for unsigned requests

        // response_type must be vp_token or vp_token id_token
        if !matches!(
            self.response_type,
            ResponseType::VpToken | ResponseType::VpTokenIdToken
        ) {
            return Err(invalid_request(
                "'response_type' must be 'vp_token' or 'vp_token id_token'",
            ));
        }

        // nonce MUST be present and non-empty (Section 5.1)
        if self.nonce.trim().is_empty() {
            return Err(invalid_request("'nonce' must not be empty"));
        }

        // nonce MUST contain only unreserved URI characters per Section 5.2
        if !is_unreserved_chars(&self.nonce) {
            return Err(invalid_request(
                "'nonce' must contain only unreserved URI characters (A-Z, a-z, 0-9, -, ., _, ~)",
            ));
        }

        // state validation (unreserved characters) - reuse base OAuth validation
        self.oauth
            .validate_state_unreserved()
            .map_err(|e| invalid_request(format!("'state' validation failed: {e}")))?;

        Ok(())
    }

    /// Validates request_uri_method consistency with request_uri presence.
    fn validate_request_uri_consistency(&self) -> Result<()> {
        // request_uri_method MUST NOT be present when request_uri is absent (Section 5.1)
        if self.request_uri_method.is_some() && self.request_uri.is_none() {
            return Err(invalid_request(
                "'request_uri_method' MUST NOT be present when 'request_uri' is absent",
            ));
        }

        Ok(())
    }

    /// Validates the query mechanism: exactly one of scope or dcql_query must be present.
    fn validate_query_mechanism(&self) -> Result<()> {
        // XOR validation: exactly one of scope or dcql_query must be present (Section 5.1)
        match (&self.oauth.scope, &self.dcql_query) {
            (Some(_), Some(_)) => {
                return Err(invalid_request(
                    "'scope' and 'dcql_query' are mutually exclusive; provide only one",
                ));
            }
            (None, None) => {
                return Err(invalid_request(
                    "either 'scope' or 'dcql_query' must be provided",
                ));
            }
            _ => {}
        }

        // Validate dcql_query structure if present
        if let Some(ref dcql) = self.dcql_query {
            dcql.validate()?;
        }

        Ok(())
    }

    /// Validates response_uri/redirect_uri consistency for the response_mode.
    fn validate_response_routing(&self) -> Result<()> {
        // response_uri required for direct_post modes; redirect_uri must not be present
        if self.response_mode.is_direct_post() {
            if self.response_uri.is_none() {
                return Err(invalid_request(
                    "'response_uri' is required when 'response_mode' is 'direct_post' \
                     or 'direct_post.jwt'",
                ));
            }
            if self.oauth.redirect_uri.is_some() {
                return Err(invalid_request(
                    "'redirect_uri' must not be present when 'response_uri' is used",
                ));
            }
        }

        // response_uri and redirect_uri are mutually exclusive regardless of response_mode
        if self.response_uri.is_some() && self.oauth.redirect_uri.is_some() {
            return Err(invalid_request(
                "'redirect_uri' must not be present when 'response_uri' is used",
            ));
        }

        Ok(())
    }

    /// Validates client_metadata and client_metadata_uri are mutually exclusive.
    fn validate_client_metadata(&self) -> Result<()> {
        if self.client_metadata.is_some() && self.client_metadata_uri.is_some() {
            return Err(invalid_request(
                "'client_metadata' and 'client_metadata_uri' are mutually exclusive",
            ));
        }

        // Validate client_metadata structure if present
        if let Some(ref metadata) = self.client_metadata {
            metadata.validate().map_err(|e| {
                Error::message(
                    ErrorKind::InvalidPresentationRequest,
                    format!("'client_metadata' validation failed: {e}"),
                )
            })?;
        }

        Ok(())
    }

    /// Validates transaction_data entries if present.
    fn validate_transaction_data(&self) -> Result<()> {
        let Some(ref td) = self.transaction_data else {
            return Ok(());
        };

        // transaction_data: non-empty array (Section 8.4)
        if td.is_empty() {
            return Err(invalid_request(
                "'transaction_data' must be a non-empty array when present",
            ));
        }

        // collect valid credential IDs for reference validation
        let valid_cred_ids: Vec<&str> = self
            .dcql_query
            .as_ref()
            .map(|q| q.credentials.iter().map(|c| c.id.as_str()).collect())
            .unwrap_or_default();

        for (i, entry) in td.iter().enumerate() {
            Self::validate_transaction_entry(i, entry, &valid_cred_ids)?;
        }

        Ok(())
    }

    /// Validates a single transaction_data entry.
    fn validate_transaction_entry(idx: usize, entry: &str, valid_cred_ids: &[&str]) -> Result<()> {
        // Use TransactionData::decode for complete validation
        let txn_data = TransactionData::decode(entry).map_err(|e| {
            Error::message(
                ErrorKind::InvalidTransactionData,
                format!("'transaction_data[{idx}]' validation failed: {e}"),
            )
        })?;

        // Validate that all credential_ids reference known credentials from the DCQL query
        for cred_id in txn_data.credential_ids() {
            if !valid_cred_ids.contains(&cred_id.as_str()) {
                return Err(Error::message(
                    ErrorKind::InvalidTransactionData,
                    format!(
                        "'transaction_data[{idx}]' references unknown credential id '{cred_id}'"
                    ),
                ));
            }
        }

        Ok(())
    }

    /// Validates verifier_info attestations if present.
    fn validate_verifier_info(&self) -> Result<()> {
        let Some(ref vi) = self.verifier_info else {
            return Ok(());
        };

        // verifier_info: non-empty array (Section 5.1)
        if vi.is_empty() {
            return Err(invalid_request(
                "'verifier_info' must be a non-empty array when present",
            ));
        }

        // collect valid credential IDs for reference validation
        let valid_cred_ids: Vec<&str> = self
            .dcql_query
            .as_ref()
            .map(|q| q.credentials.iter().map(|c| c.id.as_str()).collect())
            .unwrap_or_default();

        for (i, att) in vi.iter().enumerate() {
            att.validate(i, &valid_cred_ids)?;
        }

        Ok(())
    }
}

/// Deserializes an [`AuthorizationRequest`] and immediately validates it.
impl<'de> Deserialize<'de> for AuthorizationRequest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        // Note: client_id is optional to support unsigned DC API requests (Appendix A.2/A.3.1)
        // where it MUST be omitted. Validation logic handles the presence/absence.
        #[derive(Deserialize)]
        struct Raw {
            response_type: ResponseType,
            nonce: String,
            response_mode: ResponseMode,
            client_id: Option<String>,
            redirect_uri: Option<Url>,
            scope: Option<String>,
            state: Option<String>,
            response_uri: Option<Url>,
            request_uri: Option<Url>,
            request_uri_method: Option<RequestUriMethod>,
            dcql_query: Option<DcqlQuery>,
            client_metadata: Option<VerifierMetadata>,
            client_metadata_uri: Option<Url>,
            request: Option<String>,
            transaction_data: Option<Vec<String>>,
            verifier_info: Option<Vec<VerifierAttestation>>,
            expected_origins: Option<Vec<String>>,
        }

        let raw = Raw::deserialize(deserializer)?;

        // Note: nonce is extracted to top-level field; oauth.nonce is set to None
        // to avoid duplication. See struct documentation for details.
        let request = Self {
            response_type: raw.response_type,
            nonce: raw.nonce,
            response_mode: raw.response_mode,
            oauth: OAuthAuthorizationRequest {
                client_id: raw.client_id.unwrap_or_default(),
                redirect_uri: raw.redirect_uri,
                scope: raw.scope,
                state: raw.state,
                nonce: None, // Top-level nonce is authoritative for OID4VP
                code_challenge: None,
                code_challenge_method: None,
            },
            response_uri: raw.response_uri,
            request_uri: raw.request_uri,
            request_uri_method: raw.request_uri_method,
            dcql_query: raw.dcql_query,
            client_metadata: raw.client_metadata,
            client_metadata_uri: raw.client_metadata_uri,
            request: raw.request,
            transaction_data: raw.transaction_data,
            verifier_info: raw.verifier_info,
            expected_origins: raw.expected_origins,
        };

        // request.validate().map_err(serde::de::Error::custom)?;
        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oid4vp::dcql::{CredentialFormat, CredentialMeta, CredentialQuery};
    use serde_json::json;

    fn parse(v: serde_json::Value) -> std::result::Result<AuthorizationRequest, serde_json::Error> {
        serde_json::from_value(v)
    }

    #[test]
    fn parses_minimal_dcql_request() {
        let req = parse(json!({
            "response_type": "vp_token",
            "client_id": "https://verifier.example.com",
            "response_mode": "direct_post",
            "response_uri": "https://verifier.example.com/response",
            "nonce": "n-0S6_WzA2Mj",
            "dcql_query": {
                "credentials": [{
                    "id": "pid",
                    "format": "dc+sd-jwt",
                    "meta": { "vct_values": ["https://credentials.example.com/identity"] }
                }]
            }
        }))
        .expect("should parse");

        assert_eq!(req.response_type, ResponseType::VpToken);
        assert_eq!(req.oauth.client_id, "https://verifier.example.com");
        assert!(req.dcql_query.is_some());
    }

    #[test]
    fn parses_scope_based_request() {
        let req = parse(json!({
            "response_type": "vp_token",
            "client_id": "https://verifier.example.com",
            "response_mode": "direct_post",
            "response_uri": "https://verifier.example.com/response",
            "nonce": "n-0S6_WzA2Mj",
            "scope": "openid"
        }))
        .expect("should parse");

        assert_eq!(req.oauth.scope.as_deref(), Some("openid"));
        assert!(req.dcql_query.is_none());
    }

    #[test]
    fn parses_full_featured_request() {
        let req = parse(json!({
            "response_type": "vp_token id_token",
            "client_id": "https://verifier.example.com",
            "response_mode": "direct_post.jwt",
            "response_uri": "https://verifier.example.com/response",
            "nonce": "n-0S6_WzA2Mj",
            "state": "xyz-state",
            "request_uri": "https://verifier.example.com/request",
            "request_uri_method": "post",
            "request": "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ2ZXJpZmllciJ9",
            "transaction_data": ["eyJ0eXBlIjoib3BlbmlkNHZwIiwiY3JlZGVudGlhbF9pZHMiOlsicGlkIl19"],
            "verifier_info": [{"format": "jwt_vc", "data": "eyJ0eXBlIjoidmVyaWZpZXIifQ"}],
            "client_metadata": {
                "vp_formats_supported": {
                    "dc+sd-jwt": {
                        "sd-jwt_alg_values": ["ES256"],
                        "kb-jwt_alg_values": ["ES256"]
                    }
                }
            },
            "dcql_query": {
                "credentials": [{
                    "id": "pid",
                    "format": "dc+sd-jwt",
                    "meta": { "vct_values": ["https://example.com"] },
                    "multiple": true,
                    "claims": [
                        { "path": ["given_name"], "id": "gn" },
                        { "path": ["addresses", 0, "street"], "id": "street" }
                    ],
                    "claim_sets": [["gn"], ["gn", "street"]]
                }]
            }
        }))
        .expect("should parse");

        assert_eq!(req.response_type, ResponseType::VpTokenIdToken);
        assert_eq!(req.response_mode, ResponseMode::DirectPostJwt);
        assert_eq!(req.oauth.state.as_deref(), Some("xyz-state"));
        assert!(req.request.is_some());
        assert!(req.transaction_data.is_some());
        assert!(req.verifier_info.is_some());
        assert!(req.client_metadata.is_some());
    }

    #[test]
    fn parses_dc_api_request_with_client_id() {
        let req = parse(json!({
            "response_type": "vp_token",
            "client_id": "https://verifier.example.com",
            "response_mode": "dc_api.jwt",
            "nonce": "abc123",
            "expected_origins": ["https://app.example.com"],
            "dcql_query": {
                "credentials": [{
                    "id": "mdl",
                    "format": "mso_mdoc",
                    "meta": { "doctype_value": "org.iso.18013.5.1.mDL" }
                }]
            }
        }))
        .expect("should parse");

        assert_eq!(req.response_mode, ResponseMode::DcApiJwt);
        assert_eq!(req.oauth.client_id, "https://verifier.example.com");
        assert!(req.expected_origins.is_some());
    }

    #[test]
    fn parses_unsigned_dc_api_request_without_client_id() {
        // Per OpenID4VP Appendix A.2/A.3.1: unsigned DC API requests MUST omit client_id
        let req = parse(json!({
            "response_type": "vp_token",
            "response_mode": "dc_api",
            "nonce": "abc123",
            "dcql_query": {
                "credentials": [{
                    "id": "mdl",
                    "format": "mso_mdoc",
                    "meta": { "doctype_value": "org.iso.18013.5.1.mDL" }
                }]
            }
        }))
        .expect("should parse unsigned DC API request without client_id");

        assert_eq!(req.response_mode, ResponseMode::DcApi);
        assert!(req.oauth.client_id.is_empty());
        assert!(req.expected_origins.is_none());
    }

    #[test]
    fn parses_extension_response_mode() {
        let req = parse(json!({
            "response_type": "vp_token",
            "client_id": "https://verifier.example.com",
            "response_mode": "fragment",
            "nonce": "abc123",
            "redirect_uri": "https://verifier.example.com/callback",
            "dcql_query": {
                "credentials": [{
                    "id": "pid",
                    "format": "dc+sd-jwt",
                    "meta": { "vct_values": ["https://example.com"] }
                }]
            }
        }))
        .expect("should parse");

        assert_eq!(
            req.response_mode,
            ResponseMode::Other("fragment".to_string())
        );
        assert!(req.oauth.redirect_uri.is_some());
    }

    #[test]
    fn serde_roundtrip() {
        let req = parse(json!({
            "response_type": "vp_token",
            "client_id": "https://verifier.example.com",
            "response_mode": "direct_post",
            "response_uri": "https://verifier.example.com/response",
            "nonce": "n-0S6_WzA2Mj",
            "dcql_query": {
                "credentials": [{
                    "id": "pid",
                    "format": "dc+sd-jwt",
                    "meta": { "vct_values": ["https://example.com"] }
                }]
            }
        }))
        .expect("should parse");

        let serialized = serde_json::to_string(&req).expect("should serialize");
        let deserialized: AuthorizationRequest =
            serde_json::from_str(&serialized).expect("should round-trip");
        assert_eq!(req.nonce, deserialized.nonce);
        assert_eq!(req.oauth.client_id, deserialized.oauth.client_id);
    }

    #[test]
    fn validate_constructed_request() {
        let req = AuthorizationRequest {
            response_type: ResponseType::VpToken,
            nonce: "fresh-nonce".to_string(),
            response_mode: ResponseMode::DirectPost,
            oauth: OAuthAuthorizationRequest {
                client_id: "https://verifier.example.com".to_string(),
                redirect_uri: None,
                scope: None,
                state: None,
                nonce: None,
                code_challenge: None,
                code_challenge_method: None,
            },
            response_uri: Some(Url::parse("https://verifier.example.com/response").unwrap()),
            request_uri: None,
            request_uri_method: None,
            dcql_query: Some(DcqlQuery {
                credentials: vec![CredentialQuery {
                    id: "test-id".to_string(),
                    format: CredentialFormat::DcSdJwt,
                    multiple: None,
                    meta: CredentialMeta::SdJwt {
                        vct_values: vec!["https://example.com".to_string()],
                    },
                    claims: None,
                    claim_sets: None,
                    trusted_authorities: None,
                    require_cryptographic_holder_binding: None,
                }],
                credential_sets: None,
            }),
            client_metadata: None,
            client_metadata_uri: None,
            request: None,
            transaction_data: None,
            verifier_info: None,
            expected_origins: None,
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn display_traits() {
        assert_eq!(ResponseType::VpToken.to_string(), "vp_token");
        assert_eq!(
            ResponseType::VpTokenIdToken.to_string(),
            "vp_token id_token"
        );
        assert_eq!(ResponseMode::DirectPost.to_string(), "direct_post");
        assert_eq!(ResponseMode::DirectPostJwt.to_string(), "direct_post.jwt");
        assert_eq!(ResponseMode::DcApi.to_string(), "dc_api");
        assert_eq!(ResponseMode::DcApiJwt.to_string(), "dc_api.jwt");
        assert_eq!(
            ResponseMode::Other("fragment".to_string()).to_string(),
            "fragment"
        );
        assert_eq!(RequestUriMethod::Get.to_string(), "get");
        assert_eq!(RequestUriMethod::Post.to_string(), "post");
        assert_eq!(RequestUriMethod::default(), RequestUriMethod::Get);
    }
}
