use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use serde_with::skip_serializing_none;
use url::Url;

use crate::errors::{Error, ErrorKind, Result};

// Re-export DCQL types from the dcql module
pub use super::super::dcql::DcqlQuery;

/// An OpenID4VP Authorization Request.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AuthorizationRequest {
    pub response_type: ResponseType,

    pub client_id: String,

    pub redirect_uri: Option<Url>,

    pub scope: Option<String>,

    pub state: Option<String>,

    pub nonce: String,

    pub response_mode: ResponseMode,

    pub response_uri: Option<Url>,

    pub request_uri: Option<Url>,

    pub request_uri_method: Option<RequestUriMethod>,

    pub dcql_query: Option<DcqlQuery>,

    pub client_metadata: Option<Value>,

    pub client_metadata_uri: Option<Url>,

    pub request: Option<String>,

    pub transaction_data: Option<Vec<String>>,

    pub verifier_info: Option<Vec<VerifierAttestation>>,

    pub expected_origins: Option<Vec<String>>,
}

impl AuthorizationRequest {
    /// Validates the authorization request according to OpenID4VP spec.
    ///
    /// This method orchestrates validation by delegating to focused
    /// validation functions for each logical group of rules.
    pub fn validate(&self) -> Result<()> {
        self.validate_core_fields()?;
        self.validate_request_uri_consistency()?;
        self.validate_query_mechanism()?;
        self.validate_response_routing()?;
        self.validate_dc_api_origins()?;
        self.validate_client_metadata()?;
        self.validate_transaction_data()?;
        self.validate_verifier_info()?;

        Ok(())
    }

    /// Validates core required fields: response_type, client_id, nonce, and state.
    fn validate_core_fields(&self) -> Result<()> {
        // response_type must be vp_token or vp_token id_token
        if !matches!(
            self.response_type,
            ResponseType::VpToken | ResponseType::VpTokenIdToken
        ) {
            return Err(invalid_request(
                "'response_type' must be 'vp_token' or 'vp_token id_token'",
            ));
        }

        // client_id MUST be present and non-empty (Section 5.2)
        if self.client_id.trim().is_empty() {
            return Err(invalid_request("'client_id' must not be empty"));
        }

        // nonce MUST be present and non-empty (Section 5.1)
        if self.nonce.trim().is_empty() {
            return Err(invalid_request("'nonce' must not be empty"));
        }

        // nonce MUST contain only unreserved URI characters per Section 5.2:
        // A-Z, a-z, 0-9, -, ., _, ~
        if !is_unreserved_chars(&self.nonce) {
            return Err(invalid_request(
                "'nonce' must contain only unreserved URI characters (A-Z, a-z, 0-9, -, ., _, ~)",
            ));
        }

        // state, when present, is subject to the same character constraint (Section 5.2)
        if let Some(ref state) = self.state
            && !is_unreserved_chars(state)
        {
            return Err(invalid_request(
                "'state' must contain only unreserved URI characters (A-Z, a-z, 0-9, -, ., _, ~)",
            ));
        }

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
        match (&self.scope, &self.dcql_query) {
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

    /// Validates responseuri/redirect_uri consistency for the response_mode.
    fn validate_response_routing(&self) -> Result<()> {
        // responseuri required for direct_post modes; redirect_uri must not be present
        if self.response_mode.is_direct_post() {
            if self.response_uri.is_none() {
                return Err(invalid_request(
                    "'response_uri' is required when 'response_mode' is 'direct_post' \
                     or 'direct_post.jwt'",
                ));
            }
            if self.redirect_uri.is_some() {
                return Err(invalid_request(
                    "'redirect_uri' must not be present when 'response_uri' is used",
                ));
            }
        }

        // response_uri and redirect_uri are mutually exclusive regardless of response_mode
        if self.response_uri.is_some() && self.redirect_uri.is_some() {
            return Err(invalid_request(
                "'redirect_uri' must not be present when 'response_uri' is used",
            ));
        }

        Ok(())
    }

    /// Validates expected_origins for DC API response modes.
    ///
    /// Per Appendix A:
    /// - Signed DC API requests (with `client_id` and `request` JWT): `expected_origins` is REQUIRED
    ///   so the wallet can compare the invocation origin with the signed request.
    /// - Unsigned DC API requests (without `client_id`): `expected_origins` is NOT required.
    fn validate_dc_api_origins(&self) -> Result<()> {
        // Only validate for signed DC API requests (have client_id and request JWT)
        if self.response_mode.is_dc_api() && self.is_signed_dc_api_request() {
            match &self.expected_origins {
                None => {
                    return Err(invalid_request(
                        "'expected_origins' is required for signed DC API requests ('dc_api' or 'dc_api.jwt' with client_id and request JWT)",
                    ));
                }
                Some(origins) if origins.is_empty() => {
                    return Err(invalid_request(
                        "'expected_origins' must be a non-empty array",
                    ));
                }
                Some(origins) => {
                    for (i, origin) in origins.iter().enumerate() {
                        Self::validate_origin(i, origin)?;
                    }
                }
            }
        }

        Ok(())
    }

    /// Returns true if this is a signed DC API request (has both client_id and request JWT).
    ///
    /// Per Appendix A: signed requests include client_id and a request JWT,
    /// while unsigned requests omit client_id.
    fn is_signed_dc_api_request(&self) -> bool {
        // Signed requests have a non-empty client_id and a request JWT
        !self.client_id.trim().is_empty() && self.request.is_some()
    }

    /// Validates a single origin string is a valid origin tuple.
    fn validate_origin(idx: usize, origin: &str) -> Result<()> {
        // Parse as URL to validate structure
        let url = Url::parse(origin).map_err(|e| {
            invalid_request(format!(
                "'expected_origins[{idx}]' '{origin}' is not a valid URL: {e}"
            ))
        })?;

        // Validate it's a valid origin (no path, query, or fragment)
        // Origin = scheme + "://" + host + optional port
        if url.path() != "/" && !url.path().is_empty() {
            return Err(invalid_request(format!(
                "'expected_origins[{idx}]' '{origin}' must not contain a path"
            )));
        }
        if url.query().is_some() {
            return Err(invalid_request(format!(
                "'expected_origins[{idx}]' '{origin}' must not contain a query string"
            )));
        }
        if url.fragment().is_some() {
            return Err(invalid_request(format!(
                "'expected_origins[{idx}]' '{origin}' must not contain a fragment"
            )));
        }
        // Must have a host
        if url.host().is_none() {
            return Err(invalid_request(format!(
                "'expected_origins[{idx}]' '{origin}' must have a host"
            )));
        }

        Ok(())
    }

    /// Validates client_metadata and client_metadata_uri are mutually exclusive.
    fn validate_client_metadata(&self) -> Result<()> {
        // client_metadata and client_metadata_uri are mutually exclusive (Section 5.1)
        if self.client_metadata.is_some() && self.client_metadata_uri.is_some() {
            return Err(invalid_request(
                "'client_metadata' and 'client_metadata_uri' are mutually exclusive",
            ));
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
        // Must be a valid base64url-encoded string
        if !is_base64url(entry) {
            return Err(invalid_request(format!(
                "'transaction_data[{idx}]' must be a valid base64url-encoded string"
            )));
        }

        // Decode and validate the JSON structure
        let decoded = URL_SAFE_NO_PAD.decode(entry.as_bytes()).map_err(|e| {
            invalid_request(format!(
                "'transaction_data[{idx}]' is not valid base64url: {e}"
            ))
        })?;

        let json_str = String::from_utf8(decoded).map_err(|e| {
            invalid_request(format!(
                "'transaction_data[{idx}]' does not decode to valid UTF-8: {e}"
            ))
        })?;

        let entry_data: TransactionDataEntry = serde_json::from_str(&json_str).map_err(|e| {
            invalid_request(format!(
                "'transaction_data[{idx}]' does not decode to valid TransactionDataEntry JSON: {e}"
            ))
        })?;

        // Validate the entry structure
        entry_data.validate(idx, valid_cred_ids)?;

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

/// Checks that every character in `s` is an unreserved URI character per RFC 3986 / Section 5.2:
/// A–Z, a–z, 0–9, `-`, `.`, `_`, `~`
fn is_unreserved_chars(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~'))
}

/// Validates that a string is a valid base64url-encoded value (no padding, URL-safe alphabet).
fn is_base64url(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Deserializes an [`AuthorizationRequest`] and immediately validates it.
impl<'de> Deserialize<'de> for AuthorizationRequest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            response_type: ResponseType,
            client_id: String,
            redirect_uri: Option<Url>,
            scope: Option<String>,
            state: Option<String>,
            nonce: String,
            response_mode: ResponseMode,
            response_uri: Option<Url>,
            request_uri: Option<Url>,
            request_uri_method: Option<RequestUriMethod>,
            dcql_query: Option<DcqlQuery>,
            client_metadata: Option<Value>,
            client_metadata_uri: Option<Url>,
            request: Option<String>,
            transaction_data: Option<Vec<String>>,
            verifier_info: Option<Vec<VerifierAttestation>>,
            expected_origins: Option<Vec<String>>,
        }

        let raw = Raw::deserialize(deserializer)?;

        // Section 5.1: request_uri_method MUST NOT be present when request_uri is absent.
        // This is enforced in validate(); we preserve the raw value so validate() can
        // produce a clear error rather than silently dropping it.
        let request = Self {
            response_type: raw.response_type,
            client_id: raw.client_id,
            redirect_uri: raw.redirect_uri,
            scope: raw.scope,
            state: raw.state,
            nonce: raw.nonce,
            response_mode: raw.response_mode,
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

        request.validate().map_err(serde::de::Error::custom)?;
        Ok(request)
    }
}

fn invalid_request(message: impl Into<String>) -> Error {
    Error::message(ErrorKind::InvalidPresentationRequest, message.into())
}
/// An OpenID4VP Authorization Request.
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
/// Includes `direct_post`/`direct_post.jwt` (Section 5.1) and
/// `dc_api`/`dc_api.jwt` for the W3C Digital Credentials API (Appendix A).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResponseMode {
    #[serde(rename = "direct_post")]
    DirectPost,

    #[serde(rename = "direct_post.jwt")]
    DirectPostJwt,

    /// W3C Digital Credentials API response mode (Appendix A).
    #[serde(rename = "dc_api")]
    DcApi,

    /// W3C Digital Credentials API response mode with JWT-secured response (Appendix A).
    #[serde(rename = "dc_api.jwt")]
    DcApiJwt,
}

impl ResponseMode {
    fn is_direct_post(self) -> bool {
        matches!(self, Self::DirectPost | Self::DirectPostJwt)
    }

    fn is_dc_api(self) -> bool {
        matches!(self, Self::DcApi | Self::DcApiJwt)
    }
}

impl std::fmt::Display for ResponseMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DirectPost => write!(f, "direct_post"),
            Self::DirectPostJwt => write!(f, "direct_post.jwt"),
            Self::DcApi => write!(f, "dc_api"),
            Self::DcApiJwt => write!(f, "dc_api.jwt"),
        }
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
    pub data: Value,

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

/// Supported transaction data types per OpenID4VP Section 8.4.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionDataType {
    /// OpenID4VP transaction data type.
    #[serde(rename = "openid4vp")]
    Openid4vp,
    /// Extension point for other transaction data types.
    #[serde(untagged)]
    Other(String),
}

impl TransactionDataType {
    /// Returns true if this is a supported transaction data type.
    fn is_supported(&self) -> bool {
        matches!(self, Self::Openid4vp)
    }
}

impl std::fmt::Display for TransactionDataType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Openid4vp => write!(f, "openid4vp"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

/// Transaction data entry as decoded from base64url.
///
/// Section 8.4 requires each entry to be base64url-decoded into a JSON object
/// with at least `type` and a non-empty `credential_ids` array referencing DCQL credential IDs.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransactionDataEntry {
    /// REQUIRED. The transaction data type.
    #[serde(rename = "type")]
    pub data_type: TransactionDataType,

    pub credential_ids: Vec<String>,
}

impl TransactionDataEntry {
    fn validate(&self, idx: usize, valid_credential_ids: &[&str]) -> Result<()> {
        // Section 8.4: wallet must return invalid_transaction_data for unsupported types
        if !self.data_type.is_supported() {
            return Err(invalid_request(format!(
                "'transaction_data[{idx}].type' '{}' is not a supported transaction data type",
                self.data_type
            )));
        }
        if self.credential_ids.is_empty() {
            return Err(invalid_request(format!(
                "'transaction_data[{idx}].credential_ids' must be a non-empty array"
            )));
        }
        for (ci, id_ref) in self.credential_ids.iter().enumerate() {
            if !valid_credential_ids.contains(&id_ref.as_str()) {
                return Err(invalid_request(format!(
                    "'transaction_data[{idx}].credential_ids[{ci}]' references unknown credential id '{id_ref}'"
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::dcql::{CredentialFormat, CredentialMeta, CredentialQuery};
    use super::*;
    use serde_json::json;

    fn parse(v: Value) -> std::result::Result<AuthorizationRequest, serde_json::Error> {
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
        assert_eq!(req.client_id, "https://verifier.example.com");
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

        assert_eq!(req.scope.as_deref(), Some("openid"));
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
            "client_metadata": { "vp_formats": { "dc+sd-jwt": { "alg": ["ES256"] } } },
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
        assert_eq!(req.state.as_deref(), Some("xyz-state"));
        assert!(req.request.is_some());
        assert!(req.transaction_data.is_some());
        assert!(req.verifier_info.is_some());
        assert!(req.client_metadata.is_some());
    }

    #[test]
    fn parses_dc_api_request() {
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
        assert!(req.expected_origins.is_some());
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
        assert_eq!(req.client_id, deserialized.client_id);
    }

    #[test]
    fn validate_constructed_request() {
        let req = AuthorizationRequest {
            response_type: ResponseType::VpToken,
            client_id: "https://verifier.example.com".to_string(),
            redirect_uri: None,
            scope: None,
            state: None,
            nonce: "fresh-nonce".to_string(),
            response_mode: ResponseMode::DirectPost,
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
        assert_eq!(RequestUriMethod::Get.to_string(), "get");
        assert_eq!(RequestUriMethod::Post.to_string(), "post");
        assert_eq!(RequestUriMethod::default(), RequestUriMethod::Get);
    }
}
