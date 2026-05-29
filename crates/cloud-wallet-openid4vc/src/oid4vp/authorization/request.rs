use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use serde_with::skip_serializing_none;
use url::Url;

use crate::errors::{Error, ErrorKind, Result};

/// The `response_type` parameter for OpenID4VP Authorization Requests.
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
/// A single DCQL Claims Query object.
///
/// Defined in [OpenID4VP Section 6.3](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimsQuery {
    /// REQUIRED. A non-empty Claims Path Pointer identifying the claim.
    pub path: Vec<Value>,

    /// OPTIONAL. Identifier for this claims query, required when `claim_sets` is present.
    /// Must consist only of alphanumeric characters, `_`, or `-`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// OPTIONAL. Non-empty array of acceptable claim values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<Value>>,
}

impl ClaimsQuery {
    fn validate(&self, idx: usize, require_id: bool) -> Result<()> {
        if self.path.is_empty() {
            return Err(invalid_request(format!(
                "'claims[{idx}].path' must be a non-empty array"
            )));
        }
        if let Some(ref id) = self.id
            && !is_dcql_identifier(id)
        {
            return Err(invalid_request(format!(
                "'claims[{idx}].id' must consist only of alphanumeric characters, '_', or '-'"
            )));
        }

        if require_id && self.id.is_none() {
            return Err(invalid_request(format!(
                "'claims[{idx}].id' is required when 'claim_sets' is present"
            )));
        }
        if let Some(ref values) = self.values
            && values.is_empty()
        {
            return Err(invalid_request(format!(
                "'claims[{idx}].values' must be a non-empty array when present"
            )));
        }
        Ok(())
    }
}

/// A single Credential Set option entry.
///
/// Defined in [OpenID4VP Section 6.2](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialSet {
    /// REQUIRED. Non-empty array of options, each a non-empty list of credential query IDs.
    pub options: Vec<Vec<String>>,

    /// OPTIONAL. Defaults to `true`. Whether this credential set is required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
}

impl CredentialSet {
    fn validate(&self, idx: usize, valid_ids: &[&str]) -> Result<()> {
        if self.options.is_empty() {
            return Err(invalid_request(format!(
                "'credential_sets[{idx}].options' must be a non-empty array"
            )));
        }
        for (oi, option) in self.options.iter().enumerate() {
            if option.is_empty() {
                return Err(invalid_request(format!(
                    "'credential_sets[{idx}].options[{oi}]' must be a non-empty array"
                )));
            }
            for id_ref in option {
                if !valid_ids.contains(&id_ref.as_str()) {
                    return Err(invalid_request(format!(
                        "'credential_sets[{idx}].options[{oi}]' references unknown credential id '{id_ref}'"
                    )));
                }
            }
        }
        Ok(())
    }
}

/// A Trusted Authority Query object within a Credential Query.
///
/// Section 6.1 defines `trusted_authorities` as an array of these objects.
/// The fields are format-specific and kept as `Value` for extensibility; callers
/// that need strict per-format validation should perform it on top of this model.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustedAuthorityQuery {
    /// The type of trusted authority reference (e.g. `"aki"`, `"etsi_tl"`, `"openid_federation"`).
    #[serde(rename = "type")]
    pub authority_type: String,

    /// Type-specific authority value(s).
    pub value: Value,
}

/// A credential query within a DCQL query.
///
/// Defined in [OpenID4VP Section 6.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1).
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialQuery {
    /// REQUIRED. Unique identifier for this credential query.
    /// Must consist only of alphanumeric characters, `_`, or `-`.
    pub id: String,

    /// REQUIRED. The format of the requested credential (e.g., `"dc+sd-jwt"`, `"mso_mdoc"`).
    #[serde(rename = "format")]
    pub format: String,

    /// OPTIONAL. When `true`, the wallet MAY return more than one Presentation for this
    /// query in the `vp_token` array. Defaults to `false` (Section 8.1).
    pub multiple: Option<bool>,

    /// OPTIONAL. Format-specific metadata for the credential query.
    ///
    /// For `dc+sd-jwt` (Section B.3.1), `vct_values` must be a non-empty array of strings.
    #[serde(rename = "meta")]
    pub meta: Option<Value>,

    /// OPTIONAL. Typed array of DCQL Claims Query objects (Section 6.3).
    pub claims: Option<Vec<ClaimsQuery>>,

    /// OPTIONAL. Non-empty array of claim-id arrays used to select claim combinations.
    ///
    /// MUST NOT be present when `claims` is absent (Section 6.4.1).
    /// When present, every `claims` entry MUST have an `id` (Section 6.3).
    pub claim_sets: Option<Vec<Vec<String>>>,

    /// OPTIONAL. Trusted authority constraints for this credential (Section 6.1).
    pub trusted_authorities: Option<Vec<TrustedAuthorityQuery>>,

    /// OPTIONAL. Whether cryptographic holder binding is required. Defaults to `true` (Section 6.1).
    pub require_cryptographic_holder_binding: Option<bool>,
}

impl CredentialQuery {
    fn validate(&self, idx: usize) -> Result<()> {
        // id must be non-empty and match DCQL identifier charset
        if self.id.trim().is_empty() {
            return Err(invalid_request(format!(
                "'dcql_query.credentials[{idx}].id' must not be empty"
            )));
        }
        if !is_dcql_identifier(&self.id) {
            return Err(invalid_request(format!(
                "'dcql_query.credentials[{idx}].id' must consist only of alphanumeric characters, '_', or '-'"
            )));
        }

        // format must be non-empty
        if self.format.trim().is_empty() {
            return Err(invalid_request(format!(
                "'dcql_query.credentials[{idx}].format' must not be empty"
            )));
        }

        // format-aware meta validation
        if let Some(ref meta) = self.meta
            && self.format == "dc+sd-jwt"
        {
            let vct = meta.get("vct_values");
            match vct {
                Some(Value::Array(arr)) if !arr.is_empty() => {
                    for (vi, v) in arr.iter().enumerate() {
                        if !v.is_string() {
                            return Err(invalid_request(format!(
                                "'dcql_query.credentials[{idx}].meta.vct_values[{vi}]' must be a string"
                            )));
                        }
                    }
                }
                Some(Value::Array(_)) => {
                    return Err(invalid_request(format!(
                        "'dcql_query.credentials[{idx}].meta.vct_values' must be a non-empty array"
                    )));
                }
                None => {
                    return Err(invalid_request(format!(
                        "'dcql_query.credentials[{idx}].meta.vct_values' is required for format 'dc+sd-jwt'"
                    )));
                }
                _ => {
                    return Err(invalid_request(format!(
                        "'dcql_query.credentials[{idx}].meta.vct_values' must be an array of strings"
                    )));
                }
            }
        }

        // claim_sets MUST NOT be present when claims is absent
        if self.claim_sets.is_some() && self.claims.is_none() {
            return Err(invalid_request(format!(
                "'dcql_query.credentials[{idx}].claim_sets' MUST NOT be present when 'claims' is absent"
            )));
        }

        let has_claim_sets = self.claim_sets.is_some();

        // validate claims entries
        if let Some(ref claims) = self.claims {
            let mut seen_ids: Vec<&str> = Vec::new();
            for (ci, claim) in claims.iter().enumerate() {
                claim.validate(ci, has_claim_sets)?;
                if let Some(ref id) = claim.id {
                    if seen_ids.contains(&id.as_str()) {
                        return Err(invalid_request(format!(
                            "'dcql_query.credentials[{idx}].claims[{ci}].id' '{id}' is not unique within the claims array"
                        )));
                    }
                    seen_ids.push(id.as_str());
                }
            }
        }

        // validate claim_sets entries reference known claim IDs
        if let Some(ref claim_sets) = self.claim_sets {
            if claim_sets.is_empty() {
                return Err(invalid_request(format!(
                    "'dcql_query.credentials[{idx}].claim_sets' must be a non-empty array when present"
                )));
            }
            // collect valid claim ids for reference checking
            let valid_claim_ids: Vec<&str> = self
                .claims
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .filter_map(|c| c.id.as_deref())
                .collect();

            for (si, set) in claim_sets.iter().enumerate() {
                if set.is_empty() {
                    return Err(invalid_request(format!(
                        "'dcql_query.credentials[{idx}].claim_sets[{si}]' must be a non-empty array"
                    )));
                }
                for id_ref in set {
                    if !valid_claim_ids.contains(&id_ref.as_str()) {
                        return Err(invalid_request(format!(
                            "'dcql_query.credentials[{idx}].claim_sets[{si}]' references unknown claim id '{id_ref}'"
                        )));
                    }
                }
            }
        }

        Ok(())
    }
}

/// A Digital Credentials Query Language (DCQL) query.
///
/// Defined in [OpenID4VP Section 5.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DcqlQuery {
    /// REQUIRED. Array of credential queries. Must contain at least one element.
    pub credentials: Vec<CredentialQuery>,

    /// OPTIONAL. Credential sets for combining multiple credential queries (Section 6.2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_sets: Option<Vec<CredentialSet>>,
}

impl DcqlQuery {
    /// Validates the DCQL query structure.
    pub fn validate(&self) -> Result<()> {
        if self.credentials.is_empty() {
            return Err(invalid_request(
                "'dcql_query.credentials' must contain at least one credential query",
            ));
        }

        // validate each credential query and collect IDs for uniqueness + reference checks
        let mut seen_ids: Vec<&str> = Vec::new();
        for (i, cred) in self.credentials.iter().enumerate() {
            cred.validate(i)?;
            if seen_ids.contains(&cred.id.as_str()) {
                return Err(invalid_request(format!(
                    "'dcql_query.credentials[{i}].id' '{}' must be unique within the credentials array",
                    cred.id
                )));
            }
            seen_ids.push(cred.id.as_str());
        }

        // validate credential_sets, passing the set of valid credential IDs
        if let Some(ref sets) = self.credential_sets {
            for (i, set) in sets.iter().enumerate() {
                set.validate(i, &seen_ids)?;
            }
        }

        Ok(())
    }
}

/// Validates that a string is a valid base64url-encoded value (no padding, URL-safe alphabet).
fn is_base64url(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
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

/// An OpenID4VP Authorization Request.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AuthorizationRequest {
    /// REQUIRED. Must be `vp_token` (or `vp_token id_token`).
    pub response_type: ResponseType,

    /// REQUIRED. The Verifier's client identifier.
    pub client_id: String,

    /// OPTIONAL. Standard OAuth 2.0 redirect URI.
    pub redirect_uri: Option<Url>,

    /// OPTIONAL. OAuth 2.0 scope values representing DCQL query aliases (Section 5.5).
    /// Mutually exclusive with `dcql_query`.
    ///
    /// NOTE: This implementation accepts any non-empty scope string. Strict per-scope
    /// DCQL alias validation is left to a higher-level layer, since alias definitions
    /// are deployment-specific (Section 5.5).
    pub scope: Option<String>,

    /// OPTIONAL. Opaque state value echoed back in the response.
    /// Must contain only unreserved URI characters (A-Z, a-z, 0-9, `-`, `.`, `_`, `~`).
    pub state: Option<String>,

    /// REQUIRED. A fresh, unique nonce binding the VP Token to this request.
    /// Must contain only unreserved URI characters (A-Z, a-z, 0-9, `-`, `.`, `_`, `~`)
    /// per Section 5.2.
    pub nonce: String,

    /// REQUIRED. How the Wallet delivers the Authorization Response.
    pub response_mode: ResponseMode,

    /// CONDITIONAL. The URI to which the Wallet POSTs the Authorization Response.
    /// Required when `response_mode` is `direct_post` or `direct_post.jwt`.
    pub response_uri: Option<Url>,

    /// OPTIONAL. A reference to a JAR (JWT-Secured Authorization Request) object.
    pub request_uri: Option<Url>,

    /// OPTIONAL. Controls whether the Wallet fetches `request_uri` via GET or POST.
    /// MUST NOT be present when `request_uri` is absent (Section 5.1).
    pub request_uri_method: Option<RequestUriMethod>,

    /// CONDITIONAL. A DCQL query describing the credentials the Verifier requests.
    /// Mutually exclusive with `scope`.
    pub dcql_query: Option<DcqlQuery>,

    /// OPTIONAL. Verifier metadata provided inline.
    pub client_metadata: Option<Value>,

    /// OPTIONAL. URI from which the Wallet can fetch the Verifier's metadata.
    pub client_metadata_uri: Option<Url>,

    /// OPTIONAL. The Request Object passed by value (JAR).
    pub request: Option<String>,

    /// OPTIONAL. Non-empty array of base64url-encoded JSON strings representing
    /// transaction data for external authorization (Section 8.4).
    ///
    /// A Wallet that does not support `transaction_data` MUST return an error when
    /// this field is present. Validation here ensures the array is non-empty and
    /// each entry is a valid base64url string; semantic decoding is the Wallet's
    /// responsibility.
    pub transaction_data: Option<Vec<String>>,

    /// OPTIONAL. Non-empty array of Verifier Attestation objects for trust establishment
    /// (Section 5.1).
    pub verifier_info: Option<Vec<VerifierAttestation>>,

    /// CONDITIONAL. Non-empty array of Verifier Origins required for DC API requests
    /// (Appendix A.2). REQUIRED when `response_mode` is `dc_api` or `dc_api.jwt`.
    pub expected_origins: Option<Vec<String>>,
}

impl AuthorizationRequest {
    /// Validates the Authorization Request against all OID4VP spec constraints.
    pub fn validate(&self) -> Result<()> {
        // response_type must be vp_token (per ticket requirement)
        if !matches!(self.response_type, ResponseType::VpToken) {
            return Err(invalid_request("'response_type' must be 'vp_token'"));
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

        // request_uri_method MUST NOT be present when request_uri is absent (Section 5.1)
        if self.request_uri_method.is_some() && self.request_uri.is_none() {
            return Err(invalid_request(
                "'request_uri_method' MUST NOT be present when 'request_uri' is absent",
            ));
        }

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

        // response_uri required for direct_post modes; redirect_uri must not be present
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

        // expected_origins REQUIRED and non-empty for DC API modes (Appendix A.2)
        if self.response_mode.is_dc_api() {
            match &self.expected_origins {
                None => {
                    return Err(invalid_request(
                        "'expected_origins' is required when 'response_mode' is 'dc_api' or 'dc_api.jwt'",
                    ));
                }
                Some(origins) if origins.is_empty() => {
                    return Err(invalid_request(
                        "'expected_origins' must be a non-empty array",
                    ));
                }
                _ => {}
            }
        }

        // client_metadata and client_metadata_uri are mutually exclusive (Section 5.1)
        if self.client_metadata.is_some() && self.client_metadata_uri.is_some() {
            return Err(invalid_request(
                "'client_metadata' and 'client_metadata_uri' are mutually exclusive",
            ));
        }

        // transaction_data: non-empty array, each entry a valid base64url string (Section 8.4)
        if let Some(ref td) = self.transaction_data {
            if td.is_empty() {
                return Err(invalid_request(
                    "'transaction_data' must be a non-empty array when present",
                ));
            }
            for (i, entry) in td.iter().enumerate() {
                if !is_base64url(entry) {
                    return Err(invalid_request(format!(
                        "'transaction_data[{i}]' must be a valid base64url-encoded string"
                    )));
                }
            }
        }

        // verifier_info: non-empty array; validate each attestation (Section 5.1)
        if let Some(ref vi) = self.verifier_info {
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

/// Checks that `s` is a valid DCQL identifier: non-empty, alphanumeric + `_` + `-` (Section 6.1).
fn is_dcql_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn minimal_valid_dcql() -> Value {
        json!({
            "response_type": "vp_token",
            "client_id": "https://verifier.example.com",
            "response_mode": "direct_post",
            "response_uri": "https://verifier.example.com/response",
            "nonce": "n-0S6_WzA2Mj",
            "dcql_query": {
                "credentials": [
                    {
                        "id": "pid",
                        "format": "dc+sd-jwt",
                        "meta": { "vct_values": ["https://credentials.example.com/identity"] }
                    }
                ]
            }
        })
    }

    fn minimal_valid_scope() -> Value {
        json!({
            "response_type": "vp_token",
            "client_id": "https://verifier.example.com",
            "response_mode": "direct_post",
            "response_uri": "https://verifier.example.com/response",
            "nonce": "n-0S6_WzA2Mj",
            "scope": "openid"
        })
    }

    fn parse(v: Value) -> std::result::Result<AuthorizationRequest, serde_json::Error> {
        serde_json::from_value(v)
    }

    #[test]
    fn parses_minimal_valid_request_with_dcql() {
        let req = parse(minimal_valid_dcql()).expect("should parse");
        assert_eq!(req.response_type, ResponseType::VpToken);
        assert_eq!(req.client_id, "https://verifier.example.com");
        assert_eq!(req.nonce, "n-0S6_WzA2Mj");
        assert_eq!(req.response_mode, ResponseMode::DirectPost);
        assert!(req.dcql_query.is_some());
        assert!(req.scope.is_none());
        assert!(req.redirect_uri.is_none());
    }

    #[test]
    fn parses_minimal_valid_request_with_scope() {
        let req = parse(minimal_valid_scope()).expect("should parse");
        assert_eq!(req.response_type, ResponseType::VpToken);
        assert_eq!(req.nonce, "n-0S6_WzA2Mj");
        assert_eq!(req.scope.as_deref(), Some("openid"));
        assert!(req.dcql_query.is_none());
    }

    #[test]
    fn parses_request_with_optional_fields() {
        let mut v = minimal_valid_dcql();
        v["state"] = json!("xyz-state");
        v["request_uri"] = json!("https://verifier.example.com/request");
        v["request_uri_method"] = json!("post");

        let req = parse(v).expect("should parse");
        assert_eq!(req.state.as_deref(), Some("xyz-state"));
        assert_eq!(req.request_uri_method, Some(RequestUriMethod::Post));
        assert!(req.request_uri.is_some());
    }

    #[test]
    fn parses_request_with_new_spec_fields() {
        let mut v = minimal_valid_dcql();
        v["request"] = json!("eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ2ZXJpZmllciJ9");
        // base64url-encoded strings
        v["transaction_data"] = json!(["dHJhbnNhY3Rpb25fZGF0YQ"]);
        v["verifier_info"] = json!([{"format": "jwt_vc", "data": "eyJ0eXBlIjoidmVyaWZpZXIifQ"}]);

        let req = parse(v).expect("should parse");
        assert!(req.request.is_some());
        assert!(req.transaction_data.is_some());
        assert!(req.verifier_info.is_some());
    }

    #[test]
    fn rejects_vp_token_id_token_response_type() {
        let mut v = minimal_valid_dcql();
        v["response_type"] = json!("vp_token id_token");
        let err = parse(v).unwrap_err();
        assert!(err.to_string().contains("response_type"), "{err}");
    }

    #[test]
    fn rejects_unknown_response_type() {
        let mut v = minimal_valid_dcql();
        v["response_type"] = json!("code");
        assert!(parse(v).is_err());
    }

    #[test]
    fn rejects_id_token_only_response_type() {
        let mut v = minimal_valid_dcql();
        v["response_type"] = json!("id_token");
        assert!(parse(v).is_err());
    }

    #[test]
    fn parses_direct_post_jwt_response_mode() {
        let mut v = minimal_valid_dcql();
        v["response_mode"] = json!("direct_post.jwt");
        let req = parse(v).expect("should parse");
        assert_eq!(req.response_mode, ResponseMode::DirectPostJwt);
    }

    #[test]
    fn rejects_missing_response_mode() {
        let mut v = minimal_valid_dcql();
        v.as_object_mut().unwrap().remove("response_mode");
        let err = parse(v).unwrap_err();
        assert!(err.to_string().contains("response_mode"), "{err}");
    }

    #[test]
    fn parses_dc_api_response_mode_with_expected_origins() {
        let v = json!({
            "response_type": "vp_token",
            "client_id": "https://verifier.example.com",
            "response_mode": "dc_api",
            "nonce": "n-0S6_WzA2Mj",
            "expected_origins": ["https://app.example.com"],
            "dcql_query": {
                "credentials": [{
                    "id": "pid",
                    "format": "dc+sd-jwt",
                    "meta": { "vct_values": ["https://credentials.example.com/identity"] }
                }]
            }
        });
        let req = parse(v).expect("should parse dc_api");
        assert_eq!(req.response_mode, ResponseMode::DcApi);
        assert!(req.expected_origins.is_some());
    }

    #[test]
    fn parses_dc_api_jwt_response_mode() {
        let v = json!({
            "response_type": "vp_token",
            "client_id": "https://verifier.example.com",
            "response_mode": "dc_api.jwt",
            "nonce": "abc123",
            "expected_origins": ["https://app.example.com"],
            "dcql_query": {
                "credentials": [{
                    "id": "pid",
                    "format": "dc+sd-jwt",
                    "meta": { "vct_values": ["https://credentials.example.com/identity"] }
                }]
            }
        });
        let req = parse(v).expect("should parse dc_api.jwt");
        assert_eq!(req.response_mode, ResponseMode::DcApiJwt);
    }

    #[test]
    fn rejects_dc_api_without_expected_origins() {
        let v = json!({
            "response_type": "vp_token",
            "client_id": "https://verifier.example.com",
            "response_mode": "dc_api",
            "nonce": "abc123",
            "dcql_query": {
                "credentials": [{
                    "id": "pid",
                    "format": "dc+sd-jwt",
                    "meta": { "vct_values": ["https://example.com"] }
                }]
            }
        });
        let err = parse(v).unwrap_err();
        assert!(err.to_string().contains("expected_origins"), "{err}");
    }

    #[test]
    fn rejects_dc_api_with_empty_expected_origins() {
        let v = json!({
            "response_type": "vp_token",
            "client_id": "https://verifier.example.com",
            "response_mode": "dc_api",
            "nonce": "abc123",
            "expected_origins": [],
            "dcql_query": {
                "credentials": [{
                    "id": "pid",
                    "format": "dc+sd-jwt",
                    "meta": { "vct_values": ["https://example.com"] }
                }]
            }
        });
        let err = parse(v).unwrap_err();
        assert!(err.to_string().contains("expected_origins"), "{err}");
    }

    #[test]
    fn rejects_empty_client_id() {
        let mut v = minimal_valid_dcql();
        v["client_id"] = json!("");
        let err = parse(v).unwrap_err();
        assert!(err.to_string().contains("client_id"), "{err}");
    }

    #[test]
    fn rejects_whitespace_only_client_id() {
        let mut v = minimal_valid_dcql();
        v["client_id"] = json!("   ");
        assert!(parse(v).is_err());
    }

    #[test]
    fn rejects_empty_nonce() {
        let mut v = minimal_valid_dcql();
        v["nonce"] = json!("");
        let err = parse(v).unwrap_err();
        assert!(err.to_string().contains("nonce"), "{err}");
    }

    #[test]
    fn rejects_whitespace_only_nonce() {
        let mut v = minimal_valid_dcql();
        v["nonce"] = json!("   ");
        assert!(parse(v).is_err());
    }

    #[test]
    fn rejects_nonce_with_non_ascii_chars() {
        let mut v = minimal_valid_dcql();
        v["nonce"] = json!("nön_ascii");
        let err = parse(v).unwrap_err();
        assert!(
            err.to_string().contains("nonce") || err.to_string().contains("unreserved"),
            "{err}"
        );
    }

    #[test]
    fn rejects_nonce_with_special_chars() {
        let mut v = minimal_valid_dcql();
        v["nonce"] = json!("nonce with spaces");
        assert!(parse(v).is_err());
    }

    #[test]
    fn rejects_nonce_with_url_unsafe_chars() {
        let mut v = minimal_valid_dcql();
        v["nonce"] = json!("nonce+plus");
        assert!(parse(v).is_err());
    }

    #[test]
    fn accepts_nonce_with_period_and_tilde() {
        // comment 3: period and tilde are valid unreserved URI characters
        let mut v = minimal_valid_dcql();
        v["nonce"] = json!("nonce.with~tilde");
        let req = parse(v).expect("period and tilde should be accepted in nonce");
        assert_eq!(req.nonce, "nonce.with~tilde");
    }

    #[test]
    fn accepts_valid_url_safe_nonce() {
        let mut v = minimal_valid_dcql();
        v["nonce"] = json!("valid-nonce_123ABC");
        let req = parse(v).expect("should parse");
        assert_eq!(req.nonce, "valid-nonce_123ABC");
    }

    #[test]
    fn rejects_state_with_invalid_chars() {
        // comment 3: state is also subject to unreserved char constraint
        let mut v = minimal_valid_dcql();
        v["state"] = json!("state with spaces");
        let err = parse(v).unwrap_err();
        assert!(err.to_string().contains("state"), "{err}");
    }

    #[test]
    fn accepts_state_with_period_and_tilde() {
        let mut v = minimal_valid_dcql();
        v["state"] = json!("state.ok~here");
        let req = parse(v).expect("should parse");
        assert_eq!(req.state.as_deref(), Some("state.ok~here"));
    }

    #[test]
    fn rejects_request_uri_method_without_request_uri() {
        // comment 5: must be an error, not silently dropped
        let mut v = minimal_valid_dcql();
        v["request_uri_method"] = json!("post");
        // No request_uri provided
        let err = parse(v).unwrap_err();
        assert!(
            err.to_string().contains("request_uri_method"),
            "error should mention 'request_uri_method': {err}"
        );
    }

    #[test]
    fn request_uri_method_preserved_when_request_uri_present() {
        let mut v = minimal_valid_dcql();
        v["request_uri"] = json!("https://verifier.example.com/request");
        v["request_uri_method"] = json!("post");
        let req = parse(v).expect("should parse");
        assert_eq!(req.request_uri_method, Some(RequestUriMethod::Post));
    }

    #[test]
    fn rejects_both_scope_and_dcql_query() {
        let mut v = minimal_valid_dcql();
        v["scope"] = json!("openid");
        let err = parse(v).unwrap_err();
        assert!(err.to_string().contains("mutually exclusive"), "{err}");
    }

    #[test]
    fn rejects_neither_scope_nor_dcql_query() {
        let mut v = minimal_valid_dcql();
        v.as_object_mut().unwrap().remove("dcql_query");
        let err = parse(v).unwrap_err();
        assert!(
            err.to_string().contains("scope") || err.to_string().contains("dcql_query"),
            "{err}"
        );
    }

    #[test]
    fn rejects_empty_dcql_credentials_array() {
        let mut v = minimal_valid_dcql();
        v["dcql_query"] = json!({ "credentials": [] });
        let err = parse(v).unwrap_err();
        assert!(err.to_string().contains("credentials"), "{err}");
    }

    #[test]
    fn rejects_dcql_query_with_empty_credential_id() {
        let mut v = minimal_valid_dcql();
        v["dcql_query"] = json!({
            "credentials": [{ "id": "", "format": "dc+sd-jwt", "meta": { "vct_values": ["x"] } }]
        });
        assert!(parse(v).is_err());
    }

    #[test]
    fn rejects_dcql_query_with_invalid_credential_id_chars() {
        // comment 6: id must be alphanumeric + _ + -
        let mut v = minimal_valid_dcql();
        v["dcql_query"] = json!({
            "credentials": [{ "id": "inv@lid!", "format": "dc+sd-jwt", "meta": { "vct_values": ["x"] } }]
        });
        let err = parse(v).unwrap_err();
        assert!(err.to_string().contains("id"), "{err}");
    }

    #[test]
    fn rejects_duplicate_credential_ids() {
        // comment 6: IDs must be unique
        let mut v = minimal_valid_dcql();
        v["dcql_query"] = json!({
            "credentials": [
                { "id": "dup", "format": "dc+sd-jwt", "meta": { "vct_values": ["x"] } },
                { "id": "dup", "format": "dc+sd-jwt", "meta": { "vct_values": ["y"] } }
            ]
        });
        let err = parse(v).unwrap_err();
        assert!(err.to_string().contains("unique"), "{err}");
    }

    #[test]
    fn rejects_dcql_query_with_empty_credential_format() {
        let mut v = minimal_valid_dcql();
        v["dcql_query"] = json!({
            "credentials": [{ "id": "pid", "format": "", "meta": { "vct_values": ["x"] } }]
        });
        assert!(parse(v).is_err());
    }

    #[test]
    fn rejects_dc_sd_jwt_missing_vct_values() {
        // comment 7: dc+sd-jwt format requires meta.vct_values
        let mut v = minimal_valid_dcql();
        v["dcql_query"] = json!({
            "credentials": [{ "id": "pid", "format": "dc+sd-jwt", "meta": {} }]
        });
        let err = parse(v).unwrap_err();
        assert!(err.to_string().contains("vct_values"), "{err}");
    }

    #[test]
    fn rejects_dc_sd_jwt_empty_vct_values() {
        let mut v = minimal_valid_dcql();
        v["dcql_query"] = json!({
            "credentials": [{ "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": [] } }]
        });
        let err = parse(v).unwrap_err();
        assert!(err.to_string().contains("vct_values"), "{err}");
    }

    #[test]
    fn rejects_dc_sd_jwt_non_string_vct_values() {
        let mut v = minimal_valid_dcql();
        v["dcql_query"] = json!({
            "credentials": [{ "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": [123] } }]
        });
        let err = parse(v).unwrap_err();
        assert!(err.to_string().contains("vct_values"), "{err}");
    }

    #[test]
    fn accepts_non_sd_jwt_format_without_vct_values() {
        // meta validation is only applied to dc+sd-jwt
        let v = json!({
            "response_type": "vp_token",
            "client_id": "https://verifier.example.com",
            "response_mode": "direct_post",
            "response_uri": "https://verifier.example.com/response",
            "nonce": "abc123",
            "dcql_query": {
                "credentials": [{
                    "id": "mdl",
                    "format": "mso_mdoc",
                    "meta": { "doctype_value": "org.iso.18013.5.1.mDL" }
                }]
            }
        });
        assert!(parse(v).is_ok());
    }

    #[test]
    fn accepts_credential_query_with_multiple_true() {
        // comment 10
        let mut v = minimal_valid_dcql();
        v["dcql_query"] = json!({
            "credentials": [{
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["https://example.com"] },
                "multiple": true
            }]
        });
        let req = parse(v).expect("should parse");
        assert_eq!(req.dcql_query.unwrap().credentials[0].multiple, Some(true));
    }

    #[test]
    fn accepts_credential_query_with_trusted_authorities() {
        // comment 11
        let mut v = minimal_valid_dcql();
        v["dcql_query"] = json!({
            "credentials": [{
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["https://example.com"] },
                "trusted_authorities": [{ "type": "aki", "value": "abc123" }]
            }]
        });
        let req = parse(v).expect("should parse");
        assert!(
            req.dcql_query.unwrap().credentials[0]
                .trusted_authorities
                .is_some()
        );
    }

    #[test]
    fn accepts_require_cryptographic_holder_binding_false() {
        // comment 11
        let mut v = minimal_valid_dcql();
        v["dcql_query"] = json!({
            "credentials": [{
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["https://example.com"] },
                "require_cryptographic_holder_binding": false
            }]
        });
        let req = parse(v).expect("should parse");
        assert_eq!(
            req.dcql_query.unwrap().credentials[0].require_cryptographic_holder_binding,
            Some(false)
        );
    }

    #[test]
    fn rejects_claim_sets_without_claims() {
        // comment 12: claim_sets MUST NOT be present when claims is absent
        let mut v = minimal_valid_dcql();
        v["dcql_query"] = json!({
            "credentials": [{
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["https://example.com"] },
                "claim_sets": [["given_name"]]
            }]
        });
        let err = parse(v).unwrap_err();
        assert!(err.to_string().contains("claim_sets"), "{err}");
    }

    #[test]
    fn rejects_claims_without_id_when_claim_sets_present() {
        // comment 12: claims must have id when claim_sets is present
        let mut v = minimal_valid_dcql();
        v["dcql_query"] = json!({
            "credentials": [{
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["https://example.com"] },
                "claims": [{ "path": ["given_name"] }],
                "claim_sets": [["some_id"]]
            }]
        });
        let err = parse(v).unwrap_err();
        assert!(err.to_string().contains("id"), "{err}");
    }

    #[test]
    fn rejects_claim_sets_referencing_unknown_claim_id() {
        let mut v = minimal_valid_dcql();
        v["dcql_query"] = json!({
            "credentials": [{
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["https://example.com"] },
                "claims": [{ "path": ["given_name"], "id": "gn" }],
                "claim_sets": [["unknown_id"]]
            }]
        });
        let err = parse(v).unwrap_err();
        assert!(
            err.to_string().contains("unknown_id") || err.to_string().contains("claim"),
            "{err}"
        );
    }

    #[test]
    fn accepts_valid_claims_with_claim_sets() {
        // comment 12: valid combination
        let mut v = minimal_valid_dcql();
        v["dcql_query"] = json!({
            "credentials": [{
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["https://example.com"] },
                "claims": [
                    { "path": ["given_name"], "id": "gn" },
                    { "path": ["family_name"], "id": "fn" }
                ],
                "claim_sets": [["gn"], ["gn", "fn"]]
            }]
        });
        assert!(parse(v).is_ok());
    }

    #[test]
    fn rejects_claims_with_empty_path() {
        // comment 8: path must be non-empty
        let mut v = minimal_valid_dcql();
        v["dcql_query"] = json!({
            "credentials": [{
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["https://example.com"] },
                "claims": [{ "path": [] }]
            }]
        });
        let err = parse(v).unwrap_err();
        assert!(err.to_string().contains("path"), "{err}");
    }

    #[test]
    fn rejects_claims_with_empty_values_array() {
        // comment 8: values must be non-empty when present
        let mut v = minimal_valid_dcql();
        v["dcql_query"] = json!({
            "credentials": [{
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["https://example.com"] },
                "claims": [{ "path": ["given_name"], "values": [] }]
            }]
        });
        let err = parse(v).unwrap_err();
        assert!(err.to_string().contains("values"), "{err}");
    }

    #[test]
    fn rejects_duplicate_claim_ids() {
        // comment 8: claim ids must be unique
        let mut v = minimal_valid_dcql();
        v["dcql_query"] = json!({
            "credentials": [{
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["https://example.com"] },
                "claims": [
                    { "path": ["given_name"], "id": "dup" },
                    { "path": ["family_name"], "id": "dup" }
                ]
            }]
        });
        let err = parse(v).unwrap_err();
        assert!(err.to_string().contains("unique"), "{err}");
    }

    #[test]
    fn accepts_valid_credential_sets() {
        // comment 9
        let v = json!({
            "response_type": "vp_token",
            "client_id": "https://verifier.example.com",
            "response_mode": "direct_post",
            "response_uri": "https://verifier.example.com/response",
            "nonce": "abc123",
            "dcql_query": {
                "credentials": [
                    { "id": "id1", "format": "dc+sd-jwt", "meta": { "vct_values": ["x"] } },
                    { "id": "id2", "format": "dc+sd-jwt", "meta": { "vct_values": ["y"] } }
                ],
                "credential_sets": [
                    { "options": [["id1"], ["id2"]], "required": true }
                ]
            }
        });
        assert!(parse(v).is_ok());
    }

    #[test]
    fn rejects_credential_sets_with_empty_options() {
        // comment 9
        let v = json!({
            "response_type": "vp_token",
            "client_id": "https://verifier.example.com",
            "response_mode": "direct_post",
            "response_uri": "https://verifier.example.com/response",
            "nonce": "abc123",
            "dcql_query": {
                "credentials": [
                    { "id": "id1", "format": "dc+sd-jwt", "meta": { "vct_values": ["x"] } }
                ],
                "credential_sets": [
                    { "options": [] }
                ]
            }
        });
        let err = parse(v).unwrap_err();
        assert!(err.to_string().contains("options"), "{err}");
    }

    #[test]
    fn rejects_credential_sets_referencing_unknown_credential_id() {
        // comment 9
        let v = json!({
            "response_type": "vp_token",
            "client_id": "https://verifier.example.com",
            "response_mode": "direct_post",
            "response_uri": "https://verifier.example.com/response",
            "nonce": "abc123",
            "dcql_query": {
                "credentials": [
                    { "id": "id1", "format": "dc+sd-jwt", "meta": { "vct_values": ["x"] } }
                ],
                "credential_sets": [
                    { "options": [["unknown_id"]] }
                ]
            }
        });
        let err = parse(v).unwrap_err();
        assert!(
            err.to_string().contains("unknown_id") || err.to_string().contains("credential"),
            "{err}"
        );
    }

    #[test]
    fn rejects_empty_transaction_data_array() {
        let mut v = minimal_valid_dcql();
        v["transaction_data"] = json!([]);
        let err = parse(v).unwrap_err();
        assert!(err.to_string().contains("transaction_data"), "{err}");
    }

    #[test]
    fn rejects_invalid_base64url_in_transaction_data() {
        let mut v = minimal_valid_dcql();
        // contains '+' and '/' which are standard base64 but NOT base64url
        v["transaction_data"] = json!(["not+valid/base64url=="]);
        let err = parse(v).unwrap_err();
        assert!(err.to_string().contains("transaction_data"), "{err}");
    }

    #[test]
    fn accepts_valid_base64url_transaction_data() {
        let mut v = minimal_valid_dcql();
        v["transaction_data"] = json!(["dHJhbnNhY3Rpb25fZGF0YQ", "YW5vdGhlcl9lbnRyeQ"]);
        let req = parse(v).expect("should parse");
        assert_eq!(req.transaction_data.unwrap().len(), 2);
    }

    #[test]
    fn rejects_empty_verifier_info_array() {
        let mut v = minimal_valid_dcql();
        v["verifier_info"] = json!([]);
        let err = parse(v).unwrap_err();
        assert!(err.to_string().contains("verifier_info"), "{err}");
    }

    #[test]
    fn rejects_verifier_info_with_empty_format() {
        let mut v = minimal_valid_dcql();
        v["verifier_info"] = json!([{ "format": "", "data": "abc" }]);
        let err = parse(v).unwrap_err();
        assert!(err.to_string().contains("format"), "{err}");
    }

    #[test]
    fn rejects_verifier_info_with_empty_credential_ids() {
        let mut v = minimal_valid_dcql();
        v["verifier_info"] = json!([{ "format": "jwt_vc", "data": "abc", "credential_ids": [] }]);
        let err = parse(v).unwrap_err();
        assert!(err.to_string().contains("credential_ids"), "{err}");
    }

    #[test]
    fn rejects_verifier_info_referencing_unknown_credential_id() {
        let mut v = minimal_valid_dcql();
        v["verifier_info"] = json!([{
            "format": "jwt_vc",
            "data": "abc",
            "credential_ids": ["unknown"]
        }]);
        let err = parse(v).unwrap_err();
        assert!(
            err.to_string().contains("unknown") || err.to_string().contains("credential"),
            "{err}"
        );
    }

    #[test]
    fn accepts_valid_verifier_info() {
        let mut v = minimal_valid_dcql();
        v["verifier_info"] = json!([{
            "format": "jwt_vc",
            "data": "eyJ0eXAiOiJKV1QifQ",
            "credential_ids": ["pid"]
        }]);
        let req = parse(v).expect("should parse");
        assert!(req.verifier_info.is_some());
    }

    #[test]
    fn rejects_missing_response_uri_for_direct_post() {
        let mut v = minimal_valid_dcql();
        v.as_object_mut().unwrap().remove("response_uri");
        let err = parse(v).unwrap_err();
        assert!(err.to_string().contains("response_uri"), "{err}");
    }

    #[test]
    fn rejects_redirect_uri_when_response_uri_present() {
        let mut v = minimal_valid_dcql();
        v["redirect_uri"] = json!("https://app.example.com/callback");
        let err = parse(v).unwrap_err();
        assert!(err.to_string().contains("redirect_uri"), "{err}");
    }

    #[test]
    fn rejects_both_redirect_and_response_uri_regardless_of_mode() {
        let v = json!({
            "response_type": "vp_token",
            "client_id": "https://verifier.example.com",
            "redirect_uri": "https://app.example.com/callback",
            "response_uri": "https://verifier.example.com/response",
            "nonce": "abc123",
            "response_mode": "direct_post",
            "dcql_query": { "credentials": [{ "id": "test", "format": "dc+sd-jwt", "meta": { "vct_values": ["x"] } }] }
        });
        assert!(parse(v).is_err());
    }

    #[test]
    fn parses_with_inline_client_metadata() {
        let mut v = minimal_valid_dcql();
        v["client_metadata"] = json!({ "vp_formats": { "dc+sd-jwt": { "alg": ["ES256"] } } });
        let req = parse(v).expect("should parse");
        assert!(req.client_metadata.is_some());
    }

    #[test]
    fn parses_with_client_metadata_uri() {
        let mut v = minimal_valid_dcql();
        v["client_metadata_uri"] = json!("https://verifier.example.com/client-metadata");
        let req = parse(v).expect("should parse");
        assert!(req.client_metadata_uri.is_some());
    }

    #[test]
    fn rejects_both_client_metadata_and_client_metadata_uri() {
        let mut v = minimal_valid_dcql();
        v["client_metadata"] = json!({ "vp_formats": {} });
        v["client_metadata_uri"] = json!("https://verifier.example.com/client-metadata");
        let err = parse(v).unwrap_err();
        assert!(err.to_string().contains("client_metadata"), "{err}");
    }

    #[test]
    fn serde_roundtrip() {
        let req = parse(minimal_valid_dcql()).expect("should parse");
        let serialized = serde_json::to_string(&req).expect("should serialize");
        let deserialized: AuthorizationRequest =
            serde_json::from_str(&serialized).expect("should round-trip");
        assert_eq!(req.nonce, deserialized.nonce);
        assert_eq!(req.response_type, deserialized.response_type);
        assert_eq!(req.client_id, deserialized.client_id);
    }

    #[test]
    fn validate_succeeds_on_valid_constructed_request_with_dcql() {
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
                    format: "dc+sd-jwt".to_string(),
                    multiple: None,
                    meta: Some(serde_json::json!({ "vct_values": ["https://example.com"] })),
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
    fn validate_succeeds_on_valid_constructed_request_with_scope() {
        let req = AuthorizationRequest {
            response_type: ResponseType::VpToken,
            client_id: "https://verifier.example.com".to_string(),
            redirect_uri: None,
            scope: Some("openid".to_string()),
            state: None,
            nonce: "fresh-nonce".to_string(),
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
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn validate_returns_error_for_empty_client_id_on_constructed_value() {
        let req = AuthorizationRequest {
            response_type: ResponseType::VpToken,
            client_id: String::new(),
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
                    format: "dc+sd-jwt".to_string(),
                    multiple: None,
                    meta: Some(serde_json::json!({ "vct_values": ["https://example.com"] })),
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
        let err = req.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidPresentationRequest);
        assert!(err.to_string().contains("client_id"));
    }

    #[test]
    fn validate_returns_error_for_invalid_nonce_chars_on_constructed_value() {
        let req = AuthorizationRequest {
            response_type: ResponseType::VpToken,
            client_id: "https://verifier.example.com".to_string(),
            redirect_uri: None,
            scope: None,
            state: None,
            nonce: "invalid nonce!".to_string(),
            response_mode: ResponseMode::DirectPost,
            response_uri: Some(Url::parse("https://verifier.example.com/response").unwrap()),
            request_uri: None,
            request_uri_method: None,
            dcql_query: Some(DcqlQuery {
                credentials: vec![CredentialQuery {
                    id: "test-id".to_string(),
                    format: "dc+sd-jwt".to_string(),
                    multiple: None,
                    meta: Some(serde_json::json!({ "vct_values": ["https://example.com"] })),
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
        let err = req.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidPresentationRequest);
        assert!(err.to_string().contains("nonce"));
    }

    #[test]
    fn validate_returns_error_for_empty_nonce_on_constructed_value() {
        let req = AuthorizationRequest {
            response_type: ResponseType::VpToken,
            client_id: "https://verifier.example.com".to_string(),
            redirect_uri: None,
            scope: None,
            state: None,
            nonce: String::new(),
            response_mode: ResponseMode::DirectPost,
            response_uri: Some(Url::parse("https://verifier.example.com/response").unwrap()),
            request_uri: None,
            request_uri_method: None,
            dcql_query: Some(DcqlQuery {
                credentials: vec![CredentialQuery {
                    id: "test-id".to_string(),
                    format: "dc+sd-jwt".to_string(),
                    multiple: None,
                    meta: Some(serde_json::json!({ "vct_values": ["https://example.com"] })),
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
        let err = req.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidPresentationRequest);
    }

    #[test]
    fn response_type_display() {
        assert_eq!(ResponseType::VpToken.to_string(), "vp_token");
        assert_eq!(
            ResponseType::VpTokenIdToken.to_string(),
            "vp_token id_token"
        );
    }

    #[test]
    fn response_mode_display() {
        assert_eq!(ResponseMode::DirectPost.to_string(), "direct_post");
        assert_eq!(ResponseMode::DirectPostJwt.to_string(), "direct_post.jwt");
        assert_eq!(ResponseMode::DcApi.to_string(), "dc_api");
        assert_eq!(ResponseMode::DcApiJwt.to_string(), "dc_api.jwt");
    }

    #[test]
    fn request_uri_method_display() {
        assert_eq!(RequestUriMethod::Get.to_string(), "get");
        assert_eq!(RequestUriMethod::Post.to_string(), "post");
    }

    #[test]
    fn request_uri_method_default_is_get() {
        assert_eq!(RequestUriMethod::default(), RequestUriMethod::Get);
    }
}
