use std::collections::BTreeMap;

use serde::{Serialize, Serializer};
use serde_with::skip_serializing_none;
use url::Url;

use crate::oid4vp::AuthorizationErrorCode;

/// A presentation value returned for one DCQL Credential Query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Presentation {
    /// A compact presentation string, such as an SD-JWT VC presentation.
    String(String),

    /// A JSON object presentation, such as a JSON-based verifiable presentation.
    Object(serde_json::Map<String, serde_json::Value>),
}

/// A VP token returned in an OpenID4VP authorization response.
///
/// Per the spec, the value is a JSON object keyed by `CredentialQuery.id`,
/// where each entry contains one or more presentations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct VpToken {
    entries: BTreeMap<String, Vec<Presentation>>,
}

impl VpToken {
    /// Creates a new VP token from DCQL query entries.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The entries map is empty
    /// - Any query ID is not a valid DCQL credential query identifier
    /// - Any presentation array is empty
    pub fn new(entries: BTreeMap<String, Vec<Presentation>>) -> Result<Self, String> {
        if entries.is_empty() {
            return Err("vp_token must contain at least one credential query entry".to_string());
        }

        for (query_id, presentations) in &entries {
            if !is_valid_dcql_query_id(query_id) {
                return Err(format!(
                    "vp_token entry '{query_id}' is not a valid DCQL credential query id"
                ));
            }

            if presentations.is_empty() {
                return Err(format!(
                    "vp_token entry '{query_id}' must contain at least one presentation"
                ));
            }
        }

        Ok(Self { entries })
    }

    /// Returns the underlying DCQL entries.
    pub fn entries(&self) -> &BTreeMap<String, Vec<Presentation>> {
        &self.entries
    }
}

fn is_valid_dcql_query_id(query_id: &str) -> bool {
    !query_id.is_empty()
        && query_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

/// Authorization Response parameters for OpenID4VP.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum AuthorizationResponse {
    /// Successful Authorization Response parameters.
    Success(AuthorizationSuccessResponse),

    /// Authorization Error Response parameters.
    Error(AuthorizationErrorResponse),
}

impl AuthorizationResponse {
    /// Creates a new successful authorization response with a VP token.
    pub fn new(vp_token: VpToken) -> Self {
        Self::Success(AuthorizationSuccessResponse::new(vp_token))
    }

    /// Creates a new authorization error response.
    pub fn error(error: AuthorizationErrorCode) -> Self {
        Self::Error(AuthorizationErrorResponse::new(error))
    }

    /// Adds a state value to the response.
    pub fn with_state(mut self, state: impl Into<String>) -> Self {
        match &mut self {
            Self::Success(response) => response.state = Some(state.into()),
            Self::Error(response) => response.state = Some(state.into()),
        }
        self
    }

    /// Returns a helper that serializes `vp_token` as a JSON string for
    /// `application/x-www-form-urlencoded` `direct_post`.
    pub fn as_direct_post_form(&self) -> DirectPostAuthorizationResponse<'_> {
        DirectPostAuthorizationResponse { response: self }
    }
}

/// Successful Authorization Response parameters for OpenID4VP.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthorizationSuccessResponse {
    /// The VP token returned to the Verifier.
    vp_token: Option<VpToken>,

    /// Optional ID Token returned when the response type includes `id_token`.
    id_token: Option<String>,

    /// Optional authorization code returned when the response type includes `code`.
    code: Option<String>,

    /// Optional issuer identifier returned by response types that define it.
    iss: Option<String>,

    /// Optional state value echoed from the authorization request.
    state: Option<String>,
}

impl AuthorizationSuccessResponse {
    /// Creates a successful response with a VP token.
    pub fn new(vp_token: VpToken) -> Self {
        Self {
            vp_token: Some(vp_token),
            id_token: None,
            code: None,
            iss: None,
            state: None,
        }
    }

    /// Creates a successful response with an authorization code.
    pub fn code(code: impl Into<String>) -> Self {
        Self {
            vp_token: None,
            id_token: None,
            code: Some(code.into()),
            iss: None,
            state: None,
        }
    }

    /// Adds an ID Token to the response.
    pub fn with_id_token(mut self, id_token: impl Into<String>) -> Self {
        self.id_token = Some(id_token.into());
        self
    }

    /// Adds an authorization code to the response.
    pub fn with_code(mut self, code: impl Into<String>) -> Self {
        self.code = Some(code.into());
        self
    }

    /// Adds an issuer identifier to the response.
    pub fn with_iss(mut self, iss: impl Into<String>) -> Self {
        self.iss = Some(iss.into());
        self
    }

    /// Adds a state value to the response.
    pub fn with_state(mut self, state: impl Into<String>) -> Self {
        self.state = Some(state.into());
        self
    }
}

/// Authorization Error Response parameters for OpenID4VP.
///
/// Per Section 8.5 of the OpenID4VP specification, error responses follow the
/// OAuth 2.0 error response format defined in RFC 6749 Section 4.1.2.1.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthorizationErrorResponse {
    /// Error code describing why the request could not be completed.
    error: AuthorizationErrorCode,

    /// Human-readable ASCII text providing additional information about the error.
    ///
    /// Per RFC 6749, this is optional and used to provide additional information
    /// beyond what the error code indicates.
    error_description: Option<String>,

    /// URI identifying a human-readable web page with information about the error.
    ///
    /// Per RFC 6749, this is optional and provides a way to link to more detailed
    /// error documentation.
    error_uri: Option<String>,

    /// Optional state value echoed from the authorization request.
    state: Option<String>,
}

impl AuthorizationErrorResponse {
    /// Creates an authorization error response with just an error code.
    pub fn new(error: AuthorizationErrorCode) -> Self {
        Self {
            error,
            error_description: None,
            error_uri: None,
            state: None,
        }
    }

    /// Adds a human-readable error description to the response.
    pub fn with_error_description(mut self, description: impl Into<String>) -> Self {
        self.error_description = Some(description.into());
        self
    }

    /// Adds a URI pointing to additional error information to the response.
    pub fn with_error_uri(mut self, uri: impl Into<String>) -> Self {
        self.error_uri = Some(uri.into());
        self
    }

    /// Adds a state value to the response.
    pub fn with_state(mut self, state: impl Into<String>) -> Self {
        self.state = Some(state.into());
        self
    }
}

/// Form-encoding helper for `direct_post` authorization responses.
#[derive(Debug, Clone, Copy)]
pub struct DirectPostAuthorizationResponse<'a> {
    response: &'a AuthorizationResponse,
}

impl Serialize for DirectPostAuthorizationResponse<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.response {
            AuthorizationResponse::Success(response) => {
                DirectPostAuthorizationSuccessResponse::new(response).serialize(serializer)
            }
            AuthorizationResponse::Error(response) => response.serialize(serializer),
        }
    }
}

#[skip_serializing_none]
#[derive(Serialize)]
struct DirectPostAuthorizationSuccessResponse<'a> {
    #[serde(serialize_with = "serialize_optional_vp_token_as_json_string")]
    vp_token: Option<&'a VpToken>,
    id_token: Option<&'a str>,
    code: Option<&'a str>,
    iss: Option<&'a str>,
    state: Option<&'a str>,
}

impl<'a> DirectPostAuthorizationSuccessResponse<'a> {
    fn new(response: &'a AuthorizationSuccessResponse) -> Self {
        Self {
            vp_token: response.vp_token.as_ref(),
            id_token: response.id_token.as_deref(),
            code: response.code.as_deref(),
            iss: response.iss.as_deref(),
            state: response.state.as_deref(),
        }
    }
}

/// Serializes an optional `VpToken` as a JSON string for `direct_post` form encoding.
///
/// This function is used by `DirectPostAuthorizationSuccessResponse` to serialize
/// the `vp_token` field as a JSON string (rather than a nested JSON object),
/// as required by the `application/x-www-form-urlencoded` format.
fn serialize_optional_vp_token_as_json_string<S>(
    vp_token: &Option<&VpToken>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match vp_token {
        Some(vp_token) => serializer.serialize_str(
            &serde_json::to_string(vp_token.entries()).map_err(serde::ser::Error::custom)?,
        ),
        None => serializer.serialize_none(),
    }
}

/// A compact JWE (JSON Web Encryption) string in the form `HEADER.ENCRYPTED_KEY.IV.CIPHERTEXT.TAG`.
///
/// Per RFC 7516 Section 3.1, a JWE consists of five parts separated by dots:
/// - Protected header (always required, non-empty)
/// - Encrypted key (may be empty for algorithms like ECDH-ES that don't use a separate key)
/// - Initialization vector (may be empty for algorithms that don't use an IV)
/// - Ciphertext (always required, non-empty)
/// - Authentication tag (may be empty for algorithms that don't use an authentication tag)
///
/// This type validates the structural shape at construction time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompactJwe(String);

impl CompactJwe {
    /// Creates a new `CompactJwe` from a string.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The string is empty or contains only whitespace
    /// - The string does not contain exactly 5 dot-separated parts
    /// - The protected header (first part) is empty
    /// - The ciphertext (fourth part) is empty
    pub fn new(jwe: impl Into<String>) -> Result<Self, String> {
        let jwe = jwe.into();
        if jwe.trim().is_empty() {
            return Err("JWE must not be empty".to_string());
        }

        let parts: Vec<&str> = jwe.split('.').collect();
        if parts.len() != 5 {
            return Err(format!(
                "JWE must have 5 dot-separated parts, found {}",
                parts.len()
            ));
        }

        // Protected header (first part) must always be present and non-empty
        if parts[0].is_empty() {
            return Err("JWE protected header (part 1) must not be empty".to_string());
        }

        // Encrypted key (second part) may be empty for algorithms like ECDH-ES
        // that use key agreement and don't have a separate encrypted key

        // IV (third part) may be empty for algorithms that don't use an IV

        // Ciphertext (fourth part) must always be present and non-empty
        if parts[3].is_empty() {
            return Err("JWE ciphertext (part 4) must not be empty".to_string());
        }

        // Authentication tag (fifth part) may be empty for algorithms that don't use an auth tag

        Ok(Self(jwe))
    }

    /// Returns the underlying JWE string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Form body for the `direct_post.jwt` response mode.
///
/// Per OpenID4VP Section 8.3, the `response` parameter contains an unsigned encrypted JWT (JWE)
/// carrying the Authorization Response payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DirectPostJwtResponse {
    response: CompactJwe,
}

impl DirectPostJwtResponse {
    /// Creates a `direct_post.jwt` response form body.
    ///
    /// # Errors
    ///
    /// Returns an error if the response is not a valid compact JWE.
    pub fn new(response: impl Into<String>) -> Result<Self, String> {
        let jwe = CompactJwe::new(response)?;
        Ok(Self { response: jwe })
    }

    /// Returns the encrypted JWT response.
    pub fn response(&self) -> &str {
        self.response.as_str()
    }
}

/// Response to the verifier when the Wallet uses the `direct_post` response mode.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct DirectPostResponse {
    /// Optional redirect URI provided by the Verifier.
    pub redirect_uri: Option<Url>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn string_presentation(value: &str) -> Presentation {
        Presentation::String(value.to_string())
    }

    fn vp_token(entries: BTreeMap<String, Vec<Presentation>>) -> VpToken {
        VpToken::new(entries).expect("valid vp_token")
    }

    #[test]
    fn serializes_vp_token_with_single_entry_to_json_object() {
        let mut entries = BTreeMap::new();
        entries.insert(
            "my_credential".to_string(),
            vec![string_presentation("eyJhbGciOiJFUzI1NiJ9...")],
        );
        let token = vp_token(entries);

        let json = serde_json::to_value(&token).expect("serialize");

        assert_eq!(
            json,
            json!({
                "my_credential": ["eyJhbGciOiJFUzI1NiJ9..."]
            })
        );
    }

    #[test]
    fn serializes_vp_token_with_object_presentation() {
        let mut presentation = serde_json::Map::new();
        presentation.insert("format".to_string(), json!("ldp_vp"));

        let mut entries = BTreeMap::new();
        entries.insert(
            "my_credential".to_string(),
            vec![
                string_presentation("eyJhbGciOiJFUzI1NiJ9..."),
                Presentation::Object(presentation),
            ],
        );

        let token = vp_token(entries);

        let json = serde_json::to_value(&token).expect("serialize");

        assert_eq!(
            json,
            json!({
                "my_credential": ["eyJhbGciOiJFUzI1NiJ9...", {"format": "ldp_vp"}]
            })
        );
    }

    #[test]
    fn rejects_empty_vp_token_at_construction() {
        let err = VpToken::new(BTreeMap::new()).unwrap_err();
        assert!(
            err.to_string()
                .contains("at least one credential query entry")
        );
    }

    #[test]
    fn rejects_invalid_dcql_query_id_at_construction() {
        let mut entries = BTreeMap::new();
        entries.insert(
            "credential/1".to_string(),
            vec![string_presentation("vp-token-value")],
        );

        let err = VpToken::new(entries).unwrap_err();
        assert!(err.to_string().contains("valid DCQL credential query id"));
    }

    #[test]
    fn rejects_empty_presentation_list_at_construction() {
        let mut entries = BTreeMap::new();
        entries.insert("my_credential".to_string(), Vec::new());

        let err = VpToken::new(entries).unwrap_err();
        assert!(err.to_string().contains("at least one presentation"));
    }

    #[test]
    fn serializes_authorization_response_vp_token_as_json_object() {
        let mut entries = BTreeMap::new();
        entries.insert(
            "my_credential".to_string(),
            vec![string_presentation("eyJhbGciOiJFUzI1NiJ9...")],
        );

        let response = AuthorizationResponse::new(vp_token(entries)).with_state("state-123");

        let json = serde_json::to_value(&response).expect("serialize");

        assert_eq!(
            json,
            json!({
                "vp_token": {
                    "my_credential": ["eyJhbGciOiJFUzI1NiJ9..."]
                },
                "state": "state-123"
            })
        );
    }

    #[test]
    fn serializes_success_response_with_code_without_vp_token() {
        let response = AuthorizationResponse::Success(AuthorizationSuccessResponse::code("abc"))
            .with_state("xyz");

        let json = serde_json::to_value(&response).expect("serialize");

        assert_eq!(
            json,
            json!({
                "code": "abc",
                "state": "xyz"
            })
        );
    }

    #[test]
    fn serializes_error_response() {
        let response = AuthorizationResponse::error(AuthorizationErrorCode::WalletUnavailable)
            .with_state("state-123");

        let json = serde_json::to_value(&response).expect("serialize");

        assert_eq!(
            json,
            json!({
                "error": "wallet_unavailable",
                "state": "state-123"
            })
        );
    }

    #[test]
    fn serializes_error_response_with_state() {
        let response = AuthorizationErrorResponse::new(AuthorizationErrorCode::InvalidRequest)
            .with_state("state-123");

        let json = serde_json::to_value(&response).expect("serialize");

        assert_eq!(
            json,
            json!({
                "error": "invalid_request",
                "state": "state-123"
            })
        );
    }

    #[test]
    fn serializes_vp_token_via_direct_post_form_body() {
        let mut entries = BTreeMap::new();
        entries.insert(
            "my_credential".to_string(),
            vec![string_presentation("vp-token-value")],
        );

        let response = AuthorizationResponse::new(vp_token(entries)).with_state("state-123");

        let encoded =
            serde_urlencoded::to_string(response.as_direct_post_form()).expect("serialize");
        let params: BTreeMap<_, _> = url::form_urlencoded::parse(encoded.as_bytes())
            .into_owned()
            .collect();

        assert_eq!(
            params.get("vp_token"),
            Some(&r#"{"my_credential":["vp-token-value"]}"#.to_string())
        );
        assert_eq!(params.get("state"), Some(&"state-123".to_string()));
    }

    #[test]
    fn serializes_error_response_via_direct_post_form_body() {
        let response = AuthorizationResponse::error(AuthorizationErrorCode::AccessDenied)
            .with_state("state-123");

        let encoded =
            serde_urlencoded::to_string(response.as_direct_post_form()).expect("serialize");
        let params: BTreeMap<_, _> = url::form_urlencoded::parse(encoded.as_bytes())
            .into_owned()
            .collect();

        assert_eq!(params.get("error"), Some(&"access_denied".to_string()));
        assert_eq!(params.get("state"), Some(&"state-123".to_string()));
    }

    #[test]
    fn serializes_direct_post_jwt_response() {
        // Valid JWE format: 5 dot-separated parts
        let response =
            DirectPostJwtResponse::new("HEADER.ENCRYPTED_KEY.IV.CIPHERTEXT.TAG").unwrap();

        let encoded = serde_urlencoded::to_string(&response).expect("serialize");

        assert_eq!(encoded, "response=HEADER.ENCRYPTED_KEY.IV.CIPHERTEXT.TAG");
        assert_eq!(
            response.response(),
            "HEADER.ENCRYPTED_KEY.IV.CIPHERTEXT.TAG"
        );
    }

    #[test]
    fn rejects_empty_direct_post_jwt_response() {
        let err = DirectPostJwtResponse::new("  ").unwrap_err();

        assert!(err.contains("JWE must not be empty"));
    }

    #[test]
    fn rejects_jwe_with_wrong_number_of_parts() {
        // Only 3 parts
        let err = DirectPostJwtResponse::new("part1.part2.part3").unwrap_err();
        assert!(err.contains("JWE must have 5 dot-separated parts"));
        assert!(err.contains("found 3"));
    }

    #[test]
    fn accepts_jwe_with_empty_encrypted_key() {
        // ECDH-ES produces JWEs with empty encrypted key (second part)
        // Format: HEADER..IV.CIPHERTEXT.TAG
        let response = DirectPostJwtResponse::new("HEADER..IV.CIPHERTEXT.TAG").unwrap();
        assert_eq!(response.response(), "HEADER..IV.CIPHERTEXT.TAG");
    }

    #[test]
    fn rejects_jwe_with_empty_header() {
        // Header (first part) must always be present
        let err = DirectPostJwtResponse::new(".KEY.IV.CIPHERTEXT.TAG").unwrap_err();
        assert!(err.contains("protected header"));
    }

    #[test]
    fn rejects_jwe_with_empty_ciphertext() {
        // Ciphertext (fourth part) must always be present
        let err = DirectPostJwtResponse::new("HEADER.KEY.IV..TAG").unwrap_err();
        assert!(err.contains("ciphertext"));
    }

    #[test]
    fn serializes_direct_post_response() {
        let response = DirectPostResponse {
            redirect_uri: Some(
                Url::parse("https://client.example.org/cb#response_code=abc").unwrap(),
            ),
        };

        let json = serde_json::to_value(&response).expect("serialize");

        assert_eq!(
            json,
            json!({
                "redirect_uri": "https://client.example.org/cb#response_code=abc"
            })
        );
    }

    #[test]
    fn ignores_unknown_direct_post_response_parameters() {
        let response: DirectPostResponse = serde_json::from_value(json!({
            "redirect_uri": "https://client.example.org/cb#response_code=abc",
            "extension": "value"
        }))
        .expect("deserialize");

        assert_eq!(
            response.redirect_uri.as_ref().unwrap().as_str(),
            "https://client.example.org/cb#response_code=abc"
        );
    }
}
