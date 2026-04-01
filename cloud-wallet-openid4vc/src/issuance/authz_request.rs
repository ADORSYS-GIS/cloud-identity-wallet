//! Authorization Request models and builder for OpenID4VCI.
//!
//! This module implements the utilities to construct OAuth 2.0 authorization requests
//! as extended by OID4VCI (Section 5.1) and RFC 9396 (Rich Authorization Requests).
//!
//! # Spec References
//!
//! - [OID4VCI §5.1 Authorization Request](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-authorization-request)
//! - [RFC 9396 Rich Authorization Requests](https://www.rfc-editor.org/rfc/rfc9396.html)
//! - [RFC 7636 PKCE](https://www.rfc-editor.org/rfc/rfc7636.html)

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::errors::{Error, ErrorKind, Result};
use crate::issuance::claim_path_pointer::ClaimPathPointer;
use crate::issuance::issuer_metadata::CredentialIssuerMetadata;

/// The type of authorization detail.
///
/// For OID4VCI, this MUST be set to `openid_credential`.
/// See [OID4VCI §5.1.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-using-authorization-details).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationDetailType {
    /// Standard OID4VCI credential authorization type.
    OpenidCredential,
    /// Other custom or future authorization types.
    #[serde(untagged)]
    Other(String),
}

/// A claims description object for Authorization Details.
///
/// As defined in [OID4VCI Appendix B.1]. It defines the requirements for the claims
/// that the Wallet requests to be included in the Credential.
///
/// [OID4VCI Appendix B.1]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-B.1
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimDescription {
    /// REQUIRED. Claim path pointer to identify the claim(s) in the Credential.
    pub path: ClaimPathPointer,

    /// OPTIONAL. Indicates that the Wallet will only accept a Credential that includes
    /// this claim. Default is `false`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub mandatory: bool,

    /// Catch-all for additional parameters.
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, Value>,
}

impl ClaimDescription {
    /// Creates a new `ClaimDescription` for a specific path.
    pub fn new(path: ClaimPathPointer) -> Self {
        Self {
            path,
            mandatory: false,
            extra: std::collections::HashMap::new(),
        }
    }

    /// Sets the `mandatory` field.
    pub fn with_mandatory(mut self, mandatory: bool) -> Self {
        self.mandatory = mandatory;
        self
    }
}

/// Rich Authorization Request (RAR) detail object for OID4VCI.
///
/// As defined in [RFC 9396 §2](https://www.rfc-editor.org/rfc/rfc9396.html) and
/// [OID4VCI §5.1.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-using-authorization-details).
///
/// Per §5.1.1, `credential_configuration_id` is REQUIRED. If the Credential Issuer
/// metadata contains an `authorization_servers` parameter, the `locations` field MUST
/// be set to the Credential Issuer Identifier value.
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationDetail {
    /// REQUIRED. The type of authorization detail. MUST be `openid_credential`.
    #[serde(rename = "type")]
    pub r#type: AuthorizationDetailType,

    /// REQUIRED. Unique identifier of the Credential in the issuer's
    /// `credential_configurations_supported` map.
    pub credential_configuration_id: String,

    /// OPTIONAL. Array of Credential Issuer Identifier strings.
    /// MUST be set when the issuer metadata has an `authorization_servers` parameter,
    /// to allow the AS to identify which issuer is being targeted.
    pub locations: Option<Vec<String>>,

    /// OPTIONAL. Non-empty array of claims description objects restricting which claims
    /// to include in the issued Credential. See [OID4VCI Appendix B.1].
    pub claims: Option<Vec<ClaimDescription>>,

    /// Catch-all for additional parameters defined by extensions or profiles.
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, Value>,
}

impl AuthorizationDetail {
    /// Creates a new `AuthorizationDetail` specifying the credential by its configuration ID.
    ///
    /// This is the primary way to construct an authorization detail per [OID4VCI §5.1.1]:
    /// ```json
    /// [{ "type": "openid_credential", "credential_configuration_id": "UniversityDegreeCredential" }]
    /// ```
    pub fn for_configuration(id: impl Into<String>) -> Self {
        Self {
            r#type: AuthorizationDetailType::OpenidCredential,
            credential_configuration_id: id.into(),
            locations: None,
            claims: None,
            extra: std::collections::HashMap::new(),
        }
    }

    /// Sets the `locations` field.
    ///
    /// MUST be set when the issuer metadata contains an `authorization_servers` parameter,
    /// so the Authorization Server can identify the targeted Credential Issuer.
    pub fn with_locations(mut self, locations: Vec<String>) -> Self {
        self.locations = Some(locations);
        self
    }

    /// Restricts which claims to request in the issued Credential.
    pub fn with_claims(mut self, claims: Vec<ClaimDescription>) -> Self {
        self.claims = Some(claims);
        self
    }
}

/// PKCE code challenge method.
///
/// Only `S256` (SHA-256) is supported per [RFC 7636 §4.2](https://www.rfc-editor.org/rfc/rfc7636.html#section-4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum CodeChallengeMethod {
    /// SHA-256 code challenge (RFC 7636).
    #[default]
    S256,
}

impl std::fmt::Display for CodeChallengeMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::S256 => write!(f, "S256"),
        }
    }
}

/// PKCE (Proof Key for Code Exchange) parameters per [RFC 7636].
///
/// The `code_verifier` is kept secret and submitted at the Token Endpoint.
/// The `code_challenge` is included in the Authorization Request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkceParams {
    /// The secret random verifier string. MUST NOT be sent in the Authorization Request.
    pub code_verifier: String,
    /// The challenge derived from the verifier. Sent in the Authorization Request.
    pub code_challenge: String,
    /// The method used to derive the challenge.
    pub method: CodeChallengeMethod,
}

impl PkceParams {
    /// Generates new random PKCE parameters using S256.
    ///
    /// Generates 32 cryptographically random bytes, base64url-encodes them as the verifier,
    /// then derives `code_challenge = BASE64URL(SHA256(code_verifier))`.
    ///
    /// # Errors
    ///
    /// Returns an error if the system's cryptographically secure RNG is unavailable,
    /// which is rare but can occur on systems without proper entropy sources.
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes)
            .map_err(|e| Error::message(ErrorKind::InvalidAuthorizationRequest, e.to_string()))?;

        // verifier = base64url(random_bytes)
        let code_verifier = Base64UrlUnpadded::encode_string(&bytes);

        // challenge = base64url(sha256(verifier))
        let mut hasher = Sha256::new();
        hasher.update(code_verifier.as_bytes());
        let hash = hasher.finalize();
        let code_challenge = Base64UrlUnpadded::encode_string(&hash);

        Ok(Self {
            code_verifier,
            code_challenge,
            method: CodeChallengeMethod::S256,
        })
    }
}

/// An OAuth 2.0 Authorization Request for OID4VCI.
///
/// Compliant with [OID4VCI §5.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-authorization-request).
/// Use [`AuthorizationRequestBuilder`] to construct a valid instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRequest {
    /// Fixed to `"code"` for the Authorization Code flow.
    pub response_type: String,
    /// REQUIRED. The client identifier for the wallet.
    pub client_id: String,
    /// OPTIONAL. The redirect URI where the AS sends the user after consent.
    /// May be omitted if the client pre-registered a single redirect URI.
    pub redirect_uri: Option<String>,
    /// OPTIONAL. State value to maintain state between request and callback.
    pub state: Option<String>,
    /// OPTIONAL. Scope values requesting Credential issuance (space-separated).
    /// See [OID4VCI §5.1.2].
    pub scope: Option<String>,
    /// OPTIONAL. Processing context value originally received in a Credential Offer.
    /// Passed back to the Credential Issuer. See [OID4VCI §5.1.3].
    pub issuer_state: Option<String>,
    /// OPTIONAL. RAR authorization details requesting specific Credentials.
    /// See [OID4VCI §5.1.1].
    pub authorization_details: Option<Vec<AuthorizationDetail>>,
    /// OPTIONAL. PKCE code challenge (base64url-encoded SHA-256 of the verifier).
    pub code_challenge: Option<String>,
    /// OPTIONAL. PKCE challenge method. Will always be `S256` when present.
    pub code_challenge_method: Option<CodeChallengeMethod>,
    /// OPTIONAL. Resource indicator [RFC 8707]. RECOMMENDED when the issuer metadata
    /// contains an `authorization_servers` parameter (see [OID4VCI §5.1.2]).
    pub resource: Option<String>,
}

impl AuthorizationRequest {
    /// Converts the request parameters into a list of name-value pairs for a query string.
    ///
    /// Objects (e.g. `authorization_details`) are JSON-serialized as required by
    /// [OID4VCI §5.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-authorization-request).
    ///
    /// # Note
    ///
    /// Values are **not** percent-encoded. Callers constructing a URL query string
    /// are responsible for encoding each value (e.g., using `percent_encoding::utf8_percent_encode`).
    pub fn to_query_pairs(&self) -> Vec<(String, String)> {
        let mut pairs = Vec::new();
        pairs.push(("response_type".to_string(), self.response_type.clone()));
        pairs.push(("client_id".to_string(), self.client_id.clone()));

        if let Some(ref redirect_uri) = self.redirect_uri {
            pairs.push(("redirect_uri".to_string(), redirect_uri.clone()));
        }
        if let Some(ref state) = self.state {
            pairs.push(("state".to_string(), state.clone()));
        }
        if let Some(ref scope) = self.scope {
            pairs.push(("scope".to_string(), scope.clone()));
        }
        if let Some(ref issuer_state) = self.issuer_state {
            pairs.push(("issuer_state".to_string(), issuer_state.clone()));
        }
        if let Some(json) = self
            .authorization_details
            .as_ref()
            .and_then(|d| serde_json::to_string(d).ok())
        {
            pairs.push(("authorization_details".to_string(), json));
        }
        if let Some(ref code_challenge) = self.code_challenge {
            pairs.push(("code_challenge".to_string(), code_challenge.clone()));
        }
        if let Some(ref method) = self.code_challenge_method {
            pairs.push(("code_challenge_method".to_string(), method.to_string()));
        }
        if let Some(ref resource) = self.resource {
            pairs.push(("resource".to_string(), resource.clone()));
        }

        pairs
    }
}

/// Builder for constructing a spec-compliant [`AuthorizationRequest`].
///
/// # Validation
///
/// [`build`](Self::build) will return an error if:
/// - `client_id` is empty or blank
/// - Neither `scope` nor `authorization_details` is provided
///
/// # Example
///
/// ```
/// # use cloud_wallet_openid4vc::issuance::authorization_request::*;
/// let request = AuthorizationRequestBuilder::new("s6BhdRkqt3")
///     .with_redirect_uri("https://wallet.example.org/cb")
///     .with_authorization_detail(
///         AuthorizationDetail::for_configuration("UniversityDegreeCredential")
///     )
///     .with_pkce(PkceParams::generate().unwrap())
///     .build()
///     .unwrap();
/// assert_eq!(request.response_type, "code");
/// ```
pub struct AuthorizationRequestBuilder {
    client_id: String,
    redirect_uri: Option<String>,
    state: Option<String>,
    scope: Vec<String>,
    issuer_state: Option<String>,
    authorization_details: Vec<AuthorizationDetail>,
    pkce: Option<PkceParams>,
    resource: Option<String>,
}

impl AuthorizationRequestBuilder {
    /// Creates a new builder with the REQUIRED `client_id`.
    pub fn new(client_id: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
            redirect_uri: None,
            state: None,
            scope: Vec::new(),
            issuer_state: None,
            authorization_details: Vec::new(),
            pkce: None,
            resource: None,
        }
    }

    /// Sets the `redirect_uri` parameter.
    pub fn with_redirect_uri(mut self, redirect_uri: impl Into<String>) -> Self {
        self.redirect_uri = Some(redirect_uri.into());
        self
    }

    /// Sets the `state` parameter.
    pub fn with_state(mut self, state: impl Into<String>) -> Self {
        self.state = Some(state.into());
        self
    }

    /// Sets the `issuer_state` parameter, echoing the value from a Credential Offer.
    ///
    /// Per [OID4VCI §5.1.3], this passes the `issuer_state` value back to the Credential
    /// Issuer through the Authorization Server.
    pub fn with_issuer_state(mut self, issuer_state: impl Into<String>) -> Self {
        self.issuer_state = Some(issuer_state.into());
        self
    }

    /// Adds an OAuth 2.0 scope value for Credential issuance (§5.1.2).
    ///
    /// Multiple calls add multiple scope values; they will be space-joined on build.
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope.push(scope.into());
        self
    }

    /// Adds a RAR authorization detail for a specific Credential (§5.1.1).
    pub fn with_authorization_detail(mut self, detail: AuthorizationDetail) -> Self {
        self.authorization_details.push(detail);
        self
    }

    /// Attaches PKCE parameters to the request.
    ///
    /// PAR with PKCE is RECOMMENDED per [OID4VCI §5.1.4] to ensure confidentiality
    /// and integrity.
    pub fn with_pkce(mut self, pkce: PkceParams) -> Self {
        self.pkce = Some(pkce);
        self
    }

    /// Sets the `resource` parameter [RFC 8707].
    ///
    /// RECOMMENDED when the issuer metadata contains an `authorization_servers` parameter
    /// to help the AS differentiate between multiple Credential Issuers (§5.1.2).
    pub fn with_resource(mut self, resource: impl Into<String>) -> Self {
        self.resource = Some(resource.into());
        self
    }

    /// Builds the [`AuthorizationRequest`], validating that required fields are present.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::InvalidAuthorizationRequest`] if:
    /// - `client_id` is empty or blank
    /// - Neither `scope` nor `authorization_details` is provided
    pub fn build(self) -> Result<AuthorizationRequest> {
        if self.client_id.trim().is_empty() {
            return Err(Error::message(
                ErrorKind::InvalidAuthorizationRequest,
                "client_id must not be empty",
            ));
        }
        if self.scope.is_empty() && self.authorization_details.is_empty() {
            return Err(Error::message(
                ErrorKind::InvalidAuthorizationRequest,
                "at least one scope or authorization_detail must be provided",
            ));
        }

        Ok(AuthorizationRequest {
            response_type: "code".to_string(),
            client_id: self.client_id,
            redirect_uri: self.redirect_uri,
            state: self.state,
            scope: if self.scope.is_empty() {
                None
            } else {
                Some(self.scope.join(" "))
            },
            issuer_state: self.issuer_state,
            authorization_details: if self.authorization_details.is_empty() {
                None
            } else {
                Some(self.authorization_details)
            },
            code_challenge: self.pkce.as_ref().map(|p| p.code_challenge.clone()),
            code_challenge_method: self.pkce.as_ref().map(|p| p.method),
            resource: self.resource,
        })
    }
}

/// Looks up the scope value for a credential configuration ID in the issuer metadata.
///
/// Per [OID4VCI §5.1.2], a wallet discovers the scope string to use by finding the
/// `scope` field inside `credential_configurations_supported[config_id]`.
pub fn scope_for_credential_configuration<'a>(
    metadata: &'a CredentialIssuerMetadata,
    config_id: &str,
) -> Option<&'a str> {
    metadata
        .credential_configurations_supported
        .get(config_id)
        .and_then(|config| config.scope.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn builder_minimal_valid_with_scope() {
        let request = AuthorizationRequestBuilder::new("wallet-client")
            .with_scope("UniversityDegreeCredential")
            .build()
            .unwrap();

        assert_eq!(request.client_id, "wallet-client");
        assert_eq!(
            request.scope,
            Some("UniversityDegreeCredential".to_string())
        );
        assert_eq!(request.response_type, "code");
        // redirect_uri is OPTIONAL
        assert!(request.redirect_uri.is_none());
    }

    #[test]
    fn builder_with_redirect_uri() {
        let request = AuthorizationRequestBuilder::new("client")
            .with_redirect_uri("https://wallet.example.org/cb")
            .with_scope("openid")
            .build()
            .unwrap();

        assert_eq!(
            request.redirect_uri,
            Some("https://wallet.example.org/cb".to_string())
        );
    }

    #[test]
    fn builder_rejects_missing_authorization_source() {
        let res = AuthorizationRequestBuilder::new("client").build();
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().kind(),
            ErrorKind::InvalidAuthorizationRequest
        );
    }

    #[test]
    fn builder_rejects_blank_client_id() {
        let res = AuthorizationRequestBuilder::new("  ")
            .with_scope("openid")
            .build();
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().kind(),
            ErrorKind::InvalidAuthorizationRequest
        );
    }

    #[test]
    fn builder_with_pkce_contains_challenge() {
        let pkce = PkceParams::generate().unwrap();
        let chal = pkce.code_challenge.clone();

        let request = AuthorizationRequestBuilder::new("client")
            .with_scope("openid")
            .with_pkce(pkce)
            .build()
            .unwrap();

        assert_eq!(request.code_challenge, Some(chal));
        assert_eq!(
            request.code_challenge_method,
            Some(CodeChallengeMethod::S256)
        );
    }

    // ── AuthorizationDetail model ────────────────────────────────────────────

    #[test]
    fn rar_detail_ser_matches_spec_example() {
        // OID4VCI §5.1.1 non-normative example:
        // [{ "type": "openid_credential", "credential_configuration_id": "UniversityDegreeCredential" }]
        let detail = AuthorizationDetail::for_configuration("UniversityDegreeCredential");
        let json = serde_json::to_value(&detail).unwrap();

        assert_eq!(json["type"], "openid_credential");
        assert_eq!(
            json["credential_configuration_id"],
            "UniversityDegreeCredential"
        );
        // `format` must NOT appear — it is not part of the final OID4VCI spec
        assert!(json.get("format").is_none());
        // Optional fields omitted when None
        assert!(json.get("locations").is_none());
        assert!(json.get("claims").is_none());
    }

    #[test]
    fn rar_detail_with_locations_for_remote_as() {
        // OID4VCI §5.1.1: locations MUST be set when authorization_servers is in metadata
        let detail = AuthorizationDetail::for_configuration("UniversityDegreeCredential")
            .with_locations(vec!["https://credential-issuer.example.com".to_string()]);

        let json = serde_json::to_value(&detail).unwrap();
        assert_eq!(
            json["locations"][0],
            "https://credential-issuer.example.com"
        );
    }

    #[test]
    fn rar_detail_roundtrip_deserialization() {
        let original = AuthorizationDetail::for_configuration("MyCredential")
            .with_locations(vec!["https://issuer.example.com".to_string()]);

        let json = serde_json::to_string(&original).unwrap();
        let recovered: AuthorizationDetail = serde_json::from_str(&json).unwrap();

        assert_eq!(recovered.credential_configuration_id, "MyCredential");
        assert_eq!(
            recovered.locations,
            Some(vec!["https://issuer.example.com".to_string()])
        );
    }

    // ── multi-credential request ──────────────────────────────────────────────

    #[test]
    fn builder_with_multiple_rar_details() {
        // OID4VCI §5.1.1: "this non-normative example requests authorization to issue two
        // different Credentials"
        let request = AuthorizationRequestBuilder::new("client")
            .with_authorization_detail(AuthorizationDetail::for_configuration(
                "UniversityDegreeCredential",
            ))
            .with_authorization_detail(AuthorizationDetail::for_configuration(
                "org.iso.18013.5.1.mDL",
            ))
            .build()
            .unwrap();

        let details = request.authorization_details.unwrap();
        assert_eq!(details.len(), 2);
        assert_eq!(
            details[0].credential_configuration_id,
            "UniversityDegreeCredential"
        );
        assert_eq!(
            details[1].credential_configuration_id,
            "org.iso.18013.5.1.mDL"
        );
    }

    // ── query pair serialization ─────────────────────────────────────────────

    #[test]
    fn to_query_pairs_rar_flow_matches_spec() {
        // Based on non-normative GET example in OID4VCI §5.1.1
        let request = AuthorizationRequestBuilder::new("s6BhdRkqt3")
            .with_redirect_uri("https://wallet.example.org/cb")
            .with_authorization_detail(AuthorizationDetail::for_configuration(
                "UniversityDegreeCredential",
            ))
            .build()
            .unwrap();

        let pairs = request.to_query_pairs();
        let map: std::collections::HashMap<_, _> = pairs.into_iter().collect();

        assert_eq!(map["response_type"], "code");
        assert_eq!(map["client_id"], "s6BhdRkqt3");
        assert_eq!(map["redirect_uri"], "https://wallet.example.org/cb");

        // authorization_details must be JSON-serialized
        let details: serde_json::Value =
            serde_json::from_str(&map["authorization_details"]).unwrap();
        assert_eq!(details[0]["type"], "openid_credential");
        assert_eq!(
            details[0]["credential_configuration_id"],
            "UniversityDegreeCredential"
        );
    }

    #[test]
    fn to_query_pairs_scope_flow_with_resource() {
        // Based on non-normative scope example in OID4VCI §5.1.2
        let request = AuthorizationRequestBuilder::new("s6BhdRkqt3")
            .with_redirect_uri("https://wallet.example.org/cb")
            .with_scope("UniversityDegreeCredential")
            .with_resource("https://credential-issuer.example.com")
            .build()
            .unwrap();

        let pairs = request.to_query_pairs();
        let map: std::collections::HashMap<_, _> = pairs.into_iter().collect();
        assert_eq!(map["scope"], "UniversityDegreeCredential");
        assert_eq!(map["resource"], "https://credential-issuer.example.com");
    }

    // ── PKCE ─────────────────────────────────────────────────────────────────

    #[test]
    fn pkce_generation_produces_valid_base64url() {
        let pkce = PkceParams::generate().unwrap();

        // Should be valid base64url — no +, /, or padding =
        assert!(!pkce.code_verifier.contains('+'));
        assert!(!pkce.code_verifier.contains('/'));
        assert!(!pkce.code_verifier.contains('='));

        assert!(!pkce.code_challenge.contains('+'));
        assert!(!pkce.code_challenge.contains('/'));
        assert!(!pkce.code_challenge.contains('='));

        assert_eq!(pkce.method, CodeChallengeMethod::S256);
    }

    // ── scope discovery ───────────────────────────────────────────────────────

    #[test]
    fn scope_discovery_helper() {
        let json = serde_json::json!({
            "credential_issuer": "https://issuer.com",
            "credential_endpoint": "https://issuer.com/cred",
            "credential_configurations_supported": {
                "CredID": {
                    "format": "vc+sd-jwt",
                    "scope": "test-scope"
                }
            }
        });
        let metadata: CredentialIssuerMetadata = serde_json::from_value(json).unwrap();

        assert_eq!(
            scope_for_credential_configuration(&metadata, "CredID"),
            Some("test-scope")
        );
        assert_eq!(
            scope_for_credential_configuration(&metadata, "Unknown"),
            None
        );
    }

    // ── issuer-initiated flow ─────────────────────────────────────────────────

    #[test]
    fn issuer_initiated_flow_preserves_issuer_state() {
        // OID4VCI §5.1.3 — wallet echoes issuer_state from Credential Offer
        let request = AuthorizationRequestBuilder::new("client")
            .with_issuer_state("offer-state-from-credential-offer")
            .with_scope("UniversityDegreeCredential")
            .build()
            .unwrap();

        assert_eq!(
            request.issuer_state,
            Some("offer-state-from-credential-offer".to_string())
        );
    }

    #[test]
    fn rar_detail_with_claims_description_matches_spec() {
        // OID4VCI Appendix B.1 example
        let path = ClaimPathPointer::from_strings(["address", "street_address"]);
        let claim = ClaimDescription::new(path).with_mandatory(true);

        let detail = AuthorizationDetail::for_configuration("UniversityDegreeCredential")
            .with_claims(vec![claim]);

        let json = serde_json::to_value(&detail).unwrap();

        assert_eq!(
            json["claims"][0]["path"],
            serde_json::json!(["address", "street_address"])
        );
        assert_eq!(json["claims"][0]["mandatory"], true);
    }
}
