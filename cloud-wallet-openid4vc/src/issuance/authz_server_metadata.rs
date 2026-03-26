use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use url::Url;

use crate::errors::{Error, ErrorKind};

//  Authorization Server Metadata

/// OAuth 2.0 Authorization Server Metadata.
///
/// Represents the metadata document published at the AS well-known endpoint
/// (/.well-known/oauth-authorization-server) as defined in
/// [RFC 8414 §2](https://www.rfc-editor.org/rfc/rfc8414.html#section-2).
///
/// The OID4VCI-specific extension parameter
/// pre-authorized_grant_anonymous_access_supported is defined in
/// [OID4VCI §12.3](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-oauth-20-authorization-serv).
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationServerMetadata {
    //  RFC 8414 REQUIRED fields
    /// REQUIRED. The authorization server's issuer identifier URL.
    ///
    /// MUST use the https scheme and contain no query or fragment
    /// components. The wallet MUST verify this matches the URL used to
    /// retrieve the metadata document (RFC 8414 §3.3).
    pub issuer: Url,

    /// URL of the authorization server's authorization endpoint (RFC 6749).
    ///
    /// REQUIRED unless no grant types are supported that use the
    /// authorization endpoint. Modelled as Option because an AS that
    /// supports only the Pre-Authorized Code grant type may omit it
    /// (OID4VCI §12.2.4).
    pub authorization_endpoint: Option<Url>,

    /// URL of the authorization server's token endpoint (RFC 6749).
    ///
    /// REQUIRED unless only the implicit grant type is supported.
    pub token_endpoint: Option<Url>,

    //  RFC 8414 OPTIONAL fields
    /// OPTIONAL. URL of the authorization server's JWK Set document.
    pub jwks_uri: Option<Url>,

    /// OPTIONAL. URL of the OAuth 2.0 Dynamic Client Registration endpoint.
    pub registration_endpoint: Option<Url>,

    /// RECOMMENDED. OAuth 2.0 scope values this server supports.
    pub scopes_supported: Option<Vec<String>>,

    /// REQUIRED by RFC 8414 in responses. OAuth 2.0 response_type values
    /// this server supports. Modelled as Option to accommodate the OID4VCI
    /// exception for Pre-Authorized Code only servers (§12.2.4).
    pub response_types_supported: Option<Vec<String>>,

    /// OPTIONAL. OAuth 2.0 response_mode values this server supports.
    pub response_modes_supported: Option<Vec<String>>,

    /// OPTIONAL. OAuth 2.0 grant type values this server supports.
    pub grant_types_supported: Option<Vec<String>>,

    /// OPTIONAL. Client authentication methods supported by the token endpoint.
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,

    /// OPTIONAL. JWS signing algorithms supported by the token endpoint for
    /// JWT client authentication.
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,

    /// OPTIONAL. URL of a page with human-readable developer documentation.
    pub service_documentation: Option<Url>,

    /// OPTIONAL. BCP 47 language tags for supported UI languages.
    pub ui_locales_supported: Option<Vec<String>>,

    /// OPTIONAL. URL of the server's policy on how clients may use provided
    /// data.
    pub op_policy_uri: Option<Url>,

    /// OPTIONAL. URL of the server's terms of service.
    pub op_tos_uri: Option<Url>,

    /// OPTIONAL. URL of the OAuth 2.0 token revocation endpoint.
    pub revocation_endpoint: Option<Url>,

    /// OPTIONAL. Client authentication methods supported by the revocation
    /// endpoint.
    pub revocation_endpoint_auth_methods_supported: Option<Vec<String>>,

    /// OPTIONAL. JWS signing algorithms supported by the revocation endpoint
    /// for JWT client authentication.
    pub revocation_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,

    /// OPTIONAL. URL of the OAuth 2.0 token introspection endpoint.
    pub introspection_endpoint: Option<Url>,

    /// OPTIONAL. Client authentication methods supported by the introspection
    /// endpoint.
    pub introspection_endpoint_auth_methods_supported: Option<Vec<String>>,

    /// OPTIONAL. JWS signing algorithms supported by the introspection
    /// endpoint for JWT client authentication.
    pub introspection_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,

    /// OPTIONAL. PKCE code challenge methods this server supports.
    pub code_challenge_methods_supported: Option<Vec<String>>,

    // RFC 9126 (Pushed Authorization Requests) parameters
    /// OPTIONAL. URL of the pushed authorization request endpoint.
    ///
    /// Defined in [RFC 9126 §5](https://datatracker.ietf.org/doc/html/rfc9126#section-5).
    pub pushed_authorization_request_endpoint: Option<Url>,

    /// OPTIONAL. Whether the AS requires pushed authorization requests.
    ///
    /// Defined in [RFC 9126 §5](https://datatracker.ietf.org/doc/html/rfc9126#section-5).
    pub require_pushed_authorization_requests: Option<bool>,

    //  OID4VCI §12.3 extension
    /// OPTIONAL. Whether the AS accepts a Token Request with a
    /// Pre-Authorized Code but without a `client_id`.
    ///
    /// Defaults to false when absent (OID4VCI §12.3).
    #[serde(
        rename = "pre-authorized_grant_anonymous_access_supported",
        skip_serializing_if = "Option::is_none"
    )]
    pub pre_authorized_grant_anonymous_access_supported: Option<bool>,

    /// Catch-all for additional metadata parameters defined by other
    /// specifications or by the AS itself.
    ///
    /// RFC 8414 §2 states: "Additional authorization server metadata
    /// parameters MAY also be used." The spec also requires the wallet to
    /// ignore unrecognized parameters, but for round-trip fidelity (e.g.
    /// when the wallet stores and re-serializes received metadata) we
    /// preserve them here instead of silently dropping them.
    #[serde(flatten)]
    pub extra_fields: std::collections::HashMap<String, serde_json::Value>,
}

fn validate_https_url(url: &Url, field: &str) -> Result<(), Error> {
    if url.scheme() != "https" {
        return Err(Error::message(
            ErrorKind::InvalidAuthorizationServerMetadata,
            format!("'{field}' must use the https scheme"),
        ));
    }

    Ok(())
}

impl AuthorizationServerMetadata {
    /// Validates the Authorization Server Metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - issuer is not a valid HTTPS URL
    /// - issuer has a query or fragment component (RFC 8414 §2)
    /// - token_endpoint is present but not a valid HTTPS URL
    /// - authorization_endpoint is present but not a valid HTTPS URL
    #[must_use = "validation result must be checked"]
    pub fn validate(&self) -> Result<(), Error> {
        validate_https_url(&self.issuer, "issuer")?;

        if self.issuer.query().is_some() {
            return Err(Error::message(
                ErrorKind::InvalidAuthorizationServerMetadata,
                "issuer must not contain a query component",
            ));
        }
        if self.issuer.fragment().is_some() {
            return Err(Error::message(
                ErrorKind::InvalidAuthorizationServerMetadata,
                "issuer must not contain a fragment component",
            ));
        }

        if let Some(ref url) = self.token_endpoint {
            validate_https_url(url, "token_endpoint")?;
        }

        if let Some(ref url) = self.authorization_endpoint {
            validate_https_url(url, "authorization_endpoint")?;
        }

        if let Some(ref url) = self.jwks_uri {
            validate_https_url(url, "jwks_uri")?;
        }

        if let Some(ref url) = self.registration_endpoint {
            validate_https_url(url, "registration_endpoint")?;
        }

        if let Some(ref url) = self.service_documentation {
            validate_https_url(url, "service_documentation")?;
        }

        if let Some(ref url) = self.op_policy_uri {
            validate_https_url(url, "op_policy_uri")?;
        }

        if let Some(ref url) = self.op_tos_uri {
            validate_https_url(url, "op_tos_uri")?;
        }

        if let Some(ref url) = self.revocation_endpoint {
            validate_https_url(url, "revocation_endpoint")?;
        }

        if let Some(ref url) = self.introspection_endpoint {
            validate_https_url(url, "introspection_endpoint")?;
        }

        if let Some(ref url) = self.pushed_authorization_request_endpoint {
            validate_https_url(url, "pushed_authorization_request_endpoint")?;
        }

        Ok(())
    }

    /// Returns true if the AS supports anonymous Pre-Authorized Code token
    /// requests (i.e., without a client_id).
    ///
    /// Defaults to false per OID4VCI §12.3 when the parameter is absent.
    pub fn allows_anonymous_pre_authorized_grant(&self) -> bool {
        self.pre_authorized_grant_anonymous_access_supported
            .unwrap_or(false)
    }
}

// Token Response

/// A single entry in the authorization_details array of a Token Response.
///
/// When the wallet used authorization_details in the Authorization or Token
/// Request, each entry MUST include credential_identifiers that the wallet
/// MUST use in subsequent Credential Requests.
///
/// Defined in [OID4VCI §6.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-successful-token-response).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenResponseAuthorizationDetails {
    /// REQUIRED. MUST be openid_credential.
    #[serde(rename = "type")]
    pub r#type: String,

    /// The Credential Configuration identifier this entry relates to.
    pub credential_configuration_id: Option<String>,

    /// REQUIRED when authorization_details was used. Non-empty array of
    /// strings each identifying a Credential Dataset that can be issued
    /// using the access token returned in this response.
    ///
    /// The wallet MUST use these identifiers as the credential_identifier
    /// parameter in subsequent Credential Requests (OID4VCI §8.2).
    pub credential_identifiers: Option<Vec<String>>,

    /// OPTIONAL. Array of strings denoting the claims requested/authorized.
    ///
    /// Defined in [OID4VCI §6.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-successful-token-response).
    pub claims: Option<Vec<String>>,
}

impl TokenResponseAuthorizationDetails {
    /// Validates the authorization details entry.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - type is not openid_credential
    /// - credential_identifiers is present but empty
    #[must_use = "validation result must be checked"]
    pub fn validate(&self) -> Result<(), Error> {
        if self.r#type != "openid_credential" {
            return Err(Error::message(
                ErrorKind::InvalidTokenResponse,
                format!(
                    "authorization_details type must be 'openid_credential', got '{}'",
                    self.r#type
                ),
            ));
        }

        if let Some(ref ids) = self.credential_identifiers
            && ids.is_empty()
        {
            return Err(Error::message(
                ErrorKind::InvalidTokenResponse,
                "credential_identifiers must not be empty when present",
            ));
        }

        Ok(())
    }
}

/// Successful OAuth 2.0 Token Response extended for OID4VCI.
///
/// Represents the response from the Token Endpoint as defined in
/// [RFC 6749 §5.1](https://www.rfc-editor.org/rfc/rfc6749#section-5.1),
/// extended with the authorization_details parameter from
/// [OID4VCI §6.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-successful-token-response).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenResponse {
    /// REQUIRED. The access token issued by the authorization server.
    pub access_token: String,

    /// REQUIRED. The type of the token. Typically Bearer.
    pub token_type: String,

    /// RECOMMENDED. Lifetime of the access token in seconds.
    pub expires_in: Option<u64>,

    /// OPTIONAL. Refresh token for obtaining new access tokens.
    pub refresh_token: Option<String>,

    /// OPTIONAL. Scope of the access token.
    pub scope: Option<String>,

    /// REQUIRED when authorization_details was used in the Authorization
    /// or Token Request. OPTIONAL when scope was used.
    ///
    /// Each entry contains credential_identifiers the wallet MUST use in
    /// subsequent Credential Requests.
    pub authorization_details: Option<Vec<TokenResponseAuthorizationDetails>>,
}

impl TokenResponse {
    /// Validates the Token Response.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - access_token is empty
    /// - token_type is empty
    /// - authorization_details is present but empty
    /// - Any authorization_details entry is invalid
    #[must_use = "validation result must be checked"]
    pub fn validate(&self) -> Result<(), Error> {
        if self.access_token.is_empty() {
            return Err(Error::message(
                ErrorKind::InvalidTokenResponse,
                "access_token must not be empty",
            ));
        }

        if self.token_type.is_empty() {
            return Err(Error::message(
                ErrorKind::InvalidTokenResponse,
                "token_type must not be empty",
            ));
        }

        if let Some(ref details) = self.authorization_details {
            if details.is_empty() {
                return Err(Error::message(
                    ErrorKind::InvalidTokenResponse,
                    "authorization_details must not be empty when present",
                ));
            }
            for entry in details {
                entry.validate()?;
            }
        }

        Ok(())
    }

    /// Returns the credential_identifiers for a given
    /// credential_configuration_id, if present in authorization_details.
    ///
    /// Returns None if authorization_details is absent, the given
    /// configuration ID is not found, or the matching entry has no
    /// credential_identifiers.
    pub fn credential_identifiers_for(
        &self,
        credential_configuration_id: &str,
    ) -> Option<&[String]> {
        self.authorization_details
            .as_ref()?
            .iter()
            .find_map(|entry| {
                if entry.credential_configuration_id.as_deref() == Some(credential_configuration_id)
                {
                    entry.credential_identifiers.as_deref()
                } else {
                    None
                }
            })
    }
}

// helpers

#[cfg(test)]
mod tests {
    use super::*;

    // helpers

    fn minimal_metadata() -> AuthorizationServerMetadata {
        AuthorizationServerMetadata {
            issuer: Url::parse("https://server.example.com").unwrap(),
            authorization_endpoint: Some(Url::parse("https://server.example.com/authorize").unwrap()),
            token_endpoint: Some(Url::parse("https://server.example.com/token").unwrap()),
            jwks_uri: None,
            registration_endpoint: None,
            scopes_supported: None,
            response_types_supported: Some(vec!["code".to_string()]),
            response_modes_supported: None,
            grant_types_supported: None,
            token_endpoint_auth_methods_supported: None,
            token_endpoint_auth_signing_alg_values_supported: None,
            service_documentation: None,
            ui_locales_supported: None,
            op_policy_uri: None,
            op_tos_uri: None,
            revocation_endpoint: None,
            revocation_endpoint_auth_methods_supported: None,
            revocation_endpoint_auth_signing_alg_values_supported: None,
            introspection_endpoint: None,
            introspection_endpoint_auth_methods_supported: None,
            introspection_endpoint_auth_signing_alg_values_supported: None,
            code_challenge_methods_supported: None,
            pushed_authorization_request_endpoint: None,
            require_pushed_authorization_requests: None,
            pre_authorized_grant_anonymous_access_supported: None,
            extra_fields: std::collections::HashMap::new(),
        }
    }

    //  AuthorizationServerMetadata::validate

    #[test]
    fn valid_minimal_metadata() {
        assert!(minimal_metadata().validate().is_ok());
    }

    #[test]
    fn valid_metadata_with_pre_authorized_flag() {
        let mut m = minimal_metadata();
        m.pre_authorized_grant_anonymous_access_supported = Some(true);
        assert!(m.validate().is_ok());
    }

    #[test]
    fn rejects_http_issuer() {
        let mut m = minimal_metadata();
        m.issuer = Url::parse("http://server.example.com").unwrap();
        let err = m.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidAuthorizationServerMetadata);
        assert!(err.to_string().contains("https scheme"));
    }

    #[test]
    fn rejects_invalid_url_issuer() {
        let json = r#"{ "issuer": "not-a-url" }"#;
        let err = serde_json::from_str::<AuthorizationServerMetadata>(json).unwrap_err();
        assert!(err.to_string().contains("relative URL without a base"));
    }

    #[test]
    fn rejects_issuer_with_query() {
        let mut m = minimal_metadata();
        m.issuer = Url::parse("https://server.example.com?foo=bar").unwrap();
        let err = m.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidAuthorizationServerMetadata);
        assert!(
            err.to_string()
                .contains("issuer must not contain a query component"),
            "expected error to state that the issuer must not contain a query component, got: {}",
            err
        );
    }

    #[test]
    fn rejects_issuer_with_fragment() {
        let mut m = minimal_metadata();
        m.issuer = Url::parse("https://server.example.com#section").unwrap();
        let err = m.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidAuthorizationServerMetadata);
        assert!(
            err.to_string()
                .contains("issuer must not contain a fragment component"),
            "expected error to state that the issuer must not contain a fragment component, got: {}",
            err
        );
    }

    #[test]
    fn rejects_http_token_endpoint() {
        let mut m = minimal_metadata();
        m.token_endpoint = Some(Url::parse("http://server.example.com/token").unwrap());
        let err = m.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidAuthorizationServerMetadata);
        assert!(
            err.to_string()
                .contains("'token_endpoint' must use the https scheme"),
            "expected error to state that token_endpoint must use https, got: {}",
            err
        );
    }

    #[test]
    fn rejects_http_authorization_endpoint() {
        let mut m = minimal_metadata();
        m.authorization_endpoint = Some(Url::parse("http://server.example.com/authorize").unwrap());
        let err = m.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidAuthorizationServerMetadata);
        assert!(
            err.to_string()
                .contains("'authorization_endpoint' must use the https scheme"),
            "expected error to state that authorization_endpoint must use https, got: {}",
            err
        );
    }

    #[test]
    fn accepts_metadata_without_optional_endpoints() {
        // A Pre-Authorized Code only AS may omit authorization_endpoint
        let mut m = minimal_metadata();
        m.authorization_endpoint = None;
        m.response_types_supported = None;
        assert!(m.validate().is_ok());
    }

    #[test]
    fn valid_issuer_with_path_component() {
        let mut m = minimal_metadata();
        m.issuer = Url::parse("https://server.example.com/tenant1").unwrap();
        assert!(m.validate().is_ok());
    }

    //  allows_anonymous_pre_authorized_grant

    #[test]
    fn anonymous_grant_defaults_to_false_when_absent() {
        assert!(!minimal_metadata().allows_anonymous_pre_authorized_grant());
    }

    #[test]
    fn anonymous_grant_returns_true_when_set() {
        let mut m = minimal_metadata();
        m.pre_authorized_grant_anonymous_access_supported = Some(true);
        assert!(m.allows_anonymous_pre_authorized_grant());
    }

    #[test]
    fn anonymous_grant_returns_false_when_explicitly_false() {
        let mut m = minimal_metadata();
        m.pre_authorized_grant_anonymous_access_supported = Some(false);
        assert!(!m.allows_anonymous_pre_authorized_grant());
    }

    // AuthorizationServerMetadata serialization

    #[test]
    fn serializes_pre_authorized_flag_with_hyphenated_name() {
        let mut m = minimal_metadata();
        m.pre_authorized_grant_anonymous_access_supported = Some(true);
        let json = serde_json::to_string(&m).unwrap();
        assert!(json.contains("\"pre-authorized_grant_anonymous_access_supported\""));
        // Must NOT use the Rust field name
        assert!(!json.contains("\"pre_authorized_grant_anonymous_access_supported\""));
    }

    #[test]
    fn absent_optional_fields_omitted_from_json() {
        let m = minimal_metadata();
        let json = serde_json::to_string(&m).unwrap();
        assert!(!json.contains("jwks_uri"));
        assert!(!json.contains("registration_endpoint"));
        assert!(!json.contains("pre-authorized"));
    }

    #[test]
    fn deserializes_from_rfc8414_example() {
        // Non-normative example from RFC 8414 §3.2
        let json = r#"{
            "issuer": "https://server.example.com",
            "authorization_endpoint": "https://server.example.com/authorize",
            "token_endpoint": "https://server.example.com/token",
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic", "private_key_jwt"
            ],
            "token_endpoint_auth_signing_alg_values_supported": ["RS256", "ES256"],
            "jwks_uri": "https://server.example.com/jwks.json",
            "registration_endpoint": "https://server.example.com/register",
            "scopes_supported": ["openid", "profile", "email"],
            "response_types_supported": ["code", "code token"],
            "service_documentation":
                "http://server.example.com/service_documentation.html",
            "ui_locales_supported": ["en-US", "en-GB", "fr-FR"]
        }"#;
        let m: AuthorizationServerMetadata = serde_json::from_str(json).unwrap();
        assert!(m.validate().is_ok());
        assert_eq!(m.issuer.as_str(), "https://server.example.com/");
        assert_eq!(
            m.token_endpoint.as_ref().map(|u| u.as_str()),
            Some("https://server.example.com/token")
        );
        assert_eq!(m.scopes_supported.as_ref().unwrap().len(), 3);
        assert_eq!(
            m.token_endpoint_auth_methods_supported
                .as_ref()
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn deserializes_oid4vci_extension_field() {
        let json = r#"{
            "issuer": "https://server.example.com",
            "token_endpoint": "https://server.example.com/token",
            "pre-authorized_grant_anonymous_access_supported": true
        }"#;
        let m: AuthorizationServerMetadata = serde_json::from_str(json).unwrap();
        assert!(m.validate().is_ok());
        assert_eq!(
            m.pre_authorized_grant_anonymous_access_supported,
            Some(true)
        );
    }

    #[test]
    fn unknown_fields_are_ignored_on_deserialization() {
        // Spec: "The Wallet MUST ignore any unrecognized parameters"
        let json = r#"{
            "issuer": "https://server.example.com",
            "token_endpoint": "https://server.example.com/token",
            "some_future_extension": "value"
        }"#;
        let result: Result<AuthorizationServerMetadata, _> = serde_json::from_str(json);
        assert!(result.is_ok());
    }

    // TokenResponseAuthorizationDetails::validate

    #[test]
    fn valid_authorization_details_entry() {
        let entry = TokenResponseAuthorizationDetails {
            r#type: "openid_credential".to_string(),
            credential_configuration_id: Some("UniversityDegreeCredential".to_string()),
            credential_identifiers: Some(vec!["CivilEngineeringDegree-2023".to_string()]),
            claims: None,
        };
        assert!(entry.validate().is_ok());
    }

    #[test]
    fn rejects_wrong_type_in_authorization_details() {
        let entry = TokenResponseAuthorizationDetails {
            r#type: "some_other_type".to_string(),
            credential_configuration_id: None,
            credential_identifiers: None,
            claims: None,
        };
        let err = entry.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidTokenResponse);
        assert!(err.to_string().contains("openid_credential"));
    }

    #[test]
    fn rejects_empty_credential_identifiers() {
        let entry = TokenResponseAuthorizationDetails {
            r#type: "openid_credential".to_string(),
            credential_configuration_id: Some("UniversityDegreeCredential".to_string()),
            credential_identifiers: Some(vec![]),
            claims: None,
        };
        let err = entry.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidTokenResponse);
        assert!(err.to_string().contains("credential_identifiers"));
    }

    #[test]
    fn valid_entry_without_credential_identifiers() {
        // Scope flow: identifiers may not be returned
        let entry = TokenResponseAuthorizationDetails {
            r#type: "openid_credential".to_string(),
            credential_configuration_id: Some("UniversityDegreeCredential".to_string()),
            credential_identifiers: None,
            claims: None,
        };
        assert!(entry.validate().is_ok());
    }

    #[test]
    fn authorization_details_type_field_serializes_as_type() {
        let entry = TokenResponseAuthorizationDetails {
            r#type: "openid_credential".to_string(),
            credential_configuration_id: None,
            credential_identifiers: None,
            claims: None,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"type\":\"openid_credential\""));
        assert!(!json.contains("\"r#type\""));
    }

    // TokenResponse::validate

    #[test]
    fn valid_minimal_token_response() {
        let resp = TokenResponse {
            access_token: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: Some(86400),
            refresh_token: None,
            scope: None,
            authorization_details: None,
        };
        assert!(resp.validate().is_ok());
    }

    #[test]
    fn valid_token_response_with_authorization_details() {
        let resp = TokenResponse {
            access_token: "some-access-token".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: Some(86400),
            refresh_token: None,
            scope: None,
            authorization_details: Some(vec![TokenResponseAuthorizationDetails {
                r#type: "openid_credential".to_string(),
                credential_configuration_id: Some("UniversityDegreeCredential".to_string()),
                credential_identifiers: Some(vec![
                    "CivilEngineeringDegree-2023".to_string(),
                    "ElectricalEngineeringDegree-2023".to_string(),
                ]),
                claims: None,
            }]),
        };
        assert!(resp.validate().is_ok());
    }

    #[test]
    fn rejects_empty_access_token() {
        let resp = TokenResponse {
            access_token: String::new(),
            token_type: "Bearer".to_string(),
            expires_in: None,
            refresh_token: None,
            scope: None,
            authorization_details: None,
        };
        let err = resp.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidTokenResponse);
        assert!(err.to_string().contains("access_token"));
    }

    #[test]
    fn rejects_empty_token_type() {
        let resp = TokenResponse {
            access_token: "some-token".to_string(),
            token_type: String::new(),
            expires_in: None,
            refresh_token: None,
            scope: None,
            authorization_details: None,
        };
        let err = resp.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidTokenResponse);
        assert!(err.to_string().contains("token_type"));
    }

    #[test]
    fn rejects_empty_authorization_details_array() {
        let resp = TokenResponse {
            access_token: "some-token".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: None,
            refresh_token: None,
            scope: None,
            authorization_details: Some(vec![]),
        };
        let err = resp.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidTokenResponse);
        assert!(err.to_string().contains("authorization_details"));
    }

    #[test]
    fn invalid_authorization_details_entry_propagates_error() {
        let resp = TokenResponse {
            access_token: "some-token".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: None,
            refresh_token: None,
            scope: None,
            authorization_details: Some(vec![TokenResponseAuthorizationDetails {
                r#type: "wrong_type".to_string(),
                credential_configuration_id: None,
                credential_identifiers: None,
                claims: None,
            }]),
        };
        assert_eq!(
            resp.validate().unwrap_err().kind(),
            ErrorKind::InvalidTokenResponse
        );
    }

    // TokenResponse serialization

    #[test]
    fn deserializes_from_oid4vci_spec_example() {
        // Non-normative example from OID4VCI §6.2
        let json = r#"{
            "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6Ikp..sHQ",
            "token_type": "Bearer",
            "expires_in": 86400,
            "authorization_details": [
                {
                    "type": "openid_credential",
                    "credential_configuration_id": "UniversityDegreeCredential",
                    "credential_identifiers": [
                        "CivilEngineeringDegree-2023",
                        "ElectricalEngineeringDegree-2023"
                    ]
                }
            ]
        }"#;
        let resp: TokenResponse = serde_json::from_str(json).unwrap();
        assert!(resp.validate().is_ok());
        assert_eq!(resp.access_token, "eyJhbGciOiJSUzI1NiIsInR5cCI6Ikp..sHQ");
        assert_eq!(resp.token_type, "Bearer");
        assert_eq!(resp.expires_in, Some(86400));
        let details = resp.authorization_details.as_ref().unwrap();
        assert_eq!(details.len(), 1);
        assert_eq!(details[0].r#type, "openid_credential");
        assert_eq!(
            details[0].credential_configuration_id.as_deref(),
            Some("UniversityDegreeCredential")
        );
        assert_eq!(
            details[0].credential_identifiers.as_ref().unwrap(),
            &[
                "CivilEngineeringDegree-2023",
                "ElectricalEngineeringDegree-2023"
            ]
        );
    }

    #[test]
    fn optional_fields_omitted_from_json_when_none() {
        let resp = TokenResponse {
            access_token: "tok".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: None,
            refresh_token: None,
            scope: None,
            authorization_details: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("expires_in"));
        assert!(!json.contains("refresh_token"));
        assert!(!json.contains("scope"));
        assert!(!json.contains("authorization_details"));
    }

    // TokenResponse::credential_identifiers_for

    #[test]
    fn returns_matching_credential_identifiers() {
        let resp = TokenResponse {
            access_token: "tok".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: None,
            refresh_token: None,
            scope: None,
            authorization_details: Some(vec![
                TokenResponseAuthorizationDetails {
                    r#type: "openid_credential".to_string(),
                    credential_configuration_id: Some("UniversityDegreeCredential".to_string()),
                    credential_identifiers: Some(vec![
                        "Degree-A".to_string(),
                        "Degree-B".to_string(),
                    ]),
                    claims: None,
                },
                TokenResponseAuthorizationDetails {
                    r#type: "openid_credential".to_string(),
                    credential_configuration_id: Some("mDLCredential".to_string()),
                    credential_identifiers: Some(vec!["mDL-1".to_string()]),
                    claims: None,
                },
            ]),
        };

        let ids = resp
            .credential_identifiers_for("UniversityDegreeCredential")
            .unwrap();
        assert_eq!(ids, ["Degree-A", "Degree-B"]);
    }

    #[test]
    fn returns_none_when_authorization_details_absent() {
        let resp = TokenResponse {
            access_token: "tok".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: None,
            refresh_token: None,
            scope: None,
            authorization_details: None,
        };
        assert!(resp.credential_identifiers_for("anything").is_none());
    }

    #[test]
    fn returns_none_when_config_id_not_found() {
        let resp = TokenResponse {
            access_token: "tok".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: None,
            refresh_token: None,
            scope: None,
            authorization_details: Some(vec![TokenResponseAuthorizationDetails {
                r#type: "openid_credential".to_string(),
                credential_configuration_id: Some("UniversityDegreeCredential".to_string()),
                credential_identifiers: Some(vec!["Degree-A".to_string()]),
                claims: None,
            }]),
        };
        assert!(resp.credential_identifiers_for("mDLCredential").is_none());
    }

    // Real server round-trip

    #[test]
    fn real_keycloak_metadata_round_trips_without_data_loss() {
        // Load the fixture that contains an actual metadata response captured
        // from a Keycloak + OID4VCI server. This exercises two things:
        //   1. All known RFC 8414 fields deserialize without error.
        //   2. Unknown fields (userinfo_endpoint, frontchannel_logout_supported,
        //      dpop_signing_alg_values_supported, etc.) are preserved in
        //      extra_fields and round-trip back to identical JSON.
        let original = include_str!("../../../tests/fixtures/keycloak_as_metadata.json");

        let metadata: AuthorizationServerMetadata =
            serde_json::from_str(original).expect("fixture should deserialize without error");

        assert!(
            metadata.validate().is_ok(),
            "real server metadata should pass validation"
        );

        // Re-serialize and compare as parsed JSON values so that key ordering
        // differences between the original and serde's output do not cause
        // a false failure.
        let re_serialized =
            serde_json::to_string(&metadata).expect("serialization should not fail");

        let original_value: serde_json::Value = serde_json::from_str(original).unwrap();
        let round_tripped_value: serde_json::Value = serde_json::from_str(&re_serialized).unwrap();

        assert_eq!(
            original_value, round_tripped_value,
            "round-tripped J
            SON must be semantically identical to the original"
        );
    }
}
