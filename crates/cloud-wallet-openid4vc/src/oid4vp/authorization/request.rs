use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use serde_with::skip_serializing_none;
use url::Url;

use crate::errors::{Error, ErrorKind, Result};

/// The `response_type` parameter for OpenID4VP Authorization Requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum ResponseType {
    #[serde(rename = "vp_token")]
    VpToken,

    #[serde(rename = "vp_token id_token")]
    VpTokenIdToken,
}

impl<'de> Deserialize<'de> for ResponseType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        match s.trim() {
            "vp_token" => Ok(Self::VpToken),
            "vp_token id_token" | "id_token vp_token" => Ok(Self::VpTokenIdToken),
            other => Err(serde::de::Error::custom(format!(
                "unsupported response_type '{other}'; expected 'vp_token' or 'vp_token id_token'"
            ))),
        }
    }
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResponseMode {
    #[serde(rename = "direct_post")]
    DirectPost,

    #[serde(rename = "direct_post.jwt")]
    DirectPostJwt,
}

impl std::fmt::Display for ResponseMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DirectPost => write!(f, "direct_post"),
            Self::DirectPostJwt => write!(f, "direct_post.jwt"),
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

    /// OPTIONAL. OAuth 2.0 scope values.
    pub scope: Option<String>,

    /// OPTIONAL. Opaque state value echoed back in the response.
    pub state: Option<String>,

    /// REQUIRED. A fresh, unique nonce binding the VP Token to this request.
    pub nonce: String,

    /// CONDITIONAL. How the Wallet delivers the Authorization Response.
    pub response_mode: Option<ResponseMode>,

    /// CONDITIONAL. The URI to which the Wallet POSTs the Authorization Response.
    pub response_uri: Option<Url>,

    /// OPTIONAL. A reference to a JAR (JWT-Secured Authorization Request) object.
    pub request_uri: Option<Url>,

    /// OPTIONAL. Controls whether the Wallet fetches `request_uri` via GET or POST.
    pub request_uri_method: Option<RequestUriMethod>,

    /// REQUIRED. A DCQL query describing the credentials the Verifier requests.
    pub dcql_query: Option<Value>,

    /// OPTIONAL. Verifier metadata provided inline.
    pub client_metadata: Option<Value>,

    /// OPTIONAL. URI from which the Wallet can fetch the Verifier's metadata.
    pub client_metadata_uri: Option<Url>,

    /// OPTIONAL. Identifies the Client Identifier scheme in use.
    pub client_id_scheme: Option<String>,
}

impl AuthorizationRequest {
    /// Validates the Authorization Request against all OID4VP spec constraints.
    pub fn validate(&self) -> Result<()> {
        // response_type must be vp_token (per ticket requirement)
        if !matches!(self.response_type, ResponseType::VpToken) {
            return Err(invalid_request("'response_type' must be 'vp_token'"));
        }

        // nonce MUST be present and non-empty (Section 5.1)
        if self.nonce.trim().is_empty() {
            return Err(invalid_request("'nonce' must not be empty"));
        }

        // dcql_query MUST be present — sole query mechanism in OID4VP 1.0 (Section 5.1)
        if self.dcql_query.is_none() {
            return Err(invalid_request(
                "'dcql_query' is required but was not provided",
            ));
        }

        let uses_direct_post = matches!(
            self.response_mode,
            Some(ResponseMode::DirectPost | ResponseMode::DirectPostJwt)
        );

        if uses_direct_post {
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

        // client_metadata and client_metadata_uri are mutually exclusive (Section 5.1)
        if self.client_metadata.is_some() && self.client_metadata_uri.is_some() {
            return Err(invalid_request(
                "'client_metadata' and 'client_metadata_uri' are mutually exclusive",
            ));
        }

        Ok(())
    }
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
            response_mode: Option<ResponseMode>,
            response_uri: Option<Url>,
            request_uri: Option<Url>,
            request_uri_method: Option<RequestUriMethod>,
            dcql_query: Option<Value>,
            client_metadata: Option<Value>,
            client_metadata_uri: Option<Url>,
            client_id_scheme: Option<String>,
        }

        let raw = Raw::deserialize(deserializer)?;

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
            client_id_scheme: raw.client_id_scheme,
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

    fn minimal_valid() -> Value {
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

    fn parse(v: Value) -> std::result::Result<AuthorizationRequest, serde_json::Error> {
        serde_json::from_value(v)
    }

    #[test]
    fn parses_minimal_valid_request() {
        let req = parse(minimal_valid()).expect("should parse");
        assert_eq!(req.response_type, ResponseType::VpToken);
        assert_eq!(req.client_id, "https://verifier.example.com");
        assert_eq!(req.nonce, "n-0S6_WzA2Mj");
        assert_eq!(req.response_mode, Some(ResponseMode::DirectPost));
        assert!(req.dcql_query.is_some());
        assert!(req.redirect_uri.is_none());
    }

    #[test]
    fn parses_request_with_optional_fields() {
        let mut v = minimal_valid();
        v["state"] = json!("xyz-state");
        v["scope"] = json!("openid");
        v["client_id_scheme"] = json!("redirect_uri");
        v["request_uri_method"] = json!("post");

        let req = parse(v).expect("should parse");
        assert_eq!(req.state.as_deref(), Some("xyz-state"));
        assert_eq!(req.scope.as_deref(), Some("openid"));
        assert_eq!(req.client_id_scheme.as_deref(), Some("redirect_uri"));
        assert_eq!(req.request_uri_method, Some(RequestUriMethod::Post));
    }

    #[test]
    fn rejects_vp_token_id_token_response_type() {
        let mut v = minimal_valid();
        v["response_type"] = json!("vp_token id_token");

        let err = parse(v).unwrap_err();
        assert!(
            err.to_string().contains("response_type"),
            "error should mention 'response_type': {err}"
        );
    }

    #[test]
    fn parses_direct_post_jwt_response_mode() {
        let mut v = minimal_valid();
        v["response_mode"] = json!("direct_post.jwt");

        let req = parse(v).expect("should parse");
        assert_eq!(req.response_mode, Some(ResponseMode::DirectPostJwt));
    }

    #[test]
    fn parses_with_inline_client_metadata() {
        let mut v = minimal_valid();
        v["client_metadata"] = json!({
            "vp_formats": { "dc+sd-jwt": { "alg": ["ES256"] } }
        });

        let req = parse(v).expect("should parse");
        assert!(req.client_metadata.is_some());
    }

    #[test]
    fn parses_with_client_metadata_uri() {
        let mut v = minimal_valid();
        v["client_metadata_uri"] = json!("https://verifier.example.com/client-metadata");

        let req = parse(v).expect("should parse");
        assert!(req.client_metadata_uri.is_some());
    }

    #[test]
    fn serde_roundtrip() {
        let req = parse(minimal_valid()).expect("should parse");
        let serialized = serde_json::to_string(&req).expect("should serialize");
        let deserialized: AuthorizationRequest =
            serde_json::from_str(&serialized).expect("should round-trip");
        assert_eq!(req.nonce, deserialized.nonce);
        assert_eq!(req.response_type, deserialized.response_type);
        assert_eq!(req.client_id, deserialized.client_id);
    }

    #[test]
    fn rejects_unknown_response_type() {
        let mut v = minimal_valid();
        v["response_type"] = json!("code");
        assert!(parse(v).is_err());
    }

    #[test]
    fn rejects_id_token_only_response_type() {
        let mut v = minimal_valid();
        v["response_type"] = json!("id_token");
        assert!(parse(v).is_err());
    }

    #[test]
    fn rejects_empty_nonce() {
        let mut v = minimal_valid();
        v["nonce"] = json!("");
        let err = parse(v).unwrap_err();
        assert!(
            err.to_string().contains("nonce"),
            "error should mention 'nonce': {err}"
        );
    }

    #[test]
    fn rejects_whitespace_only_nonce() {
        let mut v = minimal_valid();
        v["nonce"] = json!("   ");
        let err = parse(v).unwrap_err();
        assert!(err.to_string().contains("nonce"));
    }

    #[test]
    fn rejects_missing_dcql_query() {
        let mut v = minimal_valid();
        v.as_object_mut().unwrap().remove("dcql_query");
        let err = parse(v).unwrap_err();
        assert!(
            err.to_string().contains("dcql_query"),
            "error should mention 'dcql_query': {err}"
        );
    }

    #[test]
    fn rejects_missing_response_uri_for_direct_post() {
        let mut v = minimal_valid();
        v.as_object_mut().unwrap().remove("response_uri");
        let err = parse(v).unwrap_err();
        assert!(
            err.to_string().contains("response_uri"),
            "error should mention 'response_uri': {err}"
        );
    }

    #[test]
    fn rejects_redirect_uri_when_response_uri_present() {
        let mut v = minimal_valid();
        v["redirect_uri"] = json!("https://app.example.com/callback");
        let err = parse(v).unwrap_err();
        assert!(
            err.to_string().contains("redirect_uri"),
            "error should mention 'redirect_uri': {err}"
        );
    }

    #[test]
    fn rejects_both_redirect_and_response_uri_regardless_of_mode() {
        // No response_mode set, but both URIs present
        let v = json!({
            "response_type": "vp_token",
            "client_id": "https://verifier.example.com",
            "redirect_uri": "https://app.example.com/callback",
            "response_uri": "https://verifier.example.com/response",
            "nonce": "abc123",
            "dcql_query": { "credentials": [] }
        });
        let err = parse(v).unwrap_err();
        assert!(err.to_string().contains("redirect_uri"));
    }

    #[test]
    fn rejects_both_client_metadata_and_client_metadata_uri() {
        let mut v = minimal_valid();
        v["client_metadata"] = json!({ "vp_formats": {} });
        v["client_metadata_uri"] = json!("https://verifier.example.com/client-metadata");
        let err = parse(v).unwrap_err();
        assert!(
            err.to_string().contains("client_metadata"),
            "error should mention 'client_metadata': {err}"
        );
    }

    #[test]
    fn validate_succeeds_on_valid_constructed_request() {
        let req = AuthorizationRequest {
            response_type: ResponseType::VpToken,
            client_id: "https://verifier.example.com".to_string(),
            redirect_uri: None,
            scope: None,
            state: None,
            nonce: "fresh-nonce".to_string(),
            response_mode: Some(ResponseMode::DirectPost),
            response_uri: Some(Url::parse("https://verifier.example.com/response").unwrap()),
            request_uri: None,
            request_uri_method: None,
            dcql_query: Some(json!({ "credentials": [] })),
            client_metadata: None,
            client_metadata_uri: None,
            client_id_scheme: None,
        };
        assert!(req.validate().is_ok());
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
            response_mode: Some(ResponseMode::DirectPost),
            response_uri: Some(Url::parse("https://verifier.example.com/response").unwrap()),
            request_uri: None,
            request_uri_method: None,
            dcql_query: Some(json!({ "credentials": [] })),
            client_metadata: None,
            client_metadata_uri: None,
            client_id_scheme: None,
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
