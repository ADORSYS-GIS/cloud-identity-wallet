//! Token Response models.
//!
//! Spec references:
//! - OpenID4VCI §6.2: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-successful-token-response>
//! - RFC 6749 §5.1: <https://www.rfc-editor.org/rfc/rfc6749#section-5.1>

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use super::authz_details::AuthorizationDetails;

/// A successful Token Response (HTTP 200 OK) per OpenID4VCI §6.2 and RFC 6749 §5.1.
///
/// Required: `access_token`, `token_type`
/// Optional: `expires_in`, `refresh_token`, `scope`, `authorization_details`
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<u64>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    /// Authorization details returned by the AS, including credential identifiers.
    pub authorization_details: Option<Vec<AuthorizationDetails>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_successful_bearer_response() {
        let json = r#"{
            "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6Ikp..sHQ",
            "token_type": "Bearer",
            "expires_in": 86400
        }"#;

        let resp: TokenResponse = serde_json::from_str(json).expect("deser failed");

        assert_eq!(resp.access_token, "eyJhbGciOiJSUzI1NiIsInR5cCI6Ikp..sHQ");
        assert_eq!(resp.token_type, "Bearer");
        assert_eq!(resp.expires_in, Some(86400));
    }

    #[test]
    fn spec_rar_response_with_credential_identifiers() {
        use crate::issuance::authz_details::AuthorizationDetailType;

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

        let resp: TokenResponse = serde_json::from_str(json).expect("deser failed");

        let details = resp.authorization_details.as_ref().unwrap();
        assert_eq!(details.len(), 1);

        let detail = &details[0];
        assert_eq!(detail.r#type, AuthorizationDetailType::OpenidCredential);
        assert_eq!(detail.credential_identifiers.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn spec_dpop_response() {
        let json = r#"{
            "access_token": "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU",
            "token_type": "DPoP",
            "expires_in": 3600
        }"#;

        let resp: TokenResponse = serde_json::from_str(json).expect("deser failed");
        assert_eq!(resp.token_type, "DPoP");
    }

    #[test]
    fn token_response_roundtrip() {
        use crate::issuance::authz_details::AuthorizationDetailType;

        let resp = TokenResponse {
            access_token: "my-access-token".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: Some(3600),
            refresh_token: Some("my-refresh-token".to_string()),
            scope: None,
            authorization_details: Some(vec![AuthorizationDetails {
                r#type: AuthorizationDetailType::OpenidCredential,
                credential_configuration_id: "MyCredential".to_string(),
                locations: None,
                claims: None,
                credential_identifiers: Some(vec!["cred-001".to_string()]),
            }]),
        };

        let json = serde_json::to_string(&resp).expect("serialize failed");
        let roundtripped: TokenResponse = serde_json::from_str(&json).expect("deserialize failed");
        assert_eq!(resp, roundtripped);
    }

    #[test]
    fn optional_fields_omitted_when_none() {
        let resp = TokenResponse {
            access_token: "token".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: None,
            refresh_token: None,
            scope: None,
            authorization_details: None,
        };

        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.get("expires_in").is_none());
        assert!(json.get("refresh_token").is_none());
    }
}
