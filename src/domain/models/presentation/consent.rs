use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct PresentationConsentRequest {
    pub accepted: bool,
    #[serde(default)]
    pub selected_credentials: Option<Vec<CredentialSelection>>,
    #[serde(default)]
    pub transaction_data_acknowledged: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct CredentialSelection {
    pub query_id: String,
    pub credential_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentStatus {
    Completed,
    Rejected,
}

#[derive(Debug, Serialize)]
pub struct PresentationConsentResponse {
    pub status: ConsentStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifier_response: Option<VerifierDirectPostResponse>,
}

#[derive(Debug, Serialize)]
pub struct VerifierDirectPostResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,
    #[serde(flatten)]
    pub additional: serde_json::Map<String, serde_json::Value>,
}

impl From<cloud_wallet_openid4vc::oid4vp::authorization::DirectPostResponse>
    for VerifierDirectPostResponse
{
    fn from(resp: cloud_wallet_openid4vc::oid4vp::authorization::DirectPostResponse) -> Self {
        Self {
            redirect_uri: resp.redirect_uri.map(|u| u.to_string()),
            additional: resp.additional,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consent_request_parses_accepted_false() {
        let req: PresentationConsentRequest =
            serde_json::from_str(r#"{"accepted": false}"#).unwrap();
        assert!(!req.accepted);
        assert!(req.selected_credentials.is_none());
        assert!(req.transaction_data_acknowledged.is_none());
    }

    #[test]
    fn consent_request_parses_with_credentials() {
        let req: PresentationConsentRequest = serde_json::from_str(
            r#"{"accepted": true, "selected_credentials": [{"query_id": "q1", "credential_id": "abc-123"}], "transaction_data_acknowledged": true}"#,
        )
        .unwrap();
        assert!(req.accepted);
        assert_eq!(req.selected_credentials.as_ref().unwrap().len(), 1);
        assert_eq!(req.selected_credentials.as_ref().unwrap()[0].query_id, "q1");
        assert_eq!(req.transaction_data_acknowledged, Some(true));
    }

    #[test]
    fn consent_status_serializes_snake_case() {
        let json = serde_json::to_string(&ConsentStatus::Completed).unwrap();
        assert_eq!(json, "\"completed\"");

        let json = serde_json::to_string(&ConsentStatus::Rejected).unwrap();
        assert_eq!(json, "\"rejected\"");
    }

    #[test]
    fn consent_response_serializes_with_redirect_uri() {
        let resp = PresentationConsentResponse {
            status: ConsentStatus::Completed,
            redirect_uri: Some("https://example.com/cb".to_string()),
            verifier_response: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["status"], "completed");
        assert_eq!(json["redirect_uri"], "https://example.com/cb");
        assert!(!json.as_object().unwrap().contains_key("verifier_response"));
    }

    #[test]
    fn consent_response_omits_optional_fields() {
        let resp = PresentationConsentResponse {
            status: ConsentStatus::Rejected,
            redirect_uri: None,
            verifier_response: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(!json.as_object().unwrap().contains_key("redirect_uri"));
        assert!(!json.as_object().unwrap().contains_key("verifier_response"));
    }

    #[test]
    fn verifier_direct_post_response_flattens_additional_fields() {
        let resp = VerifierDirectPostResponse {
            redirect_uri: Some("https://example.com/cb".to_string()),
            additional: serde_json::Map::from_iter([(
                "error".to_string(),
                serde_json::Value::String("invalid_request".to_string()),
            )]),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["redirect_uri"], "https://example.com/cb");
        assert_eq!(json["error"], "invalid_request");
    }
}
