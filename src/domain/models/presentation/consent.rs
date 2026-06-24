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
            additional: serde_json::Map::new(),
        }
    }
}
