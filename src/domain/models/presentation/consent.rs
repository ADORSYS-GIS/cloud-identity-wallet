use serde::{Deserialize, Serialize};

/// Request body for `POST /presentation/{session_id}/consent`.
#[derive(Debug, Deserialize)]
pub struct PresentationConsentRequest {
    /// Whether the user accepted the presentation request.
    pub accepted: bool,
    /// Selected credentials for each credential query.
    /// Required when `accepted` is `true`.
    pub selections: Option<Vec<CredentialSelection>>,
}

/// A credential selection for a specific DCQL query.
#[derive(Debug, Clone, Deserialize)]
pub struct CredentialSelection {
    /// The DCQL credential query ID this selection satisfies.
    pub query_id: String,
    /// The wallet credential ID selected by the user.
    pub credential_id: String,
}

/// Response body for `POST /presentation/{session_id}/consent`.
#[derive(Debug, Clone, Serialize)]
pub struct PresentationConsentResponse {
    /// The session ID.
    pub session_id: String,
    /// Outcome of the consent action.
    pub status: ConsentOutcome,
    /// The verifier's redirect_uri if one was returned in the direct_post response.
    pub redirect_uri: Option<String>,
}

/// Outcome of a consent action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentOutcome {
    /// VP token was successfully sent to the verifier.
    Submitted,
    /// The user rejected the presentation request.
    Rejected,
}
