use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct StartIssuanceRequest {
    pub offer: String,
}

#[derive(Debug, Serialize)]
pub struct StartIssuanceResponse {
    pub session_id: String,
    pub expires_at: String,
    pub issuer: IssuerSummary,
    pub credential_types: Vec<CredentialTypeDisplay>,
    pub flow: String,
    pub tx_code_required: bool,
    pub tx_code: Option<TxCodeSpec>,
}

#[derive(Debug, Serialize)]
pub struct IssuerSummary {
    pub credential_issuer: String,
    pub display_name: Option<String>,
    pub logo_uri: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CredentialTypeDisplay {
    pub credential_configuration_id: String,
    pub format: String,
    pub display: CredentialDisplay,
}

#[derive(Debug, Serialize)]
pub struct CredentialDisplay {
    pub name: String,
    pub description: Option<String>,
    pub background_color: Option<String>,
    pub text_color: Option<String>,
    pub logo: Option<Logo>,
}

#[derive(Debug, Serialize)]
pub struct Logo {
    pub uri: String,
    pub alt_text: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TxCodeSpec {
    pub input_mode: String,
    pub length: Option<u32>,
    pub description: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct IssuanceErrorResponse {
    pub error: &'static str,
    pub error_description: String,
}

impl IssuanceErrorResponse {
    pub fn invalid_credential_offer(description: impl Into<String>) -> Self {
        Self {
            error: "invalid_credential_offer",
            error_description: description.into(),
        }
    }

    pub fn issuer_metadata_fetch_failed(description: impl Into<String>) -> Self {
        Self {
            error: "issuer_metadata_fetch_failed",
            error_description: description.into(),
        }
    }

    pub fn auth_server_metadata_fetch_failed(description: impl Into<String>) -> Self {
        Self {
            error: "auth_server_metadata_fetch_failed",
            error_description: description.into(),
        }
    }

    pub fn server_error(description: impl Into<String>) -> Self {
        Self {
            error: "server_error",
            error_description: description.into(),
        }
    }
}
