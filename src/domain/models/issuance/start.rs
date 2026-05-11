use cloud_wallet_openid4vc::issuance::client::{IssuanceFlow, ResolvedOfferContext};
use cloud_wallet_openid4vc::issuance::credential_configuration::CredentialDisplay;
use cloud_wallet_openid4vc::issuance::credential_offer::TxCode;
use cloud_wallet_openid4vc::issuance::issuer_metadata::IssuerDisplay;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

use super::IssuanceError;
use crate::session::IssuanceSession;

const SESSION_TTL: Duration = Duration::minutes(15);

#[derive(Debug, Clone, Deserialize)]
pub struct StartIssuanceRequest {
    pub offer: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct StartIssuanceResponse {
    pub session_id: String,
    pub expires_at: String,
    pub issuer: Vec<IssuerDisplay>,
    pub credential_types: Vec<CredentialTypeDisplay>,
    pub flow: String,
    pub tx_code_required: bool,
    pub tx_code: Option<TxCode>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CredentialTypeDisplay {
    pub credential_configuration_id: String,
    pub format: String,
    pub display: Vec<CredentialDisplay>,
}

impl StartIssuanceResponse {
    pub fn from_context(
        context: &ResolvedOfferContext,
        session: &IssuanceSession,
    ) -> Result<Self, IssuanceError> {
        let issuer = match &context.issuer_metadata.display {
            Some(d) if !d.is_empty() => d.clone(),
            _ => vec![IssuerDisplay {
                name: Some(context.offer.credential_issuer.to_string()),
                locale: None,
                logo: None,
            }],
        };

        let credential_types: Vec<CredentialTypeDisplay> = context
            .offer
            .credential_configuration_ids
            .iter()
            .filter_map(|id| {
                let config = context
                    .issuer_metadata
                    .credential_configurations_supported
                    .get(id)?;

                let display = config
                    .credential_metadata
                    .as_ref()
                    .and_then(|m| m.display.as_ref())
                    .filter(|d| !d.is_empty())
                    .cloned()
                    .unwrap_or_else(|| vec![CredentialDisplay {
                        name: id.clone(),
                        locale: None,
                        logo: None,
                        background_color: None,
                        background_image: None,
                        text_color: None,
                        description: None,
                    }]);

                Some(CredentialTypeDisplay {
                    credential_configuration_id: id.clone(),
                    format: config.format_details.format_str().to_owned(),
                    display,
                })
            })
            .collect();

        let (flow, tx_code_required, tx_code) = match &context.flow {
            IssuanceFlow::AuthorizationCode { .. } => {
                ("authorization_code".to_owned(), false, None)
            }
            IssuanceFlow::PreAuthorizedCode { tx_code, .. } => {
                let required = tx_code.is_some();
                ("pre_authorized_code".to_owned(), required, tx_code.clone())
            }
        };

        let expires_at = (OffsetDateTime::now_utc() + SESSION_TTL)
            .format(&Rfc3339)
            .map_err(|e| {
                IssuanceError::internal_message(format!(
                    "failed to format expiration timestamp: {e}"
                ))
            })?;

        Ok(Self {
            session_id: session.id.clone(),
            expires_at,
            issuer,
            credential_types,
            flow,
            tx_code_required,
            tx_code,
        })
    }
}
