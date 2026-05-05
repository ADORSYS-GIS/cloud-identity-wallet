use cloud_wallet_openid4vc::issuance::client::{IssuanceFlow, Oid4vciClient, ResolvedOfferContext};
use cloud_wallet_openid4vc::issuance::credential_offer::InputMode;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

use super::{FlowType, IssuanceError};
use crate::session::{IssuanceSession, SessionStore};

const SESSION_TTL: Duration = Duration::minutes(15);

#[derive(Debug, Clone, Deserialize)]
pub struct StartIssuanceRequest {
    pub offer: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct StartIssuanceResponse {
    pub session_id: String,
    pub expires_at: String,
    pub issuer: IssuerInfo,
    pub credential_types: Vec<CredentialTypeDisplay>,
    pub flow: String,
    pub tx_code_required: bool,
    pub tx_code: Option<TxCodeInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IssuerInfo {
    pub credential_issuer: String,
    pub display_name: Option<String>,
    pub logo_uri: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CredentialTypeDisplay {
    pub credential_configuration_id: String,
    pub format: String,
    pub display: Option<CredentialDisplayInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CredentialDisplayInfo {
    pub name: Option<String>,
    pub description: Option<String>,
    pub background_color: Option<String>,
    pub text_color: Option<String>,
    pub logo: Option<LogoInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LogoInfo {
    pub uri: Option<String>,
    pub alt_text: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TxCodeInfo {
    pub input_mode: String,
    pub length: Option<u32>,
    pub description: Option<String>,
}

impl StartIssuanceResponse {
    pub fn from_context(context: &ResolvedOfferContext, session: &IssuanceSession) -> Self {
        let issuer = IssuerInfo {
            credential_issuer: context.offer.credential_issuer.to_string(),
            display_name: context
                .issuer_metadata
                .display
                .as_ref()
                .and_then(|d| d.first())
                .and_then(|d| d.name.clone()),
            logo_uri: context
                .issuer_metadata
                .display
                .as_ref()
                .and_then(|d| d.first())
                .and_then(|d| d.logo.as_ref())
                .map(|l| l.uri.to_string()),
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
                    .and_then(|d| d.first())
                    .map(|d| CredentialDisplayInfo {
                        name: Some(d.name.clone()),
                        description: d.description.clone(),
                        background_color: d.background_color.as_ref().map(|c| c.to_string()),
                        text_color: d.text_color.as_ref().map(|c| c.to_string()),
                        logo: d.logo.as_ref().map(|l| LogoInfo {
                            uri: Some(l.uri.to_string()),
                            alt_text: l.alt_text.clone(),
                        }),
                    });

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
                let info = tx_code.as_ref().map(|t| TxCodeInfo {
                    input_mode: match t.input_mode {
                        Some(InputMode::Numeric) => "numeric".to_owned(),
                        Some(InputMode::Text) => "text".to_owned(),
                        None => "numeric".to_owned(),
                    },
                    length: t.length,
                    description: t.description.clone(),
                });
                ("pre_authorized_code".to_owned(), required, info)
            }
        };

        let expires_at = (OffsetDateTime::now_utc() + SESSION_TTL)
            .format(&Rfc3339)
            .unwrap_or_else(|_| "unknown".to_owned());

        Self {
            session_id: session.id.clone(),
            expires_at,
            issuer,
            credential_types,
            flow,
            tx_code_required,
            tx_code,
        }
    }
}

pub async fn start_issuance_session<S: SessionStore>(
    client: &Oid4vciClient,
    session_store: &S,
    offer: &str,
    tenant_id: uuid::Uuid,
) -> Result<(ResolvedOfferContext, IssuanceSession, StartIssuanceResponse), IssuanceError> {
    if offer.is_empty() {
        return Err(IssuanceError::new(
            super::IssuanceErrorCode::InvalidCredentialOffer,
            Some("The credential offer must not be empty.".to_string()),
            super::events::IssuanceStep::OfferResolution,
        ));
    }

    tracing::debug!(offer = %offer, "resolving credential offer");

    let context = client
        .resolve_offer_with_metadata(offer, None)
        .await
        .map_err(Into::<IssuanceError>::into)?;

    let flow_type = match &context.flow {
        IssuanceFlow::AuthorizationCode { .. } => FlowType::AuthorizationCode,
        IssuanceFlow::PreAuthorizedCode { .. } => FlowType::PreAuthorizedCode,
    };

    let session = IssuanceSession::new(tenant_id, context.clone(), flow_type);

    session_store
        .upsert(session.id.clone(), &session)
        .await
        .map_err(Into::<IssuanceError>::into)?;

    let response = StartIssuanceResponse::from_context(&context, &session);

    Ok((context, session, response))
}
