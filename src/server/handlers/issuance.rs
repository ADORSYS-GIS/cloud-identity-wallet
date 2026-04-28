use axum::{
    Json,
    extract::{Extension, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use cloud_wallet_openid4vc::issuance::client::GrantType;
use cloud_wallet_openid4vc::issuance::credential_offer::InputMode;
use uuid::Uuid;

use crate::domain::models::issuance::{
    CredentialDisplay, CredentialTypeDisplay, IssuerSummary, IssuanceErrorResponse, Logo,
    StartIssuanceRequest, StartIssuanceResponse, TxCodeSpec,
};
use crate::server::AppState;
use crate::session::{FlowType, IssuanceSession, SessionStore};

pub async fn start_issuance<S: SessionStore>(
    State(state): State<AppState<S>>,
    Extension(tenant_id): Extension<Uuid>,
    headers: HeaderMap,
    Json(payload): Json<StartIssuanceRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<IssuanceErrorResponse>)> {
    let accept_language = headers
        .get("accept-language")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("en");

    let oid4vci_client = &state.service.oid4vci_client;

    let context = oid4vci_client
        .resolve_offer_with_metadata(&payload.offer, None)
        .await
        .map_err(|e| map_client_error(e))?;

    let flow_type = match context.flow.grant_type() {
        GrantType::AuthorizationCode => FlowType::AuthorizationCode,
        GrantType::PreAuthorizedCode => FlowType::PreAuthorizedCode,
    };

    let session = IssuanceSession::new(tenant_id, context.offer.clone(), flow_type);

    let issuer_display = context
        .issuer_metadata
        .display
        .as_ref()
        .and_then(|displays| select_issuer_display_by_locale(displays, accept_language));

    let issuer = IssuerSummary {
        credential_issuer: context.offer.credential_issuer.to_string(),
        display_name: issuer_display.and_then(|d| d.name.clone()),
        logo_uri: issuer_display.and_then(|d| d.logo.as_ref().map(|l| l.uri.to_string())),
    };

    let credential_types = build_credential_types(
        &context.offer.credential_configuration_ids,
        &context.issuer_metadata,
        accept_language,
    );

    let (tx_code_required, tx_code) = match &context.flow.tx_code_spec() {
        Some(tx) => (
            true,
            Some(TxCodeSpec {
                input_mode: match tx.input_mode {
                    Some(InputMode::Numeric) | None => "numeric".to_string(),
                    Some(InputMode::Text) => "text".to_string(),
                },
                length: tx.length,
                description: tx.description.clone(),
            }),
        ),
        None => (false, None),
    };

    let session_id = session.id.clone();
    state
        .service
        .session
        .upsert(session_id.as_str(), &session)
        .await
        .map_err(|e| match e {
            crate::session::SessionError::InvalidStateTransition(from, to) => (
                StatusCode::BAD_REQUEST,
                Json(IssuanceErrorResponse::invalid_session_state(format!("invalid state transition from {from} to {to}"))),
            ),
            crate::session::SessionError::ExpiredSession => (
                StatusCode::BAD_REQUEST,
                Json(IssuanceErrorResponse::session_expired("session has expired")), // TODO: use specific HTTP status code for expired session
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(IssuanceErrorResponse::server_error(format!("Session storage error: {}", e.to_string()))),
            ),
        })?;

    let response = StartIssuanceResponse {
        session_id,
        expires_at: session.expires_at.format(&time::format_description::well_known::Rfc3339).unwrap(),
        issuer,
        credential_types,
        flow: flow_type.to_string(),
        tx_code_required,
        tx_code,
    };

    Ok((StatusCode::CREATED, Json(response)))
}

fn map_client_error(e: cloud_wallet_openid4vc::issuance::client::ClientError) -> (StatusCode, Json<IssuanceErrorResponse>) {
    use cloud_wallet_openid4vc::issuance::client::ClientError::*;

    match e {
        IssuerMetadataDiscovery { message } => (
            StatusCode::BAD_GATEWAY,
            Json(IssuanceErrorResponse::issuer_metadata_fetch_failed(message)),
        ),
        AsMetadataDiscovery { message } => (
            StatusCode::BAD_GATEWAY,
            Json(IssuanceErrorResponse::auth_server_metadata_fetch_failed(message)),
        ),
        Http { .. } | MetadataDiscovery { .. } => (
            StatusCode::BAD_GATEWAY,
            Json(IssuanceErrorResponse::issuer_metadata_fetch_failed(e.to_string())),
        ),
        Validation { .. } | InvalidResponse { .. } | NoSupportedGrantType => (
            StatusCode::BAD_REQUEST,
            Json(IssuanceErrorResponse::invalid_credential_offer(e.to_string())),
        ),
        Authorization(e) => (
            StatusCode::BAD_REQUEST,
            Json(IssuanceErrorResponse::auth_error(e.to_string())),
        ),
        Token(e) => (
            StatusCode::BAD_REQUEST,
            Json(IssuanceErrorResponse::token_error(e.to_string())),
        ),
        Credential(e) => (
            StatusCode::BAD_REQUEST,
            Json(IssuanceErrorResponse::credential_error(e.to_string())),
        ),
        DeferredCredential(e) => (
            StatusCode::BAD_REQUEST,
            Json(IssuanceErrorResponse::deferred_credential_error(e.to_string())),
        ),
        Notification(e) => (
            StatusCode::BAD_REQUEST,
            Json(IssuanceErrorResponse::notification_error(e.to_string())),
        ),
        Configuration { message } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(IssuanceErrorResponse::server_error(format!("Configuration error: {}", message))),
        ),
        UnknownCredentialConfiguration { id } => (
            StatusCode::BAD_REQUEST,
            Json(IssuanceErrorResponse::invalid_credential_offer(format!("unknown credential configuration: {id}"))),
        ),
        Internal { message } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(IssuanceErrorResponse::server_error(format!("Internal client error: {}", message))),
        ),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(IssuanceErrorResponse::server_error(e.to_string())),
        ),
    }
}

fn select_issuer_display_by_locale<'a>(
    displays: &'a [cloud_wallet_openid4vc::issuance::issuer_metadata::IssuerDisplay],
    accept_language: &str,
) -> Option<&'a cloud_wallet_openid4vc::issuance::issuer_metadata::IssuerDisplay> {
    let preferred_locales: Vec<&str> = accept_language
        .split(',')
        .filter_map(|s| s.split(';').next())
        .map(|s| s.trim())
        .collect();

    for locale in &preferred_locales {
        for display in displays {
            if let Some(display_locale) = &display.locale {
                if display_locale.starts_with(locale) || locale.starts_with(display_locale) {
                    return Some(display);
                }
            }
        }
    }

    displays.first()
}

fn build_credential_types(
    config_ids: &[String],
    issuer_metadata: &cloud_wallet_openid4vc::issuance::issuer_metadata::CredentialIssuerMetadata,
    accept_language: &str,
) -> Vec<CredentialTypeDisplay> {
    config_ids
        .iter()
        .filter_map(|id| {
            let config = issuer_metadata.credential_configurations_supported.get(id)?;

            let display = config
                .credential_metadata
                .as_ref()
                .and_then(|cm| cm.display.as_ref())
                .and_then(|displays| select_credential_display_by_locale(displays, accept_language));

            Some(CredentialTypeDisplay {
                credential_configuration_id: id.clone(),
                format: config.format_details.format_str().to_string(),
                display: display.unwrap_or_else(|| CredentialDisplay {
                    name: id.clone(),
                    description: None,
                    background_color: None,
                    text_color: None,
                    logo: None,
                }),
            })
        })
        .collect()
}

fn select_credential_display_by_locale(
    displays: &[cloud_wallet_openid4vc::issuance::credential_configuration::CredentialDisplay],
    accept_language: &str,
) -> Option<CredentialDisplay> {
    let preferred_locales: Vec<&str> = accept_language
        .split(',')
        .filter_map(|s| s.split(';').next())
        .map(|s| s.trim())
        .collect();

    for locale in &preferred_locales {
        for display in displays {
            if let Some(display_locale) = &display.locale {
                if display_locale.starts_with(locale) || locale.starts_with(display_locale) {
                    return Some(map_credential_display(display));
                }
            }
        }
    }

    displays.first().map(map_credential_display)
}

fn map_credential_display(
    display: &cloud_wallet_openid4vc::issuance::credential_configuration::CredentialDisplay,
) -> CredentialDisplay {
    CredentialDisplay {
        name: display.name.clone(),
        description: display.description.clone(),
        background_color: display.background_color.as_ref().map(|c| c.to_string()),
        text_color: display.text_color.as_ref().map(|c| c.to_string()),
        logo: display.logo.as_ref().map(|l| Logo {
            uri: l.uri.to_string(),
            alt_text: l.alt_text.clone(),
        }),
    }
}

impl std::fmt::Display for FlowType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FlowType::AuthorizationCode => write!(f, "authorization_code"),
            FlowType::PreAuthorizedCode => write!(f, "pre_authorized_code"),
        }
    }
}
