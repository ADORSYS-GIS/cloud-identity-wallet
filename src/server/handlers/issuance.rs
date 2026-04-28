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
    CredentialDisplay, CredentialTypeDisplay, IssuanceErrorResponse, IssuerSummary, Logo,
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
        .map_err(map_client_error)?;

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
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(IssuanceErrorResponse::server_error(e.to_string())),
            )
        })?;

    let response = StartIssuanceResponse {
        session_id,
        expires_at: session
            .expires_at
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap(),
        issuer,
        credential_types,
        flow: flow_type.to_string(),
        tx_code_required,
        tx_code,
    };

    Ok((StatusCode::CREATED, Json(response)))
}

fn map_client_error(
    e: cloud_wallet_openid4vc::issuance::client::ClientError,
) -> (StatusCode, Json<IssuanceErrorResponse>) {
    use cloud_wallet_openid4vc::issuance::client::ClientError::*;

    match e {
        IssuerMetadataDiscovery { message } => (
            StatusCode::BAD_GATEWAY,
            Json(IssuanceErrorResponse::issuer_metadata_fetch_failed(message)),
        ),
        AsMetadataDiscovery { message } => (
            StatusCode::BAD_GATEWAY,
            Json(IssuanceErrorResponse::auth_server_metadata_fetch_failed(
                message,
            )),
        ),
        Http { .. } | MetadataDiscovery { .. } => (
            StatusCode::BAD_GATEWAY,
            Json(IssuanceErrorResponse::issuer_metadata_fetch_failed(
                e.to_string(),
            )),
        ),
        Validation { .. } | InvalidResponse { .. } | NoSupportedGrantType => (
            StatusCode::BAD_REQUEST,
            Json(IssuanceErrorResponse::invalid_credential_offer(
                e.to_string(),
            )),
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
            if let Some(display_locale) = &display.locale
                && (display_locale.starts_with(locale) || locale.starts_with(display_locale))
            {
                return Some(display);
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
            let config = issuer_metadata
                .credential_configurations_supported
                .get(id)?;

            let display = config
                .credential_metadata
                .as_ref()
                .and_then(|cm| cm.display.as_ref())
                .and_then(|displays| {
                    select_credential_display_by_locale(displays, accept_language)
                });

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
            if let Some(display_locale) = &display.locale
                && (display_locale.starts_with(locale) || locale.starts_with(display_locale))
            {
                return Some(map_credential_display(display));
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

#[cfg(test)]
mod tests {
    use super::*;
    use cloud_wallet_openid4vc::issuance::credential_configuration::{
        CredentialConfiguration, CredentialDisplay as Oid4vciCredentialDisplay, CredentialMetadata,
        Logo as Oid4vciLogo,
    };
    use cloud_wallet_openid4vc::issuance::credential_formats::{
        CredentialFormatDetails, SdJwtVcCredentialConfiguration,
    };
    use cloud_wallet_openid4vc::issuance::issuer_metadata::{
        CredentialIssuerMetadata, IssuerDisplay,
    };
    use url::Url;

    fn make_issuer_metadata_with_display(
        displays: Vec<IssuerDisplay>,
        credential_config: Option<(String, CredentialConfiguration)>,
    ) -> CredentialIssuerMetadata {
        let mut configs = std::collections::HashMap::new();
        if let Some((id, config)) = credential_config {
            configs.insert(id, config);
        }
        CredentialIssuerMetadata {
            credential_issuer: Url::parse("https://issuer.example.com").unwrap(),
            authorization_servers: None,
            credential_endpoint: Url::parse("https://issuer.example.com/credential").unwrap(),
            nonce_endpoint: None,
            deferred_credential_endpoint: None,
            notification_endpoint: None,
            batch_credential_endpoint: None,
            credential_request_encryption: None,
            credential_response_encryption: None,
            batch_credential_issuance: None,
            display: if displays.is_empty() {
                None
            } else {
                Some(displays)
            },
            credential_configurations_supported: configs,
        }
    }

    fn make_credential_config(
        id: &str,
        display: Option<Vec<Oid4vciCredentialDisplay>>,
    ) -> (String, CredentialConfiguration) {
        let config = CredentialConfiguration {
            id: None,
            format_details: CredentialFormatDetails::DcSdJwt(SdJwtVcCredentialConfiguration {
                vct: format!("https://example.com/{}", id),
            }),
            scope: None,
            cryptographic_binding_methods_supported: None,
            credential_signing_alg_values_supported: None,
            proof_types_supported: None,
            credential_metadata: display.map(|d| CredentialMetadata {
                display: Some(d),
                claims: None,
            }),
        };
        (id.to_string(), config)
    }

    #[test]
    fn test_select_issuer_display_by_locale_exact_match() {
        let displays = vec![
            IssuerDisplay {
                name: Some("English University".into()),
                locale: Some("en".into()),
                logo: None,
            },
            IssuerDisplay {
                name: Some("Deutsche Universität".into()),
                locale: Some("de".into()),
                logo: None,
            },
        ];

        let result = select_issuer_display_by_locale(&displays, "de");
        assert!(result.is_some());
        assert_eq!(
            result.unwrap().name.as_deref(),
            Some("Deutsche Universität")
        );
    }

    #[test]
    fn test_select_issuer_display_by_locale_prefix_match() {
        let displays = vec![IssuerDisplay {
            name: Some("US English".into()),
            locale: Some("en-US".into()),
            logo: None,
        }];

        let result = select_issuer_display_by_locale(&displays, "en");
        assert!(result.is_some());
    }

    #[test]
    fn test_select_issuer_display_by_locale_fallback_to_first() {
        let displays = vec![IssuerDisplay {
            name: Some("English".into()),
            locale: Some("en".into()),
            logo: None,
        }];

        let result = select_issuer_display_by_locale(&displays, "fr");
        assert!(result.is_some());
        assert_eq!(result.unwrap().name.as_deref(), Some("English"));
    }

    #[test]
    fn test_select_issuer_display_by_locale_multiple_preferred() {
        let displays = vec![
            IssuerDisplay {
                name: Some("French".into()),
                locale: Some("fr".into()),
                logo: None,
            },
            IssuerDisplay {
                name: Some("German".into()),
                locale: Some("de".into()),
                logo: None,
            },
        ];

        let result = select_issuer_display_by_locale(&displays, "de,fr");
        assert!(result.is_some());
        assert_eq!(result.unwrap().name.as_deref(), Some("German"));
    }

    #[test]
    fn test_select_issuer_display_by_locale_empty_displays() {
        let displays: Vec<IssuerDisplay> = vec![];
        let result = select_issuer_display_by_locale(&displays, "en");
        assert!(result.is_none());
    }

    #[test]
    fn test_select_issuer_display_by_locale_with_quality_values() {
        let displays = vec![IssuerDisplay {
            name: Some("English".into()),
            locale: Some("en".into()),
            logo: None,
        }];

        let result = select_issuer_display_by_locale(&displays, "en;q=0.9,de;q=0.8");
        assert!(result.is_some());
    }

    #[test]
    fn test_build_credential_types_with_display() {
        let config = make_credential_config(
            "UniversityDegree",
            Some(vec![Oid4vciCredentialDisplay {
                name: "University Degree".into(),
                locale: Some("en".into()),
                logo: Some(Oid4vciLogo {
                    uri: Url::parse("https://example.com/logo.png").unwrap(),
                    alt_text: Some("University logo".into()),
                }),
                background_color: None,
                background_image: None,
                text_color: None,
                description: Some("A degree credential".into()),
            }]),
        );

        let metadata = make_issuer_metadata_with_display(vec![], Some(config));
        let config_ids = vec!["UniversityDegree".to_string()];

        let result = build_credential_types(&config_ids, &metadata, "en");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].credential_configuration_id, "UniversityDegree");
        assert_eq!(result[0].display.name, "University Degree");
        assert_eq!(
            result[0].display.description,
            Some("A degree credential".into())
        );
    }

    #[test]
    fn test_build_credential_types_without_display() {
        let config = make_credential_config("BasicCredential", None);
        let metadata = make_issuer_metadata_with_display(vec![], Some(config));
        let config_ids = vec!["BasicCredential".to_string()];

        let result = build_credential_types(&config_ids, &metadata, "en");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].credential_configuration_id, "BasicCredential");
        assert_eq!(result[0].display.name, "BasicCredential");
        assert!(result[0].display.description.is_none());
        assert!(result[0].display.logo.is_none());
    }

    #[test]
    fn test_build_credential_types_missing_config() {
        let metadata = make_issuer_metadata_with_display(vec![], None);
        let config_ids = vec!["NonExistent".to_string()];

        let result = build_credential_types(&config_ids, &metadata, "en");
        assert!(result.is_empty());
    }

    #[test]
    fn test_build_credential_types_multiple() {
        let config1 = make_credential_config("Cred1", None);
        let config2 = make_credential_config("Cred2", None);
        let mut configs = std::collections::HashMap::new();
        configs.insert(config1.0.clone(), config1.1);
        configs.insert(config2.0.clone(), config2.1);

        let metadata = CredentialIssuerMetadata {
            credential_issuer: Url::parse("https://issuer.example.com").unwrap(),
            authorization_servers: None,
            credential_endpoint: Url::parse("https://issuer.example.com/credential").unwrap(),
            nonce_endpoint: None,
            deferred_credential_endpoint: None,
            notification_endpoint: None,
            batch_credential_endpoint: None,
            credential_request_encryption: None,
            credential_response_encryption: None,
            batch_credential_issuance: None,
            display: None,
            credential_configurations_supported: configs,
        };

        let config_ids = vec!["Cred1".to_string(), "Cred2".to_string()];
        let result = build_credential_types(&config_ids, &metadata, "en");
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_build_credential_types_locale_fallback() {
        let config = make_credential_config(
            "LocalizedCred",
            Some(vec![Oid4vciCredentialDisplay {
                name: "German Credential".into(),
                locale: Some("de".into()),
                logo: None,
                background_color: None,
                background_image: None,
                text_color: None,
                description: None,
            }]),
        );

        let metadata = make_issuer_metadata_with_display(vec![], Some(config));
        let config_ids = vec!["LocalizedCred".to_string()];

        let result = build_credential_types(&config_ids, &metadata, "en");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].display.name, "German Credential");
    }

    #[test]
    fn test_map_client_error_issuer_metadata_discovery() {
        let error =
            cloud_wallet_openid4vc::issuance::client::ClientError::IssuerMetadataDiscovery {
                message: "failed to fetch".into(),
            };
        let (status, response) = map_client_error(error);
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(response.error, "issuer_metadata_fetch_failed");
    }

    #[test]
    fn test_map_client_error_as_metadata_discovery() {
        let error = cloud_wallet_openid4vc::issuance::client::ClientError::AsMetadataDiscovery {
            message: "failed to fetch AS".into(),
        };
        let (status, response) = map_client_error(error);
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(response.error, "auth_server_metadata_fetch_failed");
    }

    #[test]
    fn test_map_client_error_validation() {
        let error = cloud_wallet_openid4vc::issuance::client::ClientError::Validation {
            message: "invalid offer".into(),
        };
        let (status, response) = map_client_error(error);
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(response.error, "invalid_credential_offer");
    }

    #[test]
    fn test_map_client_error_invalid_response() {
        let error = cloud_wallet_openid4vc::issuance::client::ClientError::InvalidResponse {
            message: "bad response".into(),
        };
        let (status, response) = map_client_error(error);
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(response.error, "invalid_credential_offer");
    }

    #[test]
    fn test_map_client_error_no_supported_grant_type() {
        let error = cloud_wallet_openid4vc::issuance::client::ClientError::NoSupportedGrantType;
        let (status, response) = map_client_error(error);
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(response.error, "invalid_credential_offer");
    }

    #[test]
    fn test_map_client_error_http() {
        let error = cloud_wallet_openid4vc::issuance::client::ClientError::http_response(
            502,
            "connection refused".into(),
        );
        let (status, response) = map_client_error(error);
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(response.error, "issuer_metadata_fetch_failed");
    }

    #[test]
    fn test_map_client_error_internal() {
        let error =
            cloud_wallet_openid4vc::issuance::client::ClientError::internal("unexpected state");
        let (status, response) = map_client_error(error);
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(response.error, "server_error");
    }
}
