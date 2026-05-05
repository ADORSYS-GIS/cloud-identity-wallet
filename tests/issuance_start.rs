use cloud_identity_wallet::domain::models::issuance::{
    FlowType, IssuanceErrorCode, StartIssuanceResponse, start_issuance_session,
};
use cloud_identity_wallet::session::{IssuanceSession, MemorySession};
use cloud_wallet_openid4vc::issuance::authz_server_metadata::AuthorizationServerMetadata;
use cloud_wallet_openid4vc::issuance::client::{
    Config as Oid4vciClientConfig, IssuanceFlow, Oid4vciClient, ResolvedOfferContext,
};
use cloud_wallet_openid4vc::issuance::credential_configuration::{
    CredentialConfiguration, CredentialDisplay, CredentialMetadata, Logo, ProofType,
    ProofTypeMetadata,
};
use cloud_wallet_openid4vc::issuance::credential_formats::{
    CredentialFormatDetails, MsoMdocCredentialConfiguration, SdJwtVcCredentialConfiguration,
};
use cloud_wallet_openid4vc::issuance::credential_offer::{
    AuthorizationCodeGrant, CredentialOffer, Grants, InputMode, PreAuthorizedCodeGrant, TxCode,
};
use cloud_wallet_openid4vc::issuance::css_color::CssColor;
use cloud_wallet_openid4vc::issuance::issuer_metadata::{CredentialIssuerMetadata, IssuerDisplay};
use std::collections::HashMap;
use url::Url;

fn make_mock_context(flow: IssuanceFlow) -> ResolvedOfferContext {
    let credential_issuer = Url::parse("https://issuer.example.com").unwrap();
    let grants = match &flow {
        IssuanceFlow::AuthorizationCode { issuer_state } => Some(Grants {
            authorization_code: Some(AuthorizationCodeGrant {
                issuer_state: issuer_state.clone(),
                authorization_server: None,
            }),
            pre_authorized_code: None,
        }),
        IssuanceFlow::PreAuthorizedCode {
            pre_authorized_code,
            tx_code,
        } => Some(Grants {
            authorization_code: None,
            pre_authorized_code: Some(PreAuthorizedCodeGrant {
                pre_authorized_code: pre_authorized_code.clone(),
                tx_code: tx_code.clone(),
                authorization_server: None,
            }),
        }),
    };

    let offer = CredentialOffer {
        credential_issuer: credential_issuer.clone(),
        credential_configuration_ids: vec!["eu.europa.ec.eudi.pid.1".to_owned()],
        grants,
    };

    let display = vec![IssuerDisplay {
        name: Some("Example EU Identity Authority".to_owned()),
        locale: Some("en-US".to_owned()),
        logo: Some(Logo {
            uri: Url::parse("https://issuer.example.com/logo.svg").unwrap(),
            alt_text: Some("Issuer Logo".to_owned()),
        }),
    }];

    let credential_config = CredentialConfiguration {
        id: None,
        format_details: CredentialFormatDetails::DcSdJwt(SdJwtVcCredentialConfiguration {
            vct: "https://credentials.example.com/pid".to_owned(),
        }),
        scope: None,
        cryptographic_binding_methods_supported: Some(vec!["jwk".to_owned()]),
        credential_signing_alg_values_supported: Some(vec![
            cloud_wallet_openid4vc::issuance::credential_configuration::AlgorithmIdentifier::String(
                "ES256".to_owned(),
            ),
        ]),
        proof_types_supported: Some({
            let mut map = HashMap::new();
            map.insert(
                ProofType::Jwt,
                ProofTypeMetadata {
                    proof_signing_alg_values_supported: vec![
                        cloud_wallet_openid4vc::issuance::credential_configuration::AlgorithmIdentifier::String(
                            "ES256".to_owned(),
                        ),
                    ],
                    key_attestations_required: None,
                },
            );
            map
        }),
        credential_metadata: Some(CredentialMetadata {
            display: Some(vec![CredentialDisplay {
                name: "EU Personal ID".to_owned(),
                locale: Some("en-US".to_owned()),
                description: Some("Official EU personal identity document".to_owned()),
                background_color: Some(CssColor::new("#12107c").unwrap()),
                text_color: Some(CssColor::new("#ffffff").unwrap()),
                background_image: None,
                logo: Some(Logo {
                    uri: Url::parse("https://issuer.example.com/pid-logo.svg").unwrap(),
                    alt_text: Some("EU PID Logo".to_owned()),
                }),
            }]),
            claims: None,
        }),
    };

    let mut configs_supported: HashMap<String, CredentialConfiguration> = HashMap::new();
    configs_supported.insert("eu.europa.ec.eudi.pid.1".to_owned(), credential_config);

    let issuer_metadata = CredentialIssuerMetadata {
        credential_issuer: credential_issuer.clone(),
        authorization_servers: None,
        credential_endpoint: Url::parse("https://issuer.example.com/credential").unwrap(),
        nonce_endpoint: None,
        deferred_credential_endpoint: None,
        notification_endpoint: None,
        batch_credential_endpoint: None,
        credential_request_encryption: None,
        credential_response_encryption: None,
        batch_credential_issuance: None,
        credential_configurations_supported: configs_supported,
        display: Some(display),
    };

    let as_metadata = AuthorizationServerMetadata {
        issuer: credential_issuer.clone(),
        authorization_endpoint: Some(Url::parse("https://issuer.example.com/authorize").unwrap()),
        token_endpoint: Some(Url::parse("https://issuer.example.com/token").unwrap()),
        jwks_uri: None,
        registration_endpoint: None,
        scopes_supported: None,
        response_types_supported: Some(vec!["code".to_owned()]),
        response_modes_supported: None,
        grant_types_supported: None,
        token_endpoint_auth_methods_supported: None,
        token_endpoint_auth_signing_alg_values_supported: None,
        service_documentation: None,
        ui_locales_supported: None,
        op_policy_uri: None,
        op_tos_uri: None,
        revocation_endpoint: None,
        revocation_endpoint_auth_methods_supported: None,
        revocation_endpoint_auth_signing_alg_values_supported: None,
        introspection_endpoint: None,
        introspection_endpoint_auth_methods_supported: None,
        introspection_endpoint_auth_signing_alg_values_supported: None,
        code_challenge_methods_supported: Some(vec!["S256".to_owned()]),
        pushed_authorization_request_endpoint: None,
        require_pushed_authorization_requests: None,
        pre_authorized_grant_anonymous_access_supported: None,
        extra_fields: HashMap::new(),
    };

    ResolvedOfferContext {
        offer,
        issuer_metadata,
        as_metadata,
        flow,
    }
}

#[test]
fn start_response_from_auth_code_context() {
    let flow = IssuanceFlow::AuthorizationCode {
        issuer_state: Some("state123".to_owned()),
    };
    let context = make_mock_context(flow);
    let session = IssuanceSession::new(
        uuid::Uuid::new_v4(),
        context.clone(),
        FlowType::AuthorizationCode,
    );

    let response = StartIssuanceResponse::from_context(&context, &session);

    assert_eq!(response.session_id, session.id);
    assert!(!response.expires_at.is_empty());
    assert_eq!(
        response.issuer.credential_issuer,
        "https://issuer.example.com/"
    );
    assert_eq!(
        response.issuer.display_name,
        Some("Example EU Identity Authority".to_owned())
    );
    assert_eq!(response.flow, "authorization_code");
    assert!(!response.tx_code_required);
    assert!(response.tx_code.is_none());
    assert_eq!(response.credential_types.len(), 1);
    let cred = &response.credential_types[0];
    assert_eq!(cred.credential_configuration_id, "eu.europa.ec.eudi.pid.1");
    assert_eq!(cred.format, "dc+sd-jwt");
    assert!(cred.display.is_some());
    let display = cred.display.as_ref().unwrap();
    assert_eq!(display.name, Some("EU Personal ID".to_owned()));
}

#[test]
fn start_response_from_pre_auth_code_context_with_tx_code() {
    let flow = IssuanceFlow::PreAuthorizedCode {
        pre_authorized_code: "pre_code_abc".to_owned(),
        tx_code: Some(TxCode {
            input_mode: Some(InputMode::Numeric),
            length: Some(6),
            description: Some("Enter the code sent to your email".to_owned()),
        }),
    };
    let context = make_mock_context(flow);
    let session = IssuanceSession::new(
        uuid::Uuid::new_v4(),
        context.clone(),
        FlowType::PreAuthorizedCode,
    );

    let response = StartIssuanceResponse::from_context(&context, &session);

    assert_eq!(response.flow, "pre_authorized_code");
    assert!(response.tx_code_required);
    let tx_code = response.tx_code.as_ref().unwrap();
    assert_eq!(tx_code.input_mode, "numeric");
    assert_eq!(tx_code.length, Some(6));
    assert_eq!(
        tx_code.description,
        Some("Enter the code sent to your email".to_owned())
    );
}

#[test]
fn start_response_from_pre_auth_code_context_without_tx_code() {
    let flow = IssuanceFlow::PreAuthorizedCode {
        pre_authorized_code: "pre_code_xyz".to_owned(),
        tx_code: None,
    };
    let context = make_mock_context(flow);
    let session = IssuanceSession::new(
        uuid::Uuid::new_v4(),
        context.clone(),
        FlowType::PreAuthorizedCode,
    );

    let response = StartIssuanceResponse::from_context(&context, &session);

    assert_eq!(response.flow, "pre_authorized_code");
    assert!(!response.tx_code_required);
    assert!(response.tx_code.is_none());
}

#[tokio::test]
async fn start_issuance_rejects_empty_offer() {
    let session_store = MemorySession::default();
    let client_config = Oid4vciClientConfig::new(
        "test-client".to_owned(),
        Url::parse("https://wallet.example.com/callback").unwrap(),
    )
    .accept_untrusted_hosts(true);
    let client = Oid4vciClient::new(client_config).unwrap();

    let result = start_issuance_session(&client, &session_store, "", uuid::Uuid::new_v4()).await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.error, IssuanceErrorCode::InvalidCredentialOffer);
}

#[test]
fn start_response_serializes_authorization_code_flow() {
    let flow = IssuanceFlow::AuthorizationCode {
        issuer_state: Some("state_xyz".to_owned()),
    };
    let context = make_mock_context(flow);
    let session = IssuanceSession::new(
        uuid::Uuid::new_v4(),
        context.clone(),
        FlowType::AuthorizationCode,
    );

    let response = StartIssuanceResponse::from_context(&context, &session);

    assert_eq!(response.session_id, session.id);
    assert_eq!(
        response.issuer.credential_issuer,
        "https://issuer.example.com/"
    );
    assert_eq!(
        response.issuer.display_name,
        Some("Example EU Identity Authority".to_owned())
    );
    assert_eq!(
        response.issuer.logo_uri,
        Some("https://issuer.example.com/logo.svg".to_owned())
    );
    assert_eq!(response.flow, "authorization_code");
    assert!(!response.tx_code_required);
    assert!(response.tx_code.is_none());
    assert_eq!(response.credential_types.len(), 1);
}

#[test]
fn start_response_serializes_pre_auth_flow_without_tx_code() {
    let flow = IssuanceFlow::PreAuthorizedCode {
        pre_authorized_code: "pre_code".to_owned(),
        tx_code: None,
    };
    let context = make_mock_context(flow);
    let session = IssuanceSession::new(
        uuid::Uuid::new_v4(),
        context.clone(),
        FlowType::PreAuthorizedCode,
    );

    let response = StartIssuanceResponse::from_context(&context, &session);

    assert_eq!(response.flow, "pre_authorized_code");
    assert!(!response.tx_code_required);
    assert!(response.tx_code.is_none());
}

#[test]
fn start_response_serializes_pre_auth_flow_with_tx_code() {
    let flow = IssuanceFlow::PreAuthorizedCode {
        pre_authorized_code: "pre_code".to_owned(),
        tx_code: Some(TxCode {
            input_mode: Some(InputMode::Numeric),
            length: Some(4),
            description: Some("Enter PIN".to_owned()),
        }),
    };
    let context = make_mock_context(flow);
    let session = IssuanceSession::new(
        uuid::Uuid::new_v4(),
        context.clone(),
        FlowType::PreAuthorizedCode,
    );

    let response = StartIssuanceResponse::from_context(&context, &session);

    assert_eq!(response.flow, "pre_authorized_code");
    assert!(response.tx_code_required);
    let tx_code = response.tx_code.as_ref().unwrap();
    assert_eq!(tx_code.input_mode, "numeric");
    assert_eq!(tx_code.length, Some(4));
    assert_eq!(tx_code.description, Some("Enter PIN".to_owned()));
}

#[test]
fn start_response_handles_multiple_credential_types() {
    let credential_issuer = Url::parse("https://issuer.example.com").unwrap();
    let offer = CredentialOffer {
        credential_issuer: credential_issuer.clone(),
        credential_configuration_ids: vec![
            "eu.europa.ec.eudi.pid.1".to_owned(),
            "eu.europa.ec.eudi.mdl.1".to_owned(),
        ],
        grants: Some(Grants {
            authorization_code: Some(AuthorizationCodeGrant {
                issuer_state: Some("state".to_owned()),
                authorization_server: None,
            }),
            pre_authorized_code: None,
        }),
    };

    let mut configs_supported: HashMap<String, CredentialConfiguration> = HashMap::new();
    configs_supported.insert(
        "eu.europa.ec.eudi.pid.1".to_owned(),
        CredentialConfiguration {
            id: None,
            format_details: CredentialFormatDetails::DcSdJwt(SdJwtVcCredentialConfiguration {
                vct: "https://credentials.example.com/pid".to_owned(),
            }),
            scope: None,
            cryptographic_binding_methods_supported: None,
            credential_signing_alg_values_supported: None,
            proof_types_supported: None,
            credential_metadata: Some(CredentialMetadata {
                display: Some(vec![CredentialDisplay {
                    name: "EU PID".to_owned(),
                    locale: Some("en-US".to_owned()),
                    description: None,
                    background_color: None,
                    text_color: None,
                    background_image: None,
                    logo: None,
                }]),
                claims: None,
            }),
        },
    );
    configs_supported.insert(
        "eu.europa.ec.eudi.mdl.1".to_owned(),
        CredentialConfiguration {
            id: None,
            format_details: CredentialFormatDetails::MsoMdoc(MsoMdocCredentialConfiguration {
                doctype: "org.iso.18013.5.1.mDL".to_owned(),
            }),
            scope: None,
            cryptographic_binding_methods_supported: None,
            credential_signing_alg_values_supported: None,
            proof_types_supported: None,
            credential_metadata: Some(CredentialMetadata {
                display: Some(vec![CredentialDisplay {
                    name: "EU MDL".to_owned(),
                    locale: Some("en-US".to_owned()),
                    description: None,
                    background_color: None,
                    text_color: None,
                    background_image: None,
                    logo: None,
                }]),
                claims: None,
            }),
        },
    );

    let issuer_metadata = CredentialIssuerMetadata {
        credential_issuer: credential_issuer.clone(),
        authorization_servers: None,
        credential_endpoint: Url::parse("https://issuer.example.com/credential").unwrap(),
        nonce_endpoint: None,
        deferred_credential_endpoint: None,
        notification_endpoint: None,
        batch_credential_endpoint: None,
        credential_request_encryption: None,
        credential_response_encryption: None,
        batch_credential_issuance: None,
        credential_configurations_supported: configs_supported,
        display: Some(vec![]),
    };

    let as_metadata = AuthorizationServerMetadata {
        issuer: credential_issuer.clone(),
        authorization_endpoint: Some(Url::parse("https://issuer.example.com/authorize").unwrap()),
        token_endpoint: Some(Url::parse("https://issuer.example.com/token").unwrap()),
        jwks_uri: None,
        registration_endpoint: None,
        scopes_supported: None,
        response_types_supported: Some(vec!["code".to_owned()]),
        response_modes_supported: None,
        grant_types_supported: None,
        token_endpoint_auth_methods_supported: None,
        token_endpoint_auth_signing_alg_values_supported: None,
        service_documentation: None,
        ui_locales_supported: None,
        op_policy_uri: None,
        op_tos_uri: None,
        revocation_endpoint: None,
        revocation_endpoint_auth_methods_supported: None,
        revocation_endpoint_auth_signing_alg_values_supported: None,
        introspection_endpoint: None,
        introspection_endpoint_auth_methods_supported: None,
        introspection_endpoint_auth_signing_alg_values_supported: None,
        code_challenge_methods_supported: Some(vec!["S256".to_owned()]),
        pushed_authorization_request_endpoint: None,
        require_pushed_authorization_requests: None,
        pre_authorized_grant_anonymous_access_supported: None,
        extra_fields: HashMap::new(),
    };

    let flow = IssuanceFlow::AuthorizationCode {
        issuer_state: Some("state".to_owned()),
    };
    let context = ResolvedOfferContext {
        offer,
        issuer_metadata,
        as_metadata,
        flow,
    };
    let session = IssuanceSession::new(
        uuid::Uuid::new_v4(),
        context.clone(),
        FlowType::AuthorizationCode,
    );

    let response = StartIssuanceResponse::from_context(&context, &session);

    assert_eq!(response.credential_types.len(), 2);
    assert_eq!(
        response.credential_types[0].credential_configuration_id,
        "eu.europa.ec.eudi.pid.1"
    );
    assert_eq!(response.credential_types[0].format, "dc+sd-jwt");
    assert_eq!(
        response.credential_types[1].credential_configuration_id,
        "eu.europa.ec.eudi.mdl.1"
    );
    assert_eq!(response.credential_types[1].format, "mso_mdoc");
}

#[test]
fn start_response_handles_missing_credential_config_gracefully() {
    let credential_issuer = Url::parse("https://issuer.example.com").unwrap();
    let offer = CredentialOffer {
        credential_issuer: credential_issuer.clone(),
        credential_configuration_ids: vec!["known_config".to_owned(), "unknown_config".to_owned()],
        grants: Some(Grants {
            authorization_code: Some(AuthorizationCodeGrant {
                issuer_state: Some("state".to_owned()),
                authorization_server: None,
            }),
            pre_authorized_code: None,
        }),
    };

    let mut configs_supported: HashMap<String, CredentialConfiguration> = HashMap::new();
    configs_supported.insert(
        "known_config".to_owned(),
        CredentialConfiguration {
            id: None,
            format_details: CredentialFormatDetails::DcSdJwt(SdJwtVcCredentialConfiguration {
                vct: "https://credentials.example.com/known".to_owned(),
            }),
            scope: None,
            cryptographic_binding_methods_supported: None,
            credential_signing_alg_values_supported: None,
            proof_types_supported: None,
            credential_metadata: None,
        },
    );

    let issuer_metadata = CredentialIssuerMetadata {
        credential_issuer: credential_issuer.clone(),
        authorization_servers: None,
        credential_endpoint: Url::parse("https://issuer.example.com/credential").unwrap(),
        nonce_endpoint: None,
        deferred_credential_endpoint: None,
        notification_endpoint: None,
        batch_credential_endpoint: None,
        credential_request_encryption: None,
        credential_response_encryption: None,
        batch_credential_issuance: None,
        credential_configurations_supported: configs_supported,
        display: Some(vec![]),
    };

    let as_metadata = AuthorizationServerMetadata {
        issuer: credential_issuer.clone(),
        authorization_endpoint: Some(Url::parse("https://issuer.example.com/authorize").unwrap()),
        token_endpoint: Some(Url::parse("https://issuer.example.com/token").unwrap()),
        jwks_uri: None,
        registration_endpoint: None,
        scopes_supported: None,
        response_types_supported: Some(vec!["code".to_owned()]),
        response_modes_supported: None,
        grant_types_supported: None,
        token_endpoint_auth_methods_supported: None,
        token_endpoint_auth_signing_alg_values_supported: None,
        service_documentation: None,
        ui_locales_supported: None,
        op_policy_uri: None,
        op_tos_uri: None,
        revocation_endpoint: None,
        revocation_endpoint_auth_methods_supported: None,
        revocation_endpoint_auth_signing_alg_values_supported: None,
        introspection_endpoint: None,
        introspection_endpoint_auth_methods_supported: None,
        introspection_endpoint_auth_signing_alg_values_supported: None,
        code_challenge_methods_supported: Some(vec!["S256".to_owned()]),
        pushed_authorization_request_endpoint: None,
        require_pushed_authorization_requests: None,
        pre_authorized_grant_anonymous_access_supported: None,
        extra_fields: HashMap::new(),
    };

    let flow = IssuanceFlow::AuthorizationCode {
        issuer_state: Some("state".to_owned()),
    };
    let context = ResolvedOfferContext {
        offer,
        issuer_metadata,
        as_metadata,
        flow,
    };
    let session = IssuanceSession::new(
        uuid::Uuid::new_v4(),
        context.clone(),
        FlowType::AuthorizationCode,
    );

    let response = StartIssuanceResponse::from_context(&context, &session);

    assert_eq!(response.credential_types.len(), 1);
    assert_eq!(
        response.credential_types[0].credential_configuration_id,
        "known_config"
    );
}

#[test]
fn start_response_handles_missing_display_info() {
    let flow = IssuanceFlow::AuthorizationCode {
        issuer_state: Some("state".to_owned()),
    };

    let credential_issuer = Url::parse("https://issuer.example.com").unwrap();
    let offer = CredentialOffer {
        credential_issuer: credential_issuer.clone(),
        credential_configuration_ids: vec!["test_id".to_owned()],
        grants: Some(Grants {
            authorization_code: Some(AuthorizationCodeGrant {
                issuer_state: Some("state".to_owned()),
                authorization_server: None,
            }),
            pre_authorized_code: None,
        }),
    };

    let mut configs_supported: HashMap<String, CredentialConfiguration> = HashMap::new();
    configs_supported.insert(
        "test_id".to_owned(),
        CredentialConfiguration {
            id: None,
            format_details: CredentialFormatDetails::DcSdJwt(SdJwtVcCredentialConfiguration {
                vct: "https://credentials.example.com/test".to_owned(),
            }),
            scope: None,
            cryptographic_binding_methods_supported: None,
            credential_signing_alg_values_supported: None,
            proof_types_supported: None,
            credential_metadata: None,
        },
    );

    let issuer_metadata = CredentialIssuerMetadata {
        credential_issuer: credential_issuer.clone(),
        authorization_servers: None,
        credential_endpoint: Url::parse("https://issuer.example.com/credential").unwrap(),
        nonce_endpoint: None,
        deferred_credential_endpoint: None,
        notification_endpoint: None,
        batch_credential_endpoint: None,
        credential_request_encryption: None,
        credential_response_encryption: None,
        batch_credential_issuance: None,
        credential_configurations_supported: configs_supported,
        display: Some(vec![]),
    };

    let as_metadata = AuthorizationServerMetadata {
        issuer: credential_issuer.clone(),
        authorization_endpoint: Some(Url::parse("https://issuer.example.com/authorize").unwrap()),
        token_endpoint: Some(Url::parse("https://issuer.example.com/token").unwrap()),
        jwks_uri: None,
        registration_endpoint: None,
        scopes_supported: None,
        response_types_supported: Some(vec!["code".to_owned()]),
        response_modes_supported: None,
        grant_types_supported: None,
        token_endpoint_auth_methods_supported: None,
        token_endpoint_auth_signing_alg_values_supported: None,
        service_documentation: None,
        ui_locales_supported: None,
        op_policy_uri: None,
        op_tos_uri: None,
        revocation_endpoint: None,
        revocation_endpoint_auth_methods_supported: None,
        revocation_endpoint_auth_signing_alg_values_supported: None,
        introspection_endpoint: None,
        introspection_endpoint_auth_methods_supported: None,
        introspection_endpoint_auth_signing_alg_values_supported: None,
        code_challenge_methods_supported: Some(vec!["S256".to_owned()]),
        pushed_authorization_request_endpoint: None,
        require_pushed_authorization_requests: None,
        pre_authorized_grant_anonymous_access_supported: None,
        extra_fields: HashMap::new(),
    };

    let context = ResolvedOfferContext {
        offer,
        issuer_metadata,
        as_metadata,
        flow,
    };
    let session = IssuanceSession::new(
        uuid::Uuid::new_v4(),
        context.clone(),
        FlowType::AuthorizationCode,
    );

    let response = StartIssuanceResponse::from_context(&context, &session);

    assert_eq!(response.credential_types.len(), 1);
    assert!(response.credential_types[0].display.is_none());
}
