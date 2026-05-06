use cloud_identity_wallet::domain::models::issuance::{
    FlowType, IssuanceErrorCode, StartIssuanceResponse, start_issuance_session,
};
use cloud_identity_wallet::session::{IssuanceSession, MemorySession};
use cloud_wallet_openid4vc::issuance::client::{
    Config as Oid4vciClientConfig, IssuanceFlow, Oid4vciClient, ResolvedOfferContext,
};
use cloud_wallet_openid4vc::issuance::credential_offer::{InputMode, TxCode};
use serde_json::json;
use url::Url;

fn make_mock_context(flow: IssuanceFlow) -> ResolvedOfferContext {
    let offer_json = match &flow {
        IssuanceFlow::AuthorizationCode { issuer_state } => json!({
            "credential_issuer": "https://issuer.example.com",
            "credential_configuration_ids": ["eu.europa.ec.eudi.pid.1"],
            "grants": {
                "authorization_code": {
                    "issuer_state": issuer_state
                }
            }
        }),
        IssuanceFlow::PreAuthorizedCode {
            pre_authorized_code,
            tx_code,
        } => json!({
            "credential_issuer": "https://issuer.example.com",
            "credential_configuration_ids": ["eu.europa.ec.eudi.pid.1"],
            "grants": {
                "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                    "pre-authorized_code": pre_authorized_code,
                    "tx_code": tx_code
                }
            }
        }),
    };

    let issuer_metadata_json = json!({
        "credential_issuer": "https://issuer.example.com",
        "credential_endpoint": "https://issuer.example.com/credential",
        "display": [{
            "name": "Example EU Identity Authority",
            "locale": "en-US",
            "logo": {
                "uri": "https://issuer.example.com/logo.svg",
                "alt_text": "Issuer Logo"
            }
        }],
        "credential_configurations_supported": {
            "eu.europa.ec.eudi.pid.1": {
                "format": "dc+sd-jwt",
                "vct": "https://credentials.example.com/pid",
                "cryptographic_binding_methods_supported": ["jwk"],
                "credential_signing_alg_values_supported": ["ES256"],
                "proof_types_supported": {
                    "jwt": {
                        "proof_signing_alg_values_supported": ["ES256"]
                    }
                },
                "credential_metadata": {
                    "display": [{
                        "name": "EU Personal ID",
                        "locale": "en-US",
                        "description": "Official EU personal identity document",
                        "background_color": "#12107c",
                        "text_color": "#ffffff",
                        "logo": {
                            "uri": "https://issuer.example.com/pid-logo.svg",
                            "alt_text": "EU PID Logo"
                        }
                    }]
                }
            }
        }
    });

    let as_metadata_json = json!({
        "issuer": "https://issuer.example.com",
        "authorization_endpoint": "https://issuer.example.com/authorize",
        "token_endpoint": "https://issuer.example.com/token",
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"]
    });

    ResolvedOfferContext {
        offer: serde_json::from_value(offer_json).unwrap(),
        issuer_metadata: serde_json::from_value(issuer_metadata_json).unwrap(),
        as_metadata: serde_json::from_value(as_metadata_json).unwrap(),
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

    let response = StartIssuanceResponse::from_context(&context, &session).unwrap();

    assert_eq!(response.session_id, session.id);
    assert!(!response.expires_at.is_empty());
    assert_eq!(
        response.issuer.credential_issuer,
        Url::parse("https://issuer.example.com").unwrap()
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
    assert_eq!(display.name, "EU Personal ID");
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

    let response = StartIssuanceResponse::from_context(&context, &session).unwrap();

    assert_eq!(response.flow, "pre_authorized_code");
    assert!(response.tx_code_required);
    let tx_code = response.tx_code.as_ref().unwrap();
    assert_eq!(tx_code.input_mode, Some(InputMode::Numeric));
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

    let response = StartIssuanceResponse::from_context(&context, &session).unwrap();

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

    let response = StartIssuanceResponse::from_context(&context, &session).unwrap();

    assert_eq!(response.session_id, session.id);
    assert_eq!(
        response.issuer.credential_issuer,
        Url::parse("https://issuer.example.com").unwrap()
    );
    assert_eq!(
        response.issuer.display_name,
        Some("Example EU Identity Authority".to_owned())
    );
    assert_eq!(
        response.issuer.logo_uri,
        Some(Url::parse("https://issuer.example.com/logo.svg").unwrap())
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

    let response = StartIssuanceResponse::from_context(&context, &session).unwrap();

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

    let response = StartIssuanceResponse::from_context(&context, &session).unwrap();

    assert_eq!(response.flow, "pre_authorized_code");
    assert!(response.tx_code_required);
    let tx_code = response.tx_code.as_ref().unwrap();
    assert_eq!(tx_code.input_mode, Some(InputMode::Numeric));
    assert_eq!(tx_code.length, Some(4));
    assert_eq!(tx_code.description, Some("Enter PIN".to_owned()));
}

#[test]
fn start_response_handles_multiple_credential_types() {
    let offer = serde_json::from_value(json!({
        "credential_issuer": "https://issuer.example.com",
        "credential_configuration_ids": ["eu.europa.ec.eudi.pid.1", "eu.europa.ec.eudi.mdl.1"],
        "grants": {
            "authorization_code": {
                "issuer_state": "state"
            }
        }
    }))
    .unwrap();

    let issuer_metadata = serde_json::from_value(json!({
        "credential_issuer": "https://issuer.example.com",
        "credential_endpoint": "https://issuer.example.com/credential",
        "credential_configurations_supported": {
            "eu.europa.ec.eudi.pid.1": {
                "format": "dc+sd-jwt",
                "vct": "https://credentials.example.com/pid",
                "credential_metadata": {
                    "display": [{
                        "name": "EU PID",
                        "locale": "en-US"
                    }]
                }
            },
            "eu.europa.ec.eudi.mdl.1": {
                "format": "mso_mdoc",
                "doctype": "org.iso.18013.5.1.mDL",
                "credential_metadata": {
                    "display": [{
                        "name": "EU MDL",
                        "locale": "en-US"
                    }]
                }
            }
        }
    }))
    .unwrap();

    let as_metadata = serde_json::from_value(json!({
        "issuer": "https://issuer.example.com",
        "authorization_endpoint": "https://issuer.example.com/authorize",
        "token_endpoint": "https://issuer.example.com/token",
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"]
    }))
    .unwrap();

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

    let response = StartIssuanceResponse::from_context(&context, &session).unwrap();

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
    let offer = serde_json::from_value(json!({
        "credential_issuer": "https://issuer.example.com",
        "credential_configuration_ids": ["known_config", "unknown_config"],
        "grants": {
            "authorization_code": {
                "issuer_state": "state"
            }
        }
    }))
    .unwrap();

    let issuer_metadata = serde_json::from_value(json!({
        "credential_issuer": "https://issuer.example.com",
        "credential_endpoint": "https://issuer.example.com/credential",
        "credential_configurations_supported": {
            "known_config": {
                "format": "dc+sd-jwt",
                "vct": "https://credentials.example.com/known"
            }
        }
    }))
    .unwrap();

    let as_metadata = serde_json::from_value(json!({
        "issuer": "https://issuer.example.com",
        "authorization_endpoint": "https://issuer.example.com/authorize",
        "token_endpoint": "https://issuer.example.com/token",
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"]
    }))
    .unwrap();

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

    let response = StartIssuanceResponse::from_context(&context, &session).unwrap();

    assert_eq!(response.credential_types.len(), 1);
    assert_eq!(
        response.credential_types[0].credential_configuration_id,
        "known_config"
    );
}

#[test]
fn start_response_handles_missing_display_info() {
    let offer = serde_json::from_value(json!({
        "credential_issuer": "https://issuer.example.com",
        "credential_configuration_ids": ["test_id"],
        "grants": {
            "authorization_code": {
                "issuer_state": "state"
            }
        }
    }))
    .unwrap();

    let issuer_metadata = serde_json::from_value(json!({
        "credential_issuer": "https://issuer.example.com",
        "credential_endpoint": "https://issuer.example.com/credential",
        "credential_configurations_supported": {
            "test_id": {
                "format": "dc+sd-jwt",
                "vct": "https://credentials.example.com/test"
            }
        }
    }))
    .unwrap();

    let as_metadata = serde_json::from_value(json!({
        "issuer": "https://issuer.example.com",
        "authorization_endpoint": "https://issuer.example.com/authorize",
        "token_endpoint": "https://issuer.example.com/token",
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"]
    }))
    .unwrap();

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

    let response = StartIssuanceResponse::from_context(&context, &session).unwrap();

    assert_eq!(response.credential_types.len(), 1);
    assert!(response.credential_types[0].display.is_none());
}
