//! E2E tests for the issuance start flow.
//!
//! These tests boot a real HTTP server with in-memory stores and use `wiremock`
//! to simulate the OIDC issuer endpoints (metadata, token, etc.).

mod utils;

use cloud_wallet_openid4vc::issuance::credential_offer::{
    AuthorizationCodeGrant, CredentialOffer, CredentialOfferData, Grants, PreAuthorizedCodeGrant,
    TxCode,
};
use reqwest::Client;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn start_issuance_authorization_code_flow_returns_201() {
    let mock_server = MockServer::start().await;
    let issuer_url = mock_server.uri();

    let offer = CredentialOfferData {
        credential_issuer: issuer_url.clone(),
        credential_configuration_ids: vec!["UniversityDegreeCredential".to_string()],
        grants: Some(Grants {
            authorization_code: Some(AuthorizationCodeGrant {
                issuer_state: Some("state_abc123".to_string()),
                authorization_server: None,
            }),
            pre_authorized_code: None,
        }),
    };
    let offer_json = serde_json::to_string(&offer).unwrap();
    let offer_uri = format!(
        "openid-credential-offer://?credential_offer={}",
        urlencoding::encode(&offer_json)
    );

    Mock::given(method("GET"))
        .and(path("/.well-known/openid-credential-issuer"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "credential_issuer": issuer_url,
            "credential_endpoint": format!("{issuer_url}/credential"),
            "credential_configurations_supported": {
                "UniversityDegreeCredential": {
                    "format": "jwt_vc_json",
                    "display": [{
                        "name": "University Degree",
                        "locale": "en-US",
                        "description": "A university degree credential",
                        "background_color": "#12107c",
                        "text_color": "#ffffff",
                        "logo": {
                            "uri": format!("{issuer_url}/logo.svg"),
                            "alt_text": "University Logo"
                        }
                    }]
                }
            }
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-authorization-server"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": issuer_url,
            "authorization_endpoint": format!("{issuer_url}/authorize"),
            "token_endpoint": format!("{issuer_url}/token"),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "code_challenge_methods_supported": ["S256"]
        })))
        .mount(&mock_server)
        .await;

    let base_url = utils::spawn_server().await;
    let client = Client::new();

    let response = client
        .post(format!("{}/api/v1/issuance/start", base_url))
        .json(&json!({ "offer": offer_uri }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 201);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert!(
        body.get("session_id").is_some(),
        "response should contain session_id"
    );
    assert_eq!(body.get("flow").unwrap(), "authorization_code");
    assert_eq!(body.get("tx_code_required").unwrap(), false);
    assert!(body.get("tx_code").unwrap().is_null());

    let issuer = body.get("issuer").unwrap();
    assert_eq!(
        issuer.get("credential_issuer").unwrap(),
        &format!("{issuer_url}/")
    );
    assert_eq!(issuer.get("display_name").unwrap(), "University Degree");

    let credential_types = body.get("credential_types").unwrap().as_array().unwrap();
    assert_eq!(credential_types.len(), 1);
    assert_eq!(
        credential_types[0]
            .get("credential_configuration_id")
            .unwrap(),
        "UniversityDegreeCredential"
    );
    assert_eq!(credential_types[0].get("format").unwrap(), "jwt_vc_json");
}

#[tokio::test]
async fn start_issuance_pre_authorized_code_flow_with_tx_code_returns_201() {
    let mock_server = MockServer::start().await;
    let issuer_url = mock_server.uri();

    let offer = CredentialOfferData {
        credential_issuer: issuer_url.clone(),
        credential_configuration_ids: vec!["EmployeeBadge".to_string()],
        grants: Some(Grants {
            authorization_code: None,
            pre_authorized_code: Some(PreAuthorizedCodeGrant {
                pre_authorized_code: "pre_code_xyz".to_string(),
                tx_code: Some(TxCode {
                    input_mode: "numeric".to_string(),
                    length: Some(6),
                    description: Some("Enter the code sent to your email".to_string()),
                }),
                authorization_server: None,
            }),
        }),
    };
    let offer_json = serde_json::to_string(&offer).unwrap();
    let offer_uri = format!(
        "openid-credential-offer://?credential_offer={}",
        urlencoding::encode(&offer_json)
    );

    Mock::given(method("GET"))
        .and(path("/.well-known/openid-credential-issuer"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "credential_issuer": issuer_url,
            "credential_endpoint": format!("{issuer_url}/credential"),
            "credential_configurations_supported": {
                "EmployeeBadge": {
                    "format": "vc+sd-jwt",
                    "display": [{
                        "name": "Employee Badge",
                        "locale": "en-US"
                    }]
                }
            }
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-authorization-server"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": issuer_url,
            "authorization_endpoint": format!("{issuer_url}/authorize"),
            "token_endpoint": format!("{issuer_url}/token"),
            "response_types_supported": ["code"],
            "grant_types_supported": ["urn:ietf:params:oauth:grant-type:pre-authorized_code"],
            "code_challenge_methods_supported": ["S256"],
            "pre_authorized_grant_anonymous_access_supported": true
        })))
        .mount(&mock_server)
        .await;

    let base_url = utils::spawn_server().await;
    let client = Client::new();

    let response = client
        .post(format!("{}/api/v1/issuance/start", base_url))
        .json(&json!({ "offer": offer_uri }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 201);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body.get("flow").unwrap(), "pre_authorized_code");
    assert_eq!(body.get("tx_code_required").unwrap(), true);

    let tx_code = body.get("tx_code").unwrap();
    assert_eq!(tx_code.get("input_mode").unwrap(), "numeric");
    assert_eq!(tx_code.get("length").unwrap(), 6);
    assert_eq!(
        tx_code.get("description").unwrap(),
        "Enter the code sent to your email"
    );
}

#[tokio::test]
async fn start_issuance_pre_authorized_code_flow_without_tx_code_returns_201() {
    let mock_server = MockServer::start().await;
    let issuer_url = mock_server.uri();

    let offer = CredentialOfferData {
        credential_issuer: issuer_url.clone(),
        credential_configuration_ids: vec!["DigitalID".to_string()],
        grants: Some(Grants {
            authorization_code: None,
            pre_authorized_code: Some(PreAuthorizedCodeGrant {
                pre_authorized_code: "pre_code_no_tx".to_string(),
                tx_code: None,
                authorization_server: None,
            }),
        }),
    };
    let offer_json = serde_json::to_string(&offer).unwrap();
    let offer_uri = format!(
        "openid-credential-offer://?credential_offer={}",
        urlencoding::encode(&offer_json)
    );

    Mock::given(method("GET"))
        .and(path("/.well-known/openid-credential-issuer"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "credential_issuer": issuer_url,
            "credential_endpoint": format!("{issuer_url}/credential"),
            "credential_configurations_supported": {
                "DigitalID": {
                    "format": "jwt_vc_json"
                }
            }
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-authorization-server"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": issuer_url,
            "authorization_endpoint": format!("{issuer_url}/authorize"),
            "token_endpoint": format!("{issuer_url}/token"),
            "response_types_supported": ["code"],
            "grant_types_supported": ["urn:ietf:params:oauth:grant-type:pre-authorized_code"],
            "code_challenge_methods_supported": ["S256"],
            "pre_authorized_grant_anonymous_access_supported": true
        })))
        .mount(&mock_server)
        .await;

    let base_url = utils::spawn_server().await;
    let client = Client::new();

    let response = client
        .post(format!("{}/api/v1/issuance/start", base_url))
        .json(&json!({ "offer": offer_uri }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 201);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body.get("flow").unwrap(), "pre_authorized_code");
    assert_eq!(body.get("tx_code_required").unwrap(), false);
    assert!(body.get("tx_code").unwrap().is_null());
}

#[tokio::test]
async fn start_issuance_empty_offer_returns_400() {
    let base_url = utils::spawn_server().await;
    let client = Client::new();

    let response = client
        .post(format!("{}/api/v1/issuance/start", base_url))
        .json(&json!({ "offer": "" }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 400);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body.get("error").unwrap(), "invalid_credential_offer");
}

#[tokio::test]
async fn start_issuance_multiple_credential_types_returns_201() {
    let mock_server = MockServer::start().await;
    let issuer_url = mock_server.uri();

    let offer = CredentialOfferData {
        credential_issuer: issuer_url.clone(),
        credential_configuration_ids: vec![
            "eu.europa.ec.eudi.pid.1".to_string(),
            "eu.europa.ec.eudi.mdl.1".to_string(),
        ],
        grants: Some(Grants {
            authorization_code: Some(AuthorizationCodeGrant {
                issuer_state: Some("state_multi".to_string()),
                authorization_server: None,
            }),
            pre_authorized_code: None,
        }),
    };
    let offer_json = serde_json::to_string(&offer).unwrap();
    let offer_uri = format!(
        "openid-credential-offer://?credential_offer={}",
        urlencoding::encode(&offer_json)
    );

    Mock::given(method("GET"))
        .and(path("/.well-known/openid-credential-issuer"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "credential_issuer": issuer_url,
            "credential_endpoint": format!("{issuer_url}/credential"),
            "credential_configurations_supported": {
                "eu.europa.ec.eudi.pid.1": {
                    "format": "vc+sd-jwt",
                    "display": [{
                        "name": "EU PID",
                        "locale": "en-US"
                    }]
                },
                "eu.europa.ec.eudi.mdl.1": {
                    "format": "mso_mdoc",
                    "display": [{
                        "name": "EU MDL",
                        "locale": "en-US"
                    }]
                }
            }
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-authorization-server"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": issuer_url,
            "authorization_endpoint": format!("{issuer_url}/authorize"),
            "token_endpoint": format!("{issuer_url}/token"),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "code_challenge_methods_supported": ["S256"]
        })))
        .mount(&mock_server)
        .await;

    let base_url = utils::spawn_server().await;
    let client = Client::new();

    let response = client
        .post(format!("{}/api/v1/issuance/start", base_url))
        .json(&json!({ "offer": offer_uri }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 201);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    let credential_types = body.get("credential_types").unwrap().as_array().unwrap();
    assert_eq!(credential_types.len(), 2);
    assert_eq!(
        credential_types[0]
            .get("credential_configuration_id")
            .unwrap(),
        "eu.europa.ec.eudi.pid.1"
    );
    assert_eq!(
        credential_types[1]
            .get("credential_configuration_id")
            .unwrap(),
        "eu.europa.ec.eudi.mdl.1"
    );
}

#[tokio::test]
async fn start_issuance_invalid_offer_uri_returns_error() {
    let base_url = utils::spawn_server().await;
    let client = Client::new();

    let response = client
        .post(format!("{}/api/v1/issuance/start", base_url))
        .json(&json!({ "offer": "not-a-valid-uri" }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 400);
}

#[tokio::test]
async fn start_issuance_unreachable_issuer_returns_bad_gateway() {
    let offer = CredentialOfferData {
        credential_issuer: "https://non-existent-issuer-12345.example.com".to_string(),
        credential_configuration_ids: vec!["TestCredential".to_string()],
        grants: Some(Grants {
            authorization_code: Some(AuthorizationCodeGrant {
                issuer_state: Some("state".to_string()),
                authorization_server: None,
            }),
            pre_authorized_code: None,
        }),
    };
    let offer_json = serde_json::to_string(&offer).unwrap();
    let offer_uri = format!(
        "openid-credential-offer://?credential_offer={}",
        urlencoding::encode(&offer_json)
    );

    let base_url = utils::spawn_server().await;
    let client = Client::new();

    let response = client
        .post(format!("{}/api/v1/issuance/start", base_url))
        .json(&json!({ "offer": offer_uri }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 502);
}
