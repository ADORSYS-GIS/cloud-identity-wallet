use super::*;
use cloud_wallet_crypto::ecdsa::{Curve, KeyPair as EcdsaKeyPair};
use std::time::Duration;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::issuance::credential_offer::{Grants, PreAuthorizedCodeGrant};

// Basic test server setup
async fn setup_mock_server() -> MockServer {
    MockServer::start().await
}

fn create_client() -> Oid4vciClient {
    let config = Config::new(
        "test_client_id",
        Url::parse("https://client.example.org/cb").unwrap(),
    )
    .timeout(Duration::from_secs(5))
    .accept_untrusted_hosts(true);
    let builder = reqwest::Client::builder().timeout(config.timeout);
    let inner_client = builder.build().unwrap();
    let retry_policy = ExponentialBackoff::builder().build_with_max_retries(0);
    let http_client = ClientBuilder::new(inner_client)
        .with(RetryTransientMiddleware::new_with_policy(retry_policy))
        .build();
    Oid4vciClient {
        config: Arc::new(config),
        http_client,
    }
}

fn get_ecdsa_signer() -> CryptoSigner {
    let keypair = EcdsaKeyPair::generate(Curve::P256).unwrap();
    let der = keypair.to_pkcs8_der().to_vec();
    CryptoSigner::from_ecdsa_der(&der).unwrap()
}

#[tokio::test]
async fn test_fetch_issuer_metadata_success() {
    let mock_server = setup_mock_server().await;

    // Mock response for issuer metadata
    let metadata_json = serde_json::json!({
        "credential_issuer": mock_server.uri(),
        "credential_endpoint": format!("{}/credential", mock_server.uri()),
        "credential_configurations_supported": {
            "UniversityDegreeCredential": {
                "format": "jwt_vc_json",
                "cryptographic_binding_methods_supported": ["jwk"],
                "credential_signing_alg_values_supported": ["ES256"],
                "proof_types_supported": {
                    "jwt": {
                        "proof_signing_alg_values_supported": ["ES256"]
                    }
                }
            }
        }
    });

    Mock::given(method("GET"))
        .and(path("/.well-known/openid-credential-issuer"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata_json))
        .mount(&mock_server)
        .await;

    let client = create_client();
    let issuer_url = Url::parse(&mock_server.uri()).unwrap();

    let result = client.fetch_issuer_metadata(&issuer_url).await;
    assert!(result.is_ok());
    let metadata = result.unwrap();
    assert_eq!(
        metadata.credential_issuer.as_str().trim_end_matches('/'),
        mock_server.uri().trim_end_matches('/')
    );
}

#[tokio::test]
async fn test_issuance_flow() {
    let mock_server = setup_mock_server().await;
    let issuer_url = mock_server.uri();

    // Mock Issuer Metadata
    let metadata_json = serde_json::json!({
        "credential_issuer": issuer_url,
        "credential_endpoint": format!("{issuer_url}/credential"),
        "nonce_endpoint": format!("{issuer_url}/nonce"),
        "authorization_servers": [issuer_url],
        "credential_configurations_supported": {
            "UniversityDegreeCredential": {
                "format": "jwt_vc_json",
                "cryptographic_binding_methods_supported": ["jwk"],
                "credential_signing_alg_values_supported": ["ES256"],
                "proof_types_supported": {
                    "jwt": {
                        "proof_signing_alg_values_supported": ["ES256"]
                    }
                }
            }
        }
    });

    Mock::given(method("GET"))
        .and(path("/.well-known/openid-credential-issuer"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata_json))
        .mount(&mock_server)
        .await;

    // Mock AS Metadata
    // For test, we make the issuer claim inside the metadata start with https to pass validation
    // because AS metadata strictly enforces issuer == https
    let as_metadata_json = serde_json::json!({
        "issuer": issuer_url.replace("http://", "https://"),
        "authorization_endpoint": format!("{issuer_url}/authorize").replace("http://", "https://"),
        "token_endpoint": format!("{issuer_url}/token").replace("http://", "https://"),
        "pushed_authorization_request_endpoint": format!("{issuer_url}/par").replace("http://", "https://"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"]
    });

    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-authorization-server"))
        .respond_with(ResponseTemplate::new(200).set_body_json(as_metadata_json))
        .mount(&mock_server)
        .await;

    // Mock Token Response
    let token_response = serde_json::json!({
        "access_token": "test_access_token_123",
        "token_type": "Bearer",
        "expires_in": 3600,
        "authorization_details": [{
            "type": "openid_credential",
            "credential_configuration_id": "UniversityDegreeCredential",
            "credential_identifiers": ["UniversityDegreeCredential"]
        }]
    });

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(token_response))
        .mount(&mock_server)
        .await;

    // Mock Nonce Response
    let nonce_response = serde_json::json!({
        "c_nonce": "wKI4LT17ac15ES9bw8ac4"
    });

    Mock::given(method("POST"))
        .and(path("/nonce"))
        .respond_with(ResponseTemplate::new(200).set_body_json(nonce_response))
        .mount(&mock_server)
        .await;

    // Execute Flow
    let client = create_client();

    // Resolve Offer
    // We construct the ResolvedOfferContext manually to bypass HTTPS validation
    // that would normally be enforced by CredentialOffer::validate().
    let offer = CredentialOffer {
        credential_issuer: Url::parse(&issuer_url).unwrap(),
        credential_configuration_ids: vec!["UniversityDegreeCredential".to_string()],
        grants: Some(Grants {
            authorization_code: None,
            pre_authorized_code: Some(PreAuthorizedCodeGrant {
                pre_authorized_code: "test_code_abc".to_string(),
                tx_code: None,
                authorization_server: None,
            }),
        }),
    };

    let issuer_metadata = client
        .fetch_issuer_metadata(&Url::parse(&issuer_url).unwrap())
        .await
        .unwrap();

    let mut as_metadata = client
        .fetch_as_metadata(&Url::parse(&issuer_url).unwrap(), &issuer_metadata, &offer)
        .await
        .unwrap();

    // After parsing, modify endpoints back to http so reqwest can actually hit mock server
    as_metadata.authorization_endpoint =
        Some(Url::parse(&format!("{issuer_url}/authorize")).unwrap());
    as_metadata.token_endpoint = Some(Url::parse(&format!("{issuer_url}/token")).unwrap());
    as_metadata.pushed_authorization_request_endpoint =
        Some(Url::parse(&format!("{issuer_url}/par")).unwrap());

    let flow_type = IssuanceFlow::PreAuthorizedCode {
        pre_authorized_code: "test_code_abc".to_string(),
        tx_code: None,
    };

    let mut issuer_metadata = issuer_metadata;
    // Modify credential endpoints back to HTTP for requests to actually succeed
    issuer_metadata.credential_endpoint = Url::parse(&format!("{issuer_url}/credential")).unwrap();
    issuer_metadata.nonce_endpoint = Some(Url::parse(&format!("{issuer_url}/nonce")).unwrap());

    let context = ResolvedOfferContext {
        offer,
        issuer_metadata,
        as_metadata: Some(as_metadata),
        flow: flow_type,
    };

    // Exchange Token
    let token = client
        .exchange_pre_authorized_code(
            &context,
            "test_code_abc",
            None::<String>,
            &["UniversityDegreeCredential".to_string()],
        )
        .await
        .expect("Failed to exchange token");
    assert_eq!(token.access_token, "test_access_token_123");

    // Request Credential
    let signer = get_ecdsa_signer();

    // Mock Credential Endpoint
    let mock_credential_resp = serde_json::json!({
        "credentials": [{"credential": "test_credential_jwt_string"}]
    });
    Mock::given(method("POST"))
        .and(path("/credential"))
        .respond_with(ResponseTemplate::new(200).set_body_json(mock_credential_resp))
        .mount(&mock_server)
        .await;

    let credentials = client
        .request_credentials(&context, &token, &signer)
        .await
        .expect("Failed to request credentials");

    assert_eq!(credentials.len(), 1);
    match &credentials[0] {
        CredentialResponse::Immediate(cred) => {
            assert_eq!(
                cred.credentials[0].credential.as_str().unwrap(),
                "test_credential_jwt_string"
            );
        }
        _ => panic!("Expected immediate credential response"),
    }
}
