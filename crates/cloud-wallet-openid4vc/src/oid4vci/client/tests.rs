use super::*;
use cloud_wallet_crypto::ecdsa::{Curve, KeyPair as EcdsaKeyPair};
use reqwest_middleware::ClientBuilder;
use reqwest_retry::RetryTransientMiddleware;
use reqwest_retry::policies::ExponentialBackoff;
use std::sync::Arc;
use std::time::Duration;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::core::client::Config;
use crate::oid4vci::credential::offer::{Grants, PreAuthorizedCodeGrant};

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
    let inner_client = OidClient {
        config: Arc::new(config),
        http_client,
    };
    Oid4vciClient::new(inner_client)
}

#[test]
fn parse_authorization_callback_success_query() {
    let callback =
        Oid4vciClient::parse_authorization_callback("code=abc123&state=ses_123").unwrap();

    match callback {
        AuthorizationCallback::Success(response) => {
            assert_eq!(response.code, "abc123");
            assert_eq!(response.state.as_deref(), Some("ses_123"));
        }
        other => panic!("expected success callback, got {other:?}"),
    }
}

#[test]
fn parse_authorization_callback_error_query() {
    let callback = Oid4vciClient::parse_authorization_callback(
        "error=access_denied&error_description=User+cancelled&state=ses_123",
    )
    .unwrap();

    match callback {
        AuthorizationCallback::Error(response) => {
            assert_eq!(response.error.error, AuthzErrorResponse::AccessDenied);
            assert_eq!(
                response.error.error_description.as_deref(),
                Some("User cancelled")
            );
            assert_eq!(response.state.as_deref(), Some("ses_123"));
        }
        other => panic!("expected error callback, got {other:?}"),
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
        as_metadata,
        flow: flow_type,
    };

    // Exchange Token
    let token = client
        .exchange_pre_authorized_code(
            &context,
            "test_code_abc",
            None::<String>,
            &["UniversityDegreeCredential".to_string()],
            None,
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
        .request_credentials(&context, &token, &signer, None)
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

#[tokio::test]
async fn test_dpop_proof_attached_to_token_request() {
    use base64::Engine;

    let mock_server = setup_mock_server().await;
    let issuer_url = mock_server.uri();

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

    let token_response = serde_json::json!({
        "access_token": "dpop_test_access_token",
        "token_type": "DPoP",
        "expires_in": 3600,
        "authorization_details": [{
            "type": "openid_credential",
            "credential_configuration_id": "UniversityDegreeCredential",
            "credential_identifiers": ["UniversityDegreeCredential"]
        }]
    });

    let token_guard = Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(token_response))
        .named("token_with_dpop")
        .mount_as_scoped(&mock_server)
        .await;

    let nonce_response = serde_json::json!({
        "c_nonce": "test_nonce_dpop_123"
    });

    Mock::given(method("POST"))
        .and(path("/nonce"))
        .respond_with(ResponseTemplate::new(200).set_body_json(nonce_response))
        .mount(&mock_server)
        .await;

    let client = create_client();

    let offer = CredentialOffer {
        credential_issuer: Url::parse(&issuer_url).unwrap(),
        credential_configuration_ids: vec!["UniversityDegreeCredential".to_string()],
        grants: Some(Grants {
            authorization_code: None,
            pre_authorized_code: Some(PreAuthorizedCodeGrant {
                pre_authorized_code: "test_code_dpop".to_string(),
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

    as_metadata.authorization_endpoint =
        Some(Url::parse(&format!("{issuer_url}/authorize")).unwrap());
    as_metadata.token_endpoint = Some(Url::parse(&format!("{issuer_url}/token")).unwrap());
    as_metadata.pushed_authorization_request_endpoint =
        Some(Url::parse(&format!("{issuer_url}/par")).unwrap());

    let flow_type = IssuanceFlow::PreAuthorizedCode {
        pre_authorized_code: "test_code_dpop".to_string(),
        tx_code: None,
    };

    let mut issuer_metadata = issuer_metadata;
    issuer_metadata.credential_endpoint = Url::parse(&format!("{issuer_url}/credential")).unwrap();
    issuer_metadata.nonce_endpoint = Some(Url::parse(&format!("{issuer_url}/nonce")).unwrap());

    let context = ResolvedOfferContext {
        offer,
        issuer_metadata,
        as_metadata,
        flow: flow_type,
    };

    let dpop_key = DpopKeyPair::generate().expect("DPoP key generation should succeed");
    let dpop_opts = DpopOptions {
        key: &dpop_key,
        nonce_handler: None,
    };

    let token = client
        .exchange_pre_authorized_code(
            &context,
            "test_code_dpop",
            None::<String>,
            &["UniversityDegreeCredential".to_string()],
            Some(&dpop_opts),
        )
        .await
        .expect("token exchange with DPoP key should succeed");

    assert_eq!(token.access_token, "dpop_test_access_token");
    assert_eq!(token.token_type, "DPoP");

    let requests = token_guard.received_requests().await;
    let dpop_header = requests
        .first()
        .expect("should have received a token request")
        .headers
        .get("DPoP")
        .expect("DPoP header must be present")
        .to_str()
        .unwrap();
    let parts: Vec<&str> = dpop_header.split('.').collect();
    assert_eq!(parts.len(), 3, "DPoP header must be a 3-part JWT");

    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[0])
        .expect("header should be valid base64url");
    let header: serde_json::Value =
        serde_json::from_slice(&header_bytes).expect("header should be valid JSON");
    assert_eq!(header["typ"], "dpop+jwt", "header typ must be dpop+jwt");
    assert_eq!(header["alg"], "ES256", "header alg must be ES256");
    assert!(
        header["jwk"]["kty"] == "EC",
        "header jwk must be an EC key"
    );

    let claims_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("claims should be valid base64url");
    let claims: serde_json::Value =
        serde_json::from_slice(&claims_bytes).expect("claims should be valid JSON");
    assert_eq!(claims["htm"], "POST", "claims htm must be POST");
    assert!(
        claims["htu"].is_string(),
        "claims htu must be present"
    );
    assert!(
        claims["jti"].is_string(),
        "claims jti must be present"
    );
    assert!(
        claims["iat"].is_number(),
        "claims iat must be present"
    );
    assert!(
        claims.get("ath").is_none(),
        "token request should not include ath claim"
    );

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let signature_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[2])
        .expect("signature should be valid base64url");
    dpop_key
        .verify_signature(signing_input.as_bytes(), &signature_bytes)
        .expect("DPoP proof signature should verify with public key");
}

#[tokio::test]
async fn test_dpop_use_nonce_retry_flow() {
    let mock_server = setup_mock_server().await;
    let issuer_url = mock_server.uri();

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

    let success_token_response = serde_json::json!({
        "access_token": "dpop_retry_access_token",
        "token_type": "DPoP",
        "expires_in": 3600,
        "authorization_details": [{
            "type": "openid_credential",
            "credential_configuration_id": "UniversityDegreeCredential",
            "credential_identifiers": ["UniversityDegreeCredential"]
        }]
    });

    let use_nonce_body = serde_json::json!({"error": "use_nonce"}).to_string();

    let nonce_handler = DpopNonceHandler::new();

    let dpop_key = DpopKeyPair::generate().expect("DPoP key generation should succeed");

    let client = create_client();

    let offer = CredentialOffer {
        credential_issuer: Url::parse(&issuer_url).unwrap(),
        credential_configuration_ids: vec!["UniversityDegreeCredential".to_string()],
        grants: Some(Grants {
            authorization_code: None,
            pre_authorized_code: Some(PreAuthorizedCodeGrant {
                pre_authorized_code: "test_code_retry".to_string(),
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

    as_metadata.authorization_endpoint =
        Some(Url::parse(&format!("{issuer_url}/authorize")).unwrap());
    as_metadata.token_endpoint = Some(Url::parse(&format!("{issuer_url}/token")).unwrap());
    as_metadata.pushed_authorization_request_endpoint =
        Some(Url::parse(&format!("{issuer_url}/par")).unwrap());

    let flow_type = IssuanceFlow::PreAuthorizedCode {
        pre_authorized_code: "test_code_retry".to_string(),
        tx_code: None,
    };

    let mut issuer_metadata = issuer_metadata;
    issuer_metadata.credential_endpoint = Url::parse(&format!("{issuer_url}/credential")).unwrap();
    issuer_metadata.nonce_endpoint = Some(Url::parse(&format!("{issuer_url}/nonce")).unwrap());

    let context = ResolvedOfferContext {
        offer,
        issuer_metadata,
        as_metadata,
        flow: flow_type,
    };

    let dpop_opts = DpopOptions {
        key: &dpop_key,
        nonce_handler: Some(&nonce_handler),
    };

    // First request to /token returns 400 use_nonce with DPoP-Nonce header
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_string(&use_nonce_body)
                .insert_header("DPoP-Nonce", "server-provided-nonce-123"),
        )
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    // Subsequent requests to /token return success
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(success_token_response))
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/nonce"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "c_nonce": "test_nonce_retry"
        })))
        .mount(&mock_server)
        .await;

    let result = client
        .exchange_pre_authorized_code(
            &context,
            "test_code_retry",
            None::<String>,
            &["UniversityDegreeCredential".to_string()],
            Some(&dpop_opts),
        )
        .await;

    assert!(
        result.is_ok(),
        "use_nonce retry should succeed: {:?}",
        result.err()
    );
    assert_eq!(result.unwrap().access_token, "dpop_retry_access_token");

    let stored_nonce = nonce_handler.get_nonce(&htu_from_url(&Url::parse(&format!("{issuer_url}/token")).unwrap()).unwrap());
    assert_eq!(
        stored_nonce,
        Some("server-provided-nonce-123".to_string()),
        "nonce handler should store the server-provided nonce after retry"
    );
}

#[tokio::test]
async fn test_dpop_nonce_handler_stores_nonce() {
    let handler = DpopNonceHandler::new();
    assert!(
        handler
            .get_nonce("https://issuer.example.com/token")
            .is_none()
    );

    handler.store_nonce("https://issuer.example.com/token", "server-nonce-456");
    assert_eq!(
        handler.get_nonce("https://issuer.example.com/token"),
        Some("server-nonce-456".to_string())
    );

    let cloned = handler.clone();
    assert_eq!(
        cloned.get_nonce("https://issuer.example.com/token"),
        Some("server-nonce-456".to_string())
    );
}

#[tokio::test]
async fn test_htu_from_url_validation() {
    let valid_url = url::Url::parse("https://issuer.example.com/token").unwrap();
    assert!(htu_from_url(&valid_url).is_ok());
    assert_eq!(
        htu_from_url(&valid_url).unwrap(),
        "https://issuer.example.com/token"
    );

    let ftp_url = url::Url::parse("ftp://issuer.example.com/resource").unwrap();
    assert!(htu_from_url(&ftp_url).is_err());

    let url_with_port = url::Url::parse("https://issuer.example.com:8443/credential").unwrap();
    assert_eq!(
        htu_from_url(&url_with_port).unwrap(),
        "https://issuer.example.com:8443/credential"
    );
}
