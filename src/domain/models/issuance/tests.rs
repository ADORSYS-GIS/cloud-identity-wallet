use parking_lot::Mutex;
use std::collections::VecDeque;
use std::sync::Arc;

use async_trait::async_trait;
use cloud_wallet_crypto::ecdsa::{Curve as EcdsaCurve, KeyPair as EcdsaKeyPair};
use cloud_wallet_openid4vc::{
    core::client::{Config as Oid4vciClientConfig, OidClient},
    oid4vci::credential::formats::{
        MsoMdocCredentialConfiguration, SdJwtVcCredentialConfiguration,
    },
    oid4vci::metadata::CredentialConfiguration,
    oid4vci::metadata::CredentialDisplay,
};
use jsonwebtoken::{Algorithm as JwtAlgorithm, EncodingKey, Header};
use url::Url;

use super::*;
use crate::outbound::{
    MemoryCredentialRepo, MemoryEventPublisher, MemoryEventSubscriber, MemoryTenantRepo,
};
use crate::session::MemorySession;

#[derive(Debug, Clone, Default)]
struct RecordingTaskQueue {
    state: Arc<Mutex<RecordingTaskQueueState>>,
}

#[derive(Debug, Default)]
struct RecordingTaskQueueState {
    next_id: u64,
    queued: VecDeque<IssuanceTask>,
    acked: Vec<IssuanceTask>,
}

impl RecordingTaskQueue {
    fn acked(&self) -> Vec<IssuanceTask> {
        self.state.lock().acked.clone()
    }

    fn queued_len(&self) -> usize {
        self.state.lock().queued.len()
    }
}

#[async_trait]
impl IssuanceTaskQueue for RecordingTaskQueue {
    async fn push(&self, task: &IssuanceTask) -> Result<()> {
        self.state.lock().queued.push_back(task.clone());
        Ok(())
    }

    async fn pop(&self) -> Result<Option<IssuanceTask>> {
        let mut state = self.state.lock();
        let Some(mut task) = state.queued.pop_front() else {
            return Ok(None);
        };

        state.next_id += 1;
        task.queue_id = Some(format!("queue-{}", state.next_id));
        Ok(Some(task))
    }

    async fn ack(&self, task: &IssuanceTask) -> Result<()> {
        self.state.lock().acked.push(task.clone());
        Ok(())
    }
}

fn make_engine(queue: RecordingTaskQueue) -> IssuanceEngine {
    let inner_client = OidClient::new(Oid4vciClientConfig::new(
        "test-client",
        Url::parse("https://wallet.example.com/callback").unwrap(),
    ))
    .unwrap();
    let client = Oid4vciClient::new(inner_client);

    let sessions = MemorySession::default();
    let publisher = MemoryEventPublisher::new(16);

    IssuanceEngine::with_worker_count(
        client,
        queue,
        publisher.clone(),
        MemoryEventSubscriber::new(&publisher),
        MemoryCredentialRepo::new(),
        MemoryTenantRepo::new(),
        &sessions,
        vec!["en".to_owned()],
        1,
    )
}

fn make_task(session_id: &str) -> IssuanceTask {
    IssuanceTask {
        queue_id: None,
        session_id: session_id.to_owned(),
        tenant_id: Uuid::new_v4(),
        flow: FlowType::PreAuthorizedCode,
        authorization_code: None,
        pkce_verifier: None,
        pre_authorized_code: Some("pre-auth-code".to_owned()),
        tx_code: None,
    }
}

fn sd_jwt_config(vct: &str) -> CredentialConfiguration {
    CredentialConfiguration {
        id: None,
        format_details: CredentialFormatDetails::DcSdJwt(SdJwtVcCredentialConfiguration {
            vct: vct.to_owned(),
        }),
        scope: None,
        cryptographic_binding_methods_supported: None,
        credential_signing_alg_values_supported: None,
        proof_types_supported: None,
        credential_metadata: None,
    }
}

fn signed_sd_jwt(claims: serde_json::Value) -> String {
    let key_pair = EcdsaKeyPair::generate(EcdsaCurve::P256).expect("key generation works");
    let mut header = Header::new(JwtAlgorithm::ES256);
    header.typ = Some("dc+sd-jwt".to_owned());

    let token = jsonwebtoken::encode(
        &header,
        &claims,
        &EncodingKey::from_ec_der(key_pair.to_pkcs8_der()),
    )
    .expect("test JWT should sign");
    format!("{token}~")
}

#[tokio::test]
async fn enqueue_persists_work_without_acknowledging_it() {
    let queue = RecordingTaskQueue::default();
    let engine = make_engine(queue.clone());

    engine.enqueue(&make_task("ses_enqueue")).await.unwrap();

    assert_eq!(queue.queued_len(), 1);
    assert!(queue.acked().is_empty());
}

#[tokio::test]
async fn processing_next_task_claims_and_acks_the_popped_task() {
    let queue = RecordingTaskQueue::default();
    let engine = make_engine(queue.clone());
    let sessions = MemorySession::default();

    engine.enqueue(&make_task("ses_missing")).await.unwrap();
    let result = engine.process_next_task(&sessions).await;

    assert!(result.is_err(), "missing session should fail terminally");
    assert_eq!(queue.queued_len(), 0);

    let acked = queue.acked();
    assert_eq!(acked.len(), 1);
    assert_eq!(acked[0].session_id, "ses_missing");
    assert_eq!(acked[0].queue_id.as_deref(), Some("queue-1"));
}

#[tokio::test]
async fn processing_empty_queue_reports_no_work() {
    let queue = RecordingTaskQueue::default();
    let engine = make_engine(queue);
    let sessions = MemorySession::default();

    let processed = engine.process_next_task(&sessions).await.unwrap();

    assert!(!processed);
}

#[tokio::test]
async fn sd_jwt_metadata_is_persisted_and_retrieved() {
    let tenant_id = Uuid::new_v4();
    let issued_at = time::UtcDateTime::now().unix_timestamp();
    let valid_until = issued_at + 3600;
    let raw = signed_sd_jwt(serde_json::json!({
        "iss": "https://issuer.example.com",
        "sub": "did:example:alice",
        "iat": issued_at,
        "exp": valid_until,
        "vct": "https://credentials.example.com/test",
        "status": {
            "status_list": {
                "idx": 42,
                "uri": "https://issuer.example.com/status/1"
            }
        }
    }));
    let sd_jwt = SdJwt::parse(&raw).expect("signed SD-JWT should parse");

    let credential = credential_from_sd_jwt(
        tenant_id,
        "https://fallback-issuer.example.com",
        sd_jwt.into_jwt().into_claims(),
        raw.clone(),
        time::UtcDateTime::from_unix_timestamp(issued_at).unwrap(),
    )
    .unwrap();
    let repo = MemoryCredentialRepo::new();
    let id = repo.upsert(credential, None).await.unwrap();

    let stored = repo.find_by_id(id, tenant_id).await.unwrap();

    assert_eq!(stored.issuer, "https://issuer.example.com");
    assert_eq!(stored.subject.as_deref(), Some("did:example:alice"));
    assert_eq!(
        stored.credential_types,
        vec!["https://credentials.example.com/test".to_owned()]
    );
    assert_eq!(stored.format, CredentialFormat::SdJwtVc);
    assert_eq!(
        stored.issued_at,
        time::UtcDateTime::from_unix_timestamp(issued_at).unwrap()
    );
    assert_eq!(
        stored.valid_until,
        Some(time::UtcDateTime::from_unix_timestamp(valid_until).unwrap())
    );
    assert_eq!(
        stored.status_location.as_ref().map(Url::as_str),
        Some("https://issuer.example.com/status/1")
    );
    assert_eq!(stored.status_index, Some(42));
    assert_eq!(stored.external_id.as_deref(), None);
}

#[tokio::test]
async fn unsupported_credential_format_is_rejected_during_storage_mapping() {
    let engine = make_engine(RecordingTaskQueue::default());
    let config = CredentialConfiguration {
        id: None,
        format_details: CredentialFormatDetails::MsoMdoc(MsoMdocCredentialConfiguration {
            doctype: "org.iso.18013.5.1.mDL".to_owned(),
        }),
        scope: None,
        cryptographic_binding_methods_supported: None,
        credential_signing_alg_values_supported: None,
        proof_types_supported: None,
        credential_metadata: None,
    };

    let result = engine
        .build_credential(
            Uuid::new_v4(),
            "https://issuer.example.com",
            &config,
            "raw-mdoc".to_owned(),
            time::UtcDateTime::now(),
        )
        .await;

    assert!(result.is_err());
}

#[test]
fn sd_jwt_alg_allow_list_is_enforced_when_present() {
    let mut config = sd_jwt_config("https://credentials.example.com/test");
    config.credential_signing_alg_values_supported = Some(vec![
        cloud_wallet_openid4vc::oid4vci::metadata::AlgorithmIdentifier::from("ES256"),
    ]);

    validate_credential_signing_alg(&config, JwtAlgorithm::ES256).unwrap();
    assert!(validate_credential_signing_alg(&config, JwtAlgorithm::RS256).is_err());
}

#[test]
fn sd_jwt_vct_mismatch_is_rejected_before_mapping() {
    let config = sd_jwt_config("https://credentials.example.com/expected");
    let raw = signed_sd_jwt(serde_json::json!({
        "iss": "https://issuer.example.com",
        "vct": "https://credentials.example.com/actual"
    }));
    let sd_jwt = SdJwt::parse(&raw).expect("signed SD-JWT should parse");
    let CredentialFormatDetails::DcSdJwt(sd_config) = &config.format_details else {
        panic!("test config should be SD-JWT VC");
    };

    let result = if sd_jwt.jwt().claims().vct != sd_config.vct {
        Err(IssuanceError::credential_request("vct mismatch"))
    } else {
        credential_from_sd_jwt(
            Uuid::new_v4(),
            "https://fallback-issuer.example.com",
            sd_jwt.into_jwt().into_claims(),
            raw.clone(),
            time::UtcDateTime::now(),
        )
        .map(|_| ())
    };
    assert!(result.is_err());
}

#[test]
fn select_preferred_chooses_locale_by_prefix() {
    // Arrange: two display entries; French listed second.
    let entries = vec![
        CredentialDisplay {
            name: "English".to_owned(),
            locale: Some("en-US".to_owned()),
            ..Default::default()
        },
        CredentialDisplay {
            name: "French".to_owned(),
            locale: Some("fr-FR".to_owned()),
            ..Default::default()
        },
    ];
    let preferred = vec!["fr".to_owned()];

    // Act
    let result = select_preferred(&entries, |d| d.locale.as_deref(), &preferred);

    // Assert: the French entry is selected even though it is listed second.
    assert!(result.is_some());
    assert_eq!(result.unwrap().name, "French");
}

#[test]
fn select_preferred_falls_back_to_first_when_no_match() {
    let entries = vec![CredentialDisplay {
        name: "English".to_owned(),
        locale: Some("en-US".to_owned()),
        ..Default::default()
    }];
    let preferred = vec!["fr".to_owned()];

    // Act: preferred locale not present — should fall back to first entry.
    let result = select_preferred(&entries, |d| d.locale.as_deref(), &preferred);

    assert!(result.is_some());
    assert_eq!(result.unwrap().name, "English");
}
