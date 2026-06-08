use parking_lot::Mutex;
use std::collections::VecDeque;
use std::sync::Arc;

use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use ciborium::Value;
use cloud_wallet_crypto::ecdsa::{Curve, KeyPair as EcdsaKeyPair};
use cloud_wallet_crypto::jwk::Key;
use cloud_wallet_openid4vc::{
    core::client::{Config as Oid4vciClientConfig, OidClient},
    formats::mdoc::StaticTrustStore,
    oid4vci::client::CryptoSigner,
    oid4vci::credential::formats::{
        MsoMdocCredentialConfiguration, SdJwtVcCredentialConfiguration,
    },
    oid4vci::metadata::CredentialConfiguration,
    oid4vci::metadata::CredentialDisplay,
};
use jsonwebtoken::{Algorithm as JwtAlgorithm, EncodingKey, Header};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair as CertKeyPair, KeyUsagePurpose,
};
use time::OffsetDateTime;
use url::Url;
use webpki::anchor_from_trusted_cert;

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

/// Creates an [`IssuanceEngine`] wired with a real IACA trust store and a
/// pre-registered P-256 test tenant.  Returns the engine together with the
/// registered tenant's UUID so negative-path mdoc tests can exercise the
/// full `build_credential` path without hitting `TenantNotFound` before the
/// verification under test.
async fn make_mdoc_engine(queue: RecordingTaskQueue, iaca_der: Vec<u8>) -> (IssuanceEngine, Uuid) {
    let tenant_repo = MemoryTenantRepo::new();
    let res = tenant_repo
        .create(crate::domain::models::tenants::RegisterTenantRequest {
            name: "test-mdoc".to_owned(),
        })
        .await
        .unwrap();
    let tenant_id = Uuid::parse_str(&res.tenant_id).unwrap();

    let inner_client = OidClient::new(Oid4vciClientConfig::new(
        "test-client",
        Url::parse("https://wallet.example.com/callback").unwrap(),
    ))
    .unwrap();
    let publisher = MemoryEventPublisher::new(16);
    let sessions = MemorySession::default();
    let engine = IssuanceEngine::with_worker_count(
        Oid4vciClient::new(inner_client),
        queue,
        publisher.clone(),
        MemoryEventSubscriber::new(&publisher),
        MemoryCredentialRepo::new(),
        tenant_repo,
        &sessions,
        vec!["en".to_owned()],
        1,
    )
    .with_iaca_trust_store(StaticTrustStore::new(vec![iaca_der]));

    (engine, tenant_id)
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

struct X5cSdJwt {
    raw: String,
    trust_anchor: rustls_pki_types::TrustAnchor<'static>,
}

fn signed_x5c_sd_jwt(claims: serde_json::Value) -> X5cSdJwt {
    let root_key = CertKeyPair::generate().expect("root key generation works");
    let mut root_params = CertificateParams::default();
    root_params.distinguished_name = DistinguishedName::new();
    root_params
        .distinguished_name
        .push(DnType::CommonName, "Test Root CA");
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let root_cert = root_params
        .self_signed(&root_key)
        .expect("root certificate should sign");
    let trust_anchor = anchor_from_trusted_cert(root_cert.der())
        .expect("root certificate should become trust anchor")
        .to_owned();
    let root_issuer = Issuer::new(root_params, root_key);

    let leaf_key = CertKeyPair::generate().expect("leaf key generation works");
    let mut leaf_params =
        CertificateParams::new(["issuer.example.com".to_owned()]).expect("leaf params build");
    leaf_params.distinguished_name = DistinguishedName::new();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "issuer.example.com");
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &root_issuer)
        .expect("leaf certificate should sign");

    let mut header = Header::new(JwtAlgorithm::ES256);
    header.typ = Some("dc+sd-jwt".to_owned());
    header.x5c = Some(vec![STANDARD.encode(leaf_cert.der().as_ref())]);

    let token = jsonwebtoken::encode(
        &header,
        &claims,
        &EncodingKey::from_ec_der(&leaf_key.serialize_der()),
    )
    .expect("test JWT should sign");

    X5cSdJwt {
        raw: format!("{token}~"),
        trust_anchor,
    }
}

fn tamper_jwt_signature(raw: &str) -> String {
    let token = raw.strip_suffix('~').expect("issued SD-JWT has trailing ~");
    let (signed_part, signature) = token.rsplit_once('.').expect("JWT has signature segment");
    let mut signature = signature.to_owned();
    let replacement = if signature.starts_with('A') { "B" } else { "A" };
    signature.replace_range(0..1, replacement);
    format!("{signed_part}.{signature}~")
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
    let fixture = signed_x5c_sd_jwt(serde_json::json!({
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
    let engine = make_engine(RecordingTaskQueue::default())
        .with_x5c_trust_anchors(vec![fixture.trust_anchor]);
    let config = sd_jwt_config("https://credentials.example.com/test");

    let credential = engine
        .build_credential(
            tenant_id,
            "https://issuer.example.com",
            &config,
            fixture.raw,
            time::UtcDateTime::from_unix_timestamp(issued_at).unwrap(),
        )
        .await
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
async fn sd_jwt_tampered_signature_is_rejected_during_build_credential() {
    let fixture = signed_x5c_sd_jwt(serde_json::json!({
        "iss": "https://issuer.example.com",
        "vct": "https://credentials.example.com/test"
    }));
    let engine = make_engine(RecordingTaskQueue::default())
        .with_x5c_trust_anchors(vec![fixture.trust_anchor]);
    let config = sd_jwt_config("https://credentials.example.com/test");

    let result = engine
        .build_credential(
            Uuid::new_v4(),
            "https://issuer.example.com",
            &config,
            tamper_jwt_signature(&fixture.raw),
            time::UtcDateTime::now(),
        )
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn sd_jwt_issuer_claim_is_stored_when_it_differs_from_metadata_issuer() {
    let fixture = signed_x5c_sd_jwt(serde_json::json!({
        "iss": "https://evil.example.com",
        "vct": "https://credentials.example.com/test"
    }));
    let engine = make_engine(RecordingTaskQueue::default())
        .with_x5c_trust_anchors(vec![fixture.trust_anchor]);
    let config = sd_jwt_config("https://credentials.example.com/test");

    let credential = engine
        .build_credential(
            Uuid::new_v4(),
            "https://issuer.example.com",
            &config,
            fixture.raw,
            time::UtcDateTime::now(),
        )
        .await
        .unwrap();

    assert_eq!(credential.issuer, "https://evil.example.com");
}

#[tokio::test]
async fn sd_jwt_missing_issuer_uses_metadata_issuer_during_build_credential() {
    let fixture = signed_x5c_sd_jwt(serde_json::json!({
        "vct": "https://credentials.example.com/test"
    }));
    let engine = make_engine(RecordingTaskQueue::default())
        .with_x5c_trust_anchors(vec![fixture.trust_anchor]);
    let config = sd_jwt_config("https://credentials.example.com/test");

    let credential = engine
        .build_credential(
            Uuid::new_v4(),
            "https://issuer.example.com",
            &config,
            fixture.raw,
            time::UtcDateTime::now(),
        )
        .await
        .unwrap();

    assert_eq!(credential.issuer, "https://issuer.example.com");
}

#[tokio::test]
async fn malformed_mdoc_credential_is_rejected_with_credential_request_error() {
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

#[tokio::test]
async fn sd_jwt_vct_mismatch_is_rejected_before_mapping() {
    let config = sd_jwt_config("https://credentials.example.com/expected");
    let fixture = signed_x5c_sd_jwt(serde_json::json!({
        "iss": "https://issuer.example.com",
        "vct": "https://credentials.example.com/actual"
    }));
    let engine = make_engine(RecordingTaskQueue::default())
        .with_x5c_trust_anchors(vec![fixture.trust_anchor]);

    let result = engine
        .build_credential(
            Uuid::new_v4(),
            "https://issuer.example.com",
            &config,
            fixture.raw,
            time::UtcDateTime::now(),
        )
        .await;

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

// ── mdoc fixture helpers ──────────────────────────────────────────────────────

/// ISO 18013-5 Document Signer Certificate EKU OID (arc 1.0.18013.5.1.2).
const DSC_EKU_OID: &[u64] = &[1, 0, 18013, 5, 1, 2];

/// Serializes a `ciborium::Value` to its canonical CBOR byte representation.
fn cbor(val: &Value) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(val, &mut buf).expect("CBOR serialization must succeed");
    buf
}

/// Builds an IACA root CA cert and a DSC cert signed by it.
///
/// Returns `(iaca_der, dsc_der, dsc_signing_key)` where `dsc_signing_key`
/// is the AWS-LC-RS backed ECDSA P-256 key used to sign the COSE_Sign1.
///
/// The DSC validity window is 2023-12-01 to 2024-12-31 (396 days < 457-day
/// ISO 18013-5 Annex B maximum). Use signed/validFrom dates within that window.
fn build_chain() -> (Vec<u8>, Vec<u8>, EcdsaKeyPair) {
    use rcgen::Issuer;
    use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use time::format_description::well_known::Rfc3339;

    let iaca_key = CertKeyPair::generate().expect("rcgen IACA key generation must succeed");
    let mut iaca_params =
        CertificateParams::new(vec!["IACA Root".to_string()]).expect("iaca params");
    iaca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let iaca_cert = iaca_params
        .self_signed(&iaca_key)
        .expect("self-signed IACA cert must succeed");
    let iaca_der: Vec<u8> = iaca_cert.der().to_vec();
    let iaca_issuer = Issuer::new(iaca_params, iaca_key);

    let dsc_aws_key =
        EcdsaKeyPair::generate(Curve::P256).expect("aws-lc-rs DSC key generation must succeed");
    let dsc_pkcs8 = dsc_aws_key.to_pkcs8_der();
    let dsc_rcgen_key = CertKeyPair::from_der_and_sign_algo(
        &PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(dsc_pkcs8)),
        &rcgen::PKCS_ECDSA_P256_SHA256,
    )
    .expect("loading aws-lc-rs key into rcgen must succeed");

    let mut dsc_params = CertificateParams::new(vec!["DSC".to_string()]).expect("dsc params");
    dsc_params.is_ca = IsCa::NoCa;
    // 396-day window — within the ISO 18013-5 Annex B 457-day maximum.
    // MSO signed/validFrom must fall within this window (use 2024-01-01).
    dsc_params.not_before = OffsetDateTime::parse("2023-12-01T00:00:00Z", &Rfc3339).unwrap();
    dsc_params.not_after = OffsetDateTime::parse("2024-12-31T23:59:59Z", &Rfc3339).unwrap();
    dsc_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::Other(DSC_EKU_OID.to_vec())];
    dsc_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let dsc_cert = dsc_params
        .signed_by(&dsc_rcgen_key, &iaca_issuer)
        .expect("DSC signing by IACA must succeed");
    let dsc_der: Vec<u8> = dsc_cert.der().to_vec();

    (iaca_der, dsc_der, dsc_aws_key)
}

/// Builds a base64url-encoded `IssuerSigned` CBOR payload with:
/// - one `family_name` item whose digest is the real SHA-256 of its `#6.24` bytes,
/// - the provided `device_key_x`/`device_key_y` coordinates as the MSO DeviceKey,
/// - a real COSE_Sign1 signed by `signing_key` (or a corrupted one when `tamper` is true),
/// - the DSC cert embedded in the unprotected header x5chain (label 33).
fn build_signed_mdoc(
    doctype: &str,
    valid_from_str: &str,
    valid_until_str: &str,
    device_key_x: &[u8],
    device_key_y: &[u8],
    dsc_der: Vec<u8>,
    signing_key: &EcdsaKeyPair,
    tamper: bool,
) -> String {
    // Build one item with a real SHA-256 digest.
    let item = Value::Map(vec![
        (Value::Text("digestID".into()), Value::Integer(0u64.into())),
        (Value::Text("random".into()), Value::Bytes(vec![0u8; 16])),
        (
            Value::Text("elementIdentifier".into()),
            Value::Text("family_name".into()),
        ),
        (
            Value::Text("elementValue".into()),
            Value::Text("Doe".into()),
        ),
    ]);
    let item_inner = cbor(&item);
    let item_tag24 = Value::Tag(24, Box::new(Value::Bytes(item_inner.clone())));
    let item_tag24_bytes = cbor(&item_tag24);

    use cloud_wallet_crypto::digest::HashAlg;
    let digest_bytes = HashAlg::Sha256.hash(&item_tag24_bytes).as_ref().to_vec();

    let device_key = Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Integer(2i64.into())), // kty: EC2
        (Value::Integer((-1i64).into()), Value::Integer(1i64.into())), // crv: P-256
        (
            Value::Integer((-2i64).into()),
            Value::Bytes(device_key_x.to_vec()),
        ), // x
        (
            Value::Integer((-3i64).into()),
            Value::Bytes(device_key_y.to_vec()),
        ), // y
    ]);

    let mso = Value::Map(vec![
        (Value::Text("version".into()), Value::Text("1.0".into())),
        (
            Value::Text("digestAlgorithm".into()),
            Value::Text("SHA-256".into()),
        ),
        (
            Value::Text("valueDigests".into()),
            Value::Map(vec![(
                Value::Text("org.iso.18013.5.1".into()),
                Value::Map(vec![(
                    Value::Integer(0u64.into()),
                    Value::Bytes(digest_bytes),
                )]),
            )]),
        ),
        (
            Value::Text("deviceKeyInfo".into()),
            Value::Map(vec![(Value::Text("deviceKey".into()), device_key)]),
        ),
        (
            Value::Text("docType".into()),
            Value::Text(doctype.to_owned()),
        ),
        (
            Value::Text("validityInfo".into()),
            Value::Map(vec![
                (
                    Value::Text("signed".into()),
                    Value::Tag(0, Box::new(Value::Text(valid_from_str.to_owned()))),
                ),
                (
                    Value::Text("validFrom".into()),
                    Value::Tag(0, Box::new(Value::Text(valid_from_str.to_owned()))),
                ),
                (
                    Value::Text("validUntil".into()),
                    Value::Tag(0, Box::new(Value::Text(valid_until_str.to_owned()))),
                ),
            ]),
        ),
    ]);

    let mso_bytes = cbor(&mso);
    let mso_payload = cbor(&Value::Tag(24, Box::new(Value::Bytes(mso_bytes.clone()))));

    // {1: -7} = alg: ES256
    let protected_header_bytes: Vec<u8> = vec![0xa1, 0x01, 0x26];

    // RFC 9052 §4.4 Sig_Structure
    let tbs = cbor(&Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected_header_bytes.clone()),
        Value::Bytes(vec![]), // external AAD
        Value::Bytes(mso_payload.clone()),
    ]));

    let sig_bytes = signing_key
        .sign_sha256(&tbs)
        .expect("COSE signing must succeed");

    let final_sig: Vec<u8> = if tamper {
        let mut corrupted = sig_bytes.to_vec();
        corrupted[0] ^= 0xff;
        corrupted
    } else {
        sig_bytes.to_vec()
    };

    // Label 33 = x5chain
    let unprotected = Value::Map(vec![(
        Value::Integer(33.into()),
        Value::Array(vec![Value::Bytes(dsc_der)]),
    )]);

    let cose_sign1 = Value::Tag(
        18,
        Box::new(Value::Array(vec![
            Value::Bytes(protected_header_bytes),
            unprotected,
            Value::Bytes(mso_payload),
            Value::Bytes(final_sig),
        ])),
    );

    let item_tag24_val: Value =
        ciborium::de::from_reader(item_tag24_bytes.as_slice()).expect("round-trip must succeed");

    let issuer_signed = Value::Map(vec![
        (
            Value::Text("nameSpaces".into()),
            Value::Map(vec![(
                Value::Text("org.iso.18013.5.1".into()),
                Value::Array(vec![item_tag24_val]),
            )]),
        ),
        (Value::Text("issuerAuth".into()), cose_sign1),
    ]);

    Base64UrlUnpadded::encode_string(&cbor(&issuer_signed))
}

fn mdoc_config(doctype: &str) -> CredentialConfiguration {
    CredentialConfiguration {
        id: None,
        format_details: CredentialFormatDetails::MsoMdoc(MsoMdocCredentialConfiguration {
            doctype: doctype.to_owned(),
        }),
        scope: None,
        cryptographic_binding_methods_supported: None,
        credential_signing_alg_values_supported: None,
        proof_types_supported: None,
        credential_metadata: None,
    }
}

#[tokio::test]
async fn mdoc_credential_fields_are_populated_from_mso_validity_info() {
    // Arrange: build a real chain and use the tenant's P-256 key as the DeviceKey.
    let (iaca_der, dsc_der, signing_key) = build_chain();

    let tenant_repo = MemoryTenantRepo::new();
    let tenant_id = {
        let res = tenant_repo
            .create(crate::domain::models::tenants::RegisterTenantRequest {
                name: "test".to_owned(),
            })
            .await
            .unwrap();
        Uuid::parse_str(&res.tenant_id).unwrap()
    };

    // Extract the tenant's proof JWK so we can embed the matching DeviceKey in the MSO.
    let tenant_key = tenant_repo.find_key(tenant_id).await.unwrap();
    let signer = CryptoSigner::from_ecdsa_der(tenant_key.der_bytes.expose()).unwrap();
    let proof_jwk = signer.proof_jwk();
    let Key::Ec(ref ec) = proof_jwk.key else {
        panic!("test tenant must be EC-keyed (P-256)");
    };
    let x_bytes = ec.x.as_ref().to_vec();
    let y_bytes = ec.y.as_ref().to_vec();

    let raw = build_signed_mdoc(
        "org.iso.18013.5.1.mDL",
        "2024-01-01T00:00:00Z",
        "9998-01-01T00:00:00Z",
        &x_bytes,
        &y_bytes,
        dsc_der,
        &signing_key,
        false,
    );

    let inner_client = OidClient::new(Oid4vciClientConfig::new(
        "test-client",
        Url::parse("https://wallet.example.com/callback").unwrap(),
    ))
    .unwrap();
    let sessions = MemorySession::default();
    let publisher = MemoryEventPublisher::new(16);
    let engine = IssuanceEngine::with_worker_count(
        Oid4vciClient::new(inner_client),
        RecordingTaskQueue::default(),
        publisher.clone(),
        MemoryEventSubscriber::new(&publisher),
        MemoryCredentialRepo::new(),
        tenant_repo,
        &sessions,
        vec!["en".to_owned()],
        1,
    )
    .with_iaca_trust_store(StaticTrustStore::new(vec![iaca_der]));

    let config = mdoc_config("org.iso.18013.5.1.mDL");

    // Act
    let credential = engine
        .build_credential(
            tenant_id,
            "https://issuer.example.com",
            &config,
            raw,
            time::UtcDateTime::now(),
        )
        .await
        .unwrap();

    // Assert: fields come from MSO, not from config or fallbacks.
    assert_eq!(credential.format, CredentialFormat::Mdoc);
    assert_eq!(
        credential.credential_types,
        vec!["org.iso.18013.5.1.mDL".to_owned()]
    );
    // signed = "2024-01-01T00:00:00Z" → must match what build_signed_mdoc uses
    assert_eq!(
        credential.issued_at,
        time::UtcDateTime::from_unix_timestamp(
            OffsetDateTime::parse(
                "2024-01-01T00:00:00Z",
                &time::format_description::well_known::Rfc3339
            )
            .unwrap()
            .unix_timestamp()
        )
        .unwrap()
    );
    assert!(credential.valid_until.is_some());
    assert!(credential.subject.is_none());
    assert_eq!(credential.issuer, "https://issuer.example.com");
}

#[tokio::test]
async fn mdoc_tampered_digest_is_rejected_before_storage() {
    // Arrange: build a fixture with an intentionally wrong digest entry.
    // The item bytes hash to a real SHA-256, but we put 32 zero bytes in valueDigests.
    // verify_issuer_signature() passes first (the COSE signature over the tampered MSO
    // is valid), then verify_digests() rejects the all-zero digest that does not match
    // the real SHA-256 of the item bytes.
    let (iaca_der, dsc_der, signing_key) = build_chain();

    let (engine, tenant_id) = make_mdoc_engine(RecordingTaskQueue::default(), iaca_der).await;

    // Embed the tenant's real proof JWK as the DeviceKey so that device-key
    // binding succeeds and the only failing check is the digest check under
    // test. A non-matching DeviceKey would independently trip
    // `verify_device_key_binding`, masking whether `verify_digests` actually
    // caught the tampering.
    let tenant_key = engine.tenant_repo.find_key(tenant_id).await.unwrap();
    let signer = CryptoSigner::from_ecdsa_der(tenant_key.der_bytes.expose()).unwrap();
    let proof_jwk = signer.proof_jwk();
    let Key::Ec(ref ec) = proof_jwk.key else {
        panic!("test tenant must be EC-keyed (P-256)");
    };
    let x_bytes = ec.x.as_ref().to_vec();
    let y_bytes = ec.y.as_ref().to_vec();

    // Build a raw mdoc but then corrupt the valueDigest entry at the CBOR level.
    // The simplest approach: build an mdoc via build_signed_mdoc (correct digests),
    // then flip the last byte of the base64url — the CBOR becomes mangled.
    // Instead, construct a custom MSO with all-zero digest bytes:
    let item = Value::Map(vec![
        (Value::Text("digestID".into()), Value::Integer(0u64.into())),
        (Value::Text("random".into()), Value::Bytes(vec![0u8; 16])),
        (
            Value::Text("elementIdentifier".into()),
            Value::Text("family_name".into()),
        ),
        (
            Value::Text("elementValue".into()),
            Value::Text("Doe".into()),
        ),
    ]);
    let item_inner = cbor(&item);
    let item_tag24 = Value::Tag(24, Box::new(Value::Bytes(item_inner)));
    let item_tag24_bytes = cbor(&item_tag24);
    let item_tag24_val: Value = ciborium::de::from_reader(item_tag24_bytes.as_slice()).unwrap();

    // Wrong digest: all zeros instead of the real SHA-256.
    let wrong_digest = vec![0u8; 32];

    let device_key = Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Integer(2i64.into())),
        (Value::Integer((-1i64).into()), Value::Integer(1i64.into())),
        (Value::Integer((-2i64).into()), Value::Bytes(x_bytes)),
        (Value::Integer((-3i64).into()), Value::Bytes(y_bytes)),
    ]);
    let mso = Value::Map(vec![
        (Value::Text("version".into()), Value::Text("1.0".into())),
        (
            Value::Text("digestAlgorithm".into()),
            Value::Text("SHA-256".into()),
        ),
        (
            Value::Text("valueDigests".into()),
            Value::Map(vec![(
                Value::Text("org.iso.18013.5.1".into()),
                Value::Map(vec![(
                    Value::Integer(0u64.into()),
                    Value::Bytes(wrong_digest),
                )]),
            )]),
        ),
        (
            Value::Text("deviceKeyInfo".into()),
            Value::Map(vec![(Value::Text("deviceKey".into()), device_key)]),
        ),
        (
            Value::Text("docType".into()),
            Value::Text("org.iso.18013.5.1.mDL".into()),
        ),
        (
            Value::Text("validityInfo".into()),
            Value::Map(vec![
                (
                    Value::Text("signed".into()),
                    Value::Tag(0, Box::new(Value::Text("2024-01-01T00:00:00Z".into()))),
                ),
                (
                    Value::Text("validFrom".into()),
                    Value::Tag(0, Box::new(Value::Text("2024-01-01T00:00:00Z".into()))),
                ),
                (
                    Value::Text("validUntil".into()),
                    Value::Tag(0, Box::new(Value::Text("9998-01-01T00:00:00Z".into()))),
                ),
            ]),
        ),
    ]);

    let mso_bytes = cbor(&mso);
    let mso_payload = cbor(&Value::Tag(24, Box::new(Value::Bytes(mso_bytes.clone()))));
    let protected_header_bytes: Vec<u8> = vec![0xa1, 0x01, 0x26];
    let tbs = cbor(&Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected_header_bytes.clone()),
        Value::Bytes(vec![]),
        Value::Bytes(mso_payload.clone()),
    ]));
    let sig_bytes = signing_key.sign_sha256(&tbs).unwrap();
    let unprotected = Value::Map(vec![(
        Value::Integer(33.into()),
        Value::Array(vec![Value::Bytes(dsc_der)]),
    )]);
    let cose_sign1 = Value::Tag(
        18,
        Box::new(Value::Array(vec![
            Value::Bytes(protected_header_bytes),
            unprotected,
            Value::Bytes(mso_payload),
            Value::Bytes(sig_bytes.to_vec()),
        ])),
    );
    let issuer_signed = Value::Map(vec![
        (
            Value::Text("nameSpaces".into()),
            Value::Map(vec![(
                Value::Text("org.iso.18013.5.1".into()),
                Value::Array(vec![item_tag24_val]),
            )]),
        ),
        (Value::Text("issuerAuth".into()), cose_sign1),
    ]);
    let raw = Base64UrlUnpadded::encode_string(&cbor(&issuer_signed));

    let config = mdoc_config("org.iso.18013.5.1.mDL");

    // Act
    let result = engine
        .build_credential(
            tenant_id,
            "https://issuer.example.com",
            &config,
            raw,
            time::UtcDateTime::now(),
        )
        .await;

    // Assert: must be rejected specifically by the digest check — not by an
    // unrelated device-key mismatch, which the matching DeviceKey above rules out.
    let err = result.unwrap_err();
    let desc = err.error_description().unwrap_or("");
    assert!(
        desc.contains("digest mismatch"),
        "tampered digest must be rejected by the digest check specifically; got: {desc}"
    );
    assert!(
        !desc.contains("device key"),
        "must not be masked by an unrelated device-key mismatch; got: {desc}"
    );
}

#[tokio::test]
async fn mdoc_invalid_issuer_signature_is_rejected_before_storage() {
    // Arrange: valid structure + correct digests + real IACA chain,
    // but the COSE_Sign1 signature bytes are corrupted (tamper = true).
    let (iaca_der, dsc_der, signing_key) = build_chain();

    let (engine, tenant_id) = make_mdoc_engine(RecordingTaskQueue::default(), iaca_der).await;

    // Embed the tenant's real proof JWK as the DeviceKey so that device-key
    // binding succeeds and the only failing check is the issuer-signature check
    // under test. A non-matching DeviceKey would independently trip
    // `verify_device_key_binding`, masking whether `verify_issuer_signature`
    // actually caught the corrupted signature.
    let tenant_key = engine.tenant_repo.find_key(tenant_id).await.unwrap();
    let signer = CryptoSigner::from_ecdsa_der(tenant_key.der_bytes.expose()).unwrap();
    let proof_jwk = signer.proof_jwk();
    let Key::Ec(ref ec) = proof_jwk.key else {
        panic!("test tenant must be EC-keyed (P-256)");
    };
    let x_bytes = ec.x.as_ref().to_vec();
    let y_bytes = ec.y.as_ref().to_vec();

    let raw = build_signed_mdoc(
        "org.iso.18013.5.1.mDL",
        "2024-01-01T00:00:00Z",
        "9998-01-01T00:00:00Z",
        &x_bytes,
        &y_bytes,
        dsc_der,
        &signing_key,
        true, // tamper = corrupt the COSE signature
    );

    let config = mdoc_config("org.iso.18013.5.1.mDL");

    // Act
    let result = engine
        .build_credential(
            tenant_id,
            "https://issuer.example.com",
            &config,
            raw,
            time::UtcDateTime::now(),
        )
        .await;

    // Assert: must be rejected specifically by the issuer-signature check — not
    // by an unrelated device-key mismatch, which the matching DeviceKey above rules out.
    let err = result.unwrap_err();
    let desc = err.error_description().unwrap_or("");
    assert!(
        desc.contains("issuer signature verification failed"),
        "corrupted issuer signature must be rejected by the signature check specifically; got: {desc}"
    );
    assert!(
        !desc.contains("device key"),
        "must not be masked by an unrelated device-key mismatch; got: {desc}"
    );
}

#[tokio::test]
async fn mdoc_device_key_mismatch_is_rejected_before_storage() {
    // Arrange: valid structure + correct digests + valid COSE signature,
    // but the MSO DeviceKey (all-zero x,y) does not match the tenant's proof JWK.
    let (iaca_der, dsc_der, signing_key) = build_chain();

    let wrong_x = vec![0u8; 32];
    let wrong_y = vec![0u8; 32];

    let raw = build_signed_mdoc(
        "org.iso.18013.5.1.mDL",
        "2024-01-01T00:00:00Z",
        "9998-01-01T00:00:00Z",
        &wrong_x,
        &wrong_y,
        dsc_der,
        &signing_key,
        false,
    );

    let (engine, tenant_id) = make_mdoc_engine(RecordingTaskQueue::default(), iaca_der).await;
    let config = mdoc_config("org.iso.18013.5.1.mDL");

    // Act: the registered tenant has a real P-256 key whose x/y coordinates are
    // non-zero and will not match the all-zero DeviceKey in the MSO —
    // verify_device_key_binding must reject it.
    let result = engine
        .build_credential(
            tenant_id,
            "https://issuer.example.com",
            &config,
            raw,
            time::UtcDateTime::now(),
        )
        .await;

    // Assert
    assert!(result.is_err(), "device key mismatch must be rejected");
}

#[tokio::test]
async fn ldp_vc_json_object_credential_is_converted_to_string_not_rejected_as_invalid_type() {
    // Arrange: an ldp_vc JSON object credential routed through store_credentials.
    //
    // NOTE: this does NOT exercise ldp_vc issuance support — `build_credential`
    // has no `LdpVc` arm, so the credential is still rejected, just later and
    // with a more accurate error ("unsupported credential format 'ldp_vc'"
    // instead of "must be a string or a JSON object"). What this test pins down
    // is that the `v @ serde_json::Value::Object(_)` arm in `store_credentials`
    // converts the object to a JSON string and lets it continue past the
    // type check, rather than being rejected at that stage for having the
    // wrong shape.
    //
    // If the `v @ serde_json::Value::Object(_)` arm were removed, the `_` arm
    // would trigger and produce the "must be a string or a JSON object" message,
    // causing the assertion below to fail and giving a regression signal.
    use cloud_wallet_openid4vc::oid4vci::client::{IssuanceFlow, ResolvedOfferContext};
    use cloud_wallet_openid4vc::oid4vci::credential::formats::{
        CredentialFormatDetails, SdJwtVcCredentialConfiguration,
    };
    use cloud_wallet_openid4vc::oid4vci::credential::offer::CredentialOffer;
    use cloud_wallet_openid4vc::oid4vci::credential::{
        CredentialObject, ImmediateCredentialResponse,
    };
    use cloud_wallet_openid4vc::oid4vci::metadata::{
        AuthorizationServerMetadata, CredentialIssuerMetadata,
    };
    use std::collections::HashMap;

    let issuer_url = Url::parse("https://issuer.example.com").unwrap();

    // A DcSdJwt config is used so build_credential tries to parse the serialised
    // JSON as an SD-JWT; that parse will fail, but the failure is downstream of
    // the Object→String conversion we are testing.
    let sd_jwt_config = CredentialConfiguration {
        id: None,
        format_details: CredentialFormatDetails::DcSdJwt(SdJwtVcCredentialConfiguration {
            vct: "TestCredential".to_owned(),
        }),
        scope: None,
        cryptographic_binding_methods_supported: None,
        credential_signing_alg_values_supported: None,
        proof_types_supported: None,
        credential_metadata: None,
    };
    let mut configs = HashMap::new();
    configs.insert("test-cred".to_owned(), sd_jwt_config);

    let context = ResolvedOfferContext {
        offer: CredentialOffer {
            credential_issuer: issuer_url.clone(),
            credential_configuration_ids: vec!["test-cred".to_owned()],
            grants: None,
        },
        issuer_metadata: CredentialIssuerMetadata {
            credential_issuer: issuer_url.clone(),
            authorization_servers: None,
            credential_endpoint: issuer_url.clone(),
            nonce_endpoint: None,
            deferred_credential_endpoint: None,
            notification_endpoint: None,
            batch_credential_endpoint: None,
            credential_request_encryption: None,
            credential_response_encryption: None,
            batch_credential_issuance: None,
            display: None,
            credential_configurations_supported: configs,
        },
        as_metadata: AuthorizationServerMetadata {
            issuer: issuer_url,
            authorization_endpoint: None,
            token_endpoint: None,
            jwks_uri: None,
            registration_endpoint: None,
            scopes_supported: None,
            response_types_supported: None,
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
            code_challenge_methods_supported: None,
            pushed_authorization_request_endpoint: None,
            require_pushed_authorization_requests: None,
            pre_authorized_grant_anonymous_access_supported: None,
            extra_fields: HashMap::new(),
        },
        flow: IssuanceFlow::PreAuthorizedCode {
            pre_authorized_code: "test-code".to_owned(),
            tx_code: None,
        },
    };

    let json_cred = serde_json::json!({
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential"],
        "issuer": "https://issuer.example.com",
        "credentialSubject": { "id": "did:example:alice" }
    });
    let immediate = ImmediateCredentialResponse::new(vec![CredentialObject::new(json_cred)]);

    let engine = make_engine(RecordingTaskQueue::default());
    let mut credential_ids = vec![];
    let mut credential_types = vec![];

    // Act
    let result = engine
        .store_credentials(
            Uuid::new_v4(),
            &context,
            "test-cred",
            immediate,
            &mut credential_ids,
            &mut credential_types,
        )
        .await;

    // Assert: the Object arm was entered (JSON → string conversion succeeded).
    // The resulting error comes from SD-JWT parsing, NOT from the `_` fallback.
    let err = result.unwrap_err();
    let desc = err.error_description().unwrap_or("");
    assert!(
        !desc.contains("must be a string or a JSON object"),
        "JSON object credential must pass the Object→String conversion arm; got: {desc}"
    );
}
