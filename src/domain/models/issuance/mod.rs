mod consent;
mod error;
mod events;
mod start;
mod task;
mod tx_code;

use cloud_wallet_openid4vc::oid4vci::metadata::{CredentialConfiguration, CredentialDisplay};
pub use consent::{ConsentError, ConsentRequest, ConsentResponse, NextAction};
pub use error::{IssuanceError, IssuanceErrorCode};
pub use events::*;
pub use start::{CredentialTypeDisplay, StartIssuanceRequest, StartIssuanceResponse};
pub use task::{IssuanceTask, TaskResult};
pub use tx_code::{TxCodeError, TxCodeRequest, TxCodeResponse};

use std::{sync::Arc, time::Duration};

use cloud_wallet_openid4vc::formats::sd_jwt::{SdJwt, SdJwtClaims, StatusClaim, X5cTrustAnchors};
use cloud_wallet_openid4vc::oid4vci::client::{CryptoSigner, Oid4vciClient, ResolvedOfferContext};
use cloud_wallet_openid4vc::oid4vci::credential::formats::CredentialFormatDetails;
use cloud_wallet_openid4vc::oid4vci::credential::{
    CredentialResponse, DeferredCredentialResult, ImmediateCredentialResponse,
};
use cloud_wallet_openid4vc::oid4vci::notification::{NotificationEvent, NotificationRequest};
use cloud_wallet_openid4vc::oid4vci::token::TokenResponse;
use jsonwebtoken::Algorithm as JwtAlgorithm;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

use crate::domain::models::credential::{
    Credential, CredentialDisplayMetadata, CredentialFormat, CredentialStatus,
};
use crate::domain::models::tenants::SignAlgorithm;
use crate::domain::ports::{
    CredentialRepo, IssuanceEventPublisher, IssuanceEventStream, IssuanceEventSubscriber,
    IssuanceTaskQueue, TenantRepo,
};
use crate::session::{IssuanceSession, IssuanceState, SessionStore, transition};
use tokio::{sync::Notify, task::JoinHandle};

type Result<T> = std::result::Result<T, IssuanceError>;

/// Maximum number of deferred credential polling attempts.
const MAX_DEFERRED_RETRIES: u32 = 60;
const DEFAULT_WORKER_IDLE_SLEEP: Duration = Duration::from_millis(250);
const DEFAULT_WORKER_ERROR_SLEEP: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowType {
    AuthorizationCode,
    PreAuthorizedCode,
}

/// The issuance engine.
///
/// Holds shared references to all internal services.
/// Designed to be cheaply cloneable (all fields are `Arc`).
pub struct IssuanceEngine {
    pub client: Arc<Oid4vciClient>,
    pub task_queue: Arc<dyn IssuanceTaskQueue>,
    pub event_publisher: Arc<dyn IssuanceEventPublisher>,
    pub event_subscriber: Arc<dyn IssuanceEventSubscriber>,
    pub credential_repo: Arc<dyn CredentialRepo>,
    pub tenant_repo: Arc<dyn TenantRepo>,
    workers: Arc<Mutex<Vec<JoinHandle<()>>>>,
    worker_notify: Arc<Notify>,
    preferred_display_locales: Arc<Vec<String>>,
}

impl Clone for IssuanceEngine {
    fn clone(&self) -> Self {
        Self {
            client: Arc::clone(&self.client),
            task_queue: Arc::clone(&self.task_queue),
            event_publisher: Arc::clone(&self.event_publisher),
            event_subscriber: Arc::clone(&self.event_subscriber),
            credential_repo: Arc::clone(&self.credential_repo),
            tenant_repo: Arc::clone(&self.tenant_repo),
            workers: Arc::clone(&self.workers),
            worker_notify: Arc::clone(&self.worker_notify),
            preferred_display_locales: Arc::clone(&self.preferred_display_locales),
        }
    }
}

impl std::fmt::Debug for IssuanceEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuanceEngine")
            .field("client", &self.client)
            .field(
                "task_queue",
                &std::any::type_name::<dyn IssuanceTaskQueue>(),
            )
            .field(
                "event_publisher",
                &std::any::type_name::<dyn IssuanceEventPublisher>(),
            )
            .field(
                "event_subscriber",
                &std::any::type_name::<dyn IssuanceEventSubscriber>(),
            )
            .field("worker_count", &self.worker_count())
            .field("preferred_display_locales", &self.preferred_display_locales)
            .finish()
    }
}

impl IssuanceEngine {
    /// Create a new orchestrator with all required dependencies and default workers.
    ///
    /// The default worker count is the machine's available parallelism.
    #[allow(clippy::too_many_arguments)]
    pub fn new<Q, P, B, C, T, S>(
        client: Oid4vciClient,
        task_queue: Q,
        event_publisher: P,
        event_subscriber: B,
        credential_repo: C,
        tenant_repo: T,
        session_store: &S,
        preferred_display_locales: Vec<String>,
    ) -> Self
    where
        Q: IssuanceTaskQueue,
        P: IssuanceEventPublisher,
        B: IssuanceEventSubscriber,
        C: CredentialRepo,
        T: TenantRepo,
        S: SessionStore + Clone,
    {
        Self::with_worker_count(
            client,
            task_queue,
            event_publisher,
            event_subscriber,
            credential_repo,
            tenant_repo,
            session_store,
            preferred_display_locales,
            default_worker_count(),
        )
    }

    /// Create a new orchestrator and override how many background workers it starts.
    #[allow(clippy::too_many_arguments)]
    pub fn with_worker_count<Q, P, B, C, T, S>(
        client: Oid4vciClient,
        task_queue: Q,
        event_publisher: P,
        event_subscriber: B,
        credential_repo: C,
        tenant_repo: T,
        session_store: &S,
        preferred_display_locales: Vec<String>,
        worker_count: usize,
    ) -> Self
    where
        Q: IssuanceTaskQueue,
        P: IssuanceEventPublisher,
        B: IssuanceEventSubscriber,
        C: CredentialRepo,
        T: TenantRepo,
        S: SessionStore + Clone,
    {
        let engine = Self {
            client: Arc::new(client),
            task_queue: Arc::new(task_queue),
            event_publisher: Arc::new(event_publisher),
            event_subscriber: Arc::new(event_subscriber),
            credential_repo: Arc::new(credential_repo),
            tenant_repo: Arc::new(tenant_repo),
            workers: Arc::default(),
            worker_notify: Arc::new(Notify::new()),
            preferred_display_locales: Arc::new(preferred_display_locales),
        };

        engine.start_worker_count(session_store.clone(), worker_count)
    }

    /// Return the number of worker currently attached to this engine.
    pub fn worker_count(&self) -> usize {
        self.workers.lock().len()
    }

    /// Enqueue a task for background issuance.
    ///
    /// Handlers should call this once the session has been moved to `processing`.
    /// The task is later claimed by a worker that will execute it.
    #[instrument(skip_all, fields(session_id = %task.session_id, tenant_id = %task.tenant_id))]
    pub async fn enqueue(&self, task: &IssuanceTask) -> Result<()> {
        self.task_queue.push(task).await?;
        self.worker_notify.notify_one();
        Ok(())
    }

    /// Subscribe to issuance events for a specific session.
    ///
    /// Returns a stream that yields events as they are published.
    /// The stream auto-terminates after a terminal event (completed or failed).
    pub async fn subscribe(&self, session_id: &str) -> Result<IssuanceEventStream> {
        self.event_subscriber.subscribe(session_id).await
    }

    fn start_worker_count<S: SessionStore + Clone>(
        self,
        session_store: S,
        worker_count: usize,
    ) -> Self {
        let existing_workers = self.worker_count();
        if existing_workers > 0 {
            return self;
        }

        let handles = (0..worker_count.max(1))
            .map(|_| self.spawn_worker(session_store.clone()))
            .collect::<Vec<_>>();
        self.workers.lock().extend(handles);
        self
    }

    /// Spawn a worker loop.
    fn spawn_worker<S: SessionStore + Clone>(&self, session_store: S) -> JoinHandle<()> {
        let engine = self.clone();
        tokio::spawn(async move {
            loop {
                match engine.process_next_task(&session_store).await {
                    Ok(true) => {}
                    Ok(false) => engine.wait_for_work().await,
                    Err(error) => {
                        error!(%error, "issuance worker iteration failed");
                        tokio::time::sleep(DEFAULT_WORKER_ERROR_SLEEP).await;
                    }
                }
            }
        })
    }

    async fn wait_for_work(&self) {
        tokio::select! {
            _ = self.worker_notify.notified() => {}
            _ = tokio::time::sleep(DEFAULT_WORKER_IDLE_SLEEP) => {}
        }
    }

    /// Claim and process the next available queued task.
    ///
    /// Returns `Ok(false)` when the queue has no available task.
    async fn process_next_task<S: SessionStore>(&self, session_store: &S) -> Result<bool> {
        let Some(task) = self.task_queue.pop().await? else {
            return Ok(false);
        };

        self.process_queued_task(task, session_store).await?;
        Ok(true)
    }

    /// Execute a task that was claimed from the queue and acknowledge it when terminal.
    async fn process_queued_task<S: SessionStore>(
        &self,
        task: IssuanceTask,
        session_store: &S,
    ) -> Result<()> {
        let session_id = task.session_id.clone();
        let result = self.execute(&task, session_store).await;

        if let Err(ack_err) = self.task_queue.ack(&task).await {
            warn!(
                error = %ack_err,
                session_id = %session_id,
                "failed to acknowledge issuance task"
            );
            if result.is_ok() {
                return Err(ack_err);
            }
        }
        result
    }

    /// Execute the full issuance flow for a task.
    ///
    /// Loads the session from the store to obtain the offer context
    /// and user selected configuration ids, then drives:
    /// 1. Token exchange
    /// 2. Credential request (with deferred polling)
    /// 3. Credential storage
    /// 4. SSE event emission
    ///
    /// On failure, emits a `failed` SSE event and removes the session.
    async fn execute<S: SessionStore>(&self, task: &IssuanceTask, session_store: &S) -> Result<()> {
        let session_id = &task.session_id;
        let session: IssuanceSession =
            session_store
                .get(session_id.as_str())
                .await?
                .ok_or_else(|| {
                    IssuanceError::internal_message(format!("session {session_id} not found"))
                })?;

        let result = self
            .execute_inner(
                task,
                session_store,
                &session.context,
                &session.selected_config_ids,
            )
            .await;

        if let Err(ref err) = result {
            error!(error = ?err, step = %err.step(), "issuance failed");

            // Emit failed SSE event
            let failed = IssuanceEvent::Failed(SseFailedEvent::new(
                session_id,
                err.step().as_str(),
                Some(err.to_string()),
                err.step(),
            ));
            if let Err(pub_err) = self.event_publisher.publish(&failed).await {
                warn!(error = %pub_err, "failed to publish failure event");
            }

            // Remove terminal failed session.
            self.terminate_session(session_store, session_id).await.ok();
        }
        result
    }

    async fn execute_inner<S: SessionStore>(
        &self,
        task: &IssuanceTask,
        session_store: &S,
        context: &ResolvedOfferContext,
        selected_config_ids: &[String],
    ) -> Result<()> {
        let session_id = &task.session_id;
        self.emit_processing(session_id, ProcessingStep::ExchangingToken)
            .await;

        let token_response = match task.flow {
            FlowType::AuthorizationCode => {
                let code = task
                    .authorization_code
                    .as_deref()
                    .ok_or(IssuanceError::token("missing authorization_code"))?;
                let verifier = task
                    .pkce_verifier
                    .as_deref()
                    .ok_or(IssuanceError::token("missing pkce_verifier"))?;

                self.client
                    .exchange_authorization_code(context, code, verifier, selected_config_ids)
                    .await?
            }
            FlowType::PreAuthorizedCode => {
                let pre_code = task
                    .pre_authorized_code
                    .as_deref()
                    .ok_or(IssuanceError::token("missing pre_authorized_code"))?;

                self.client
                    .exchange_pre_authorized_code(
                        context,
                        pre_code,
                        task.tx_code.as_deref(),
                        selected_config_ids,
                    )
                    .await?
            }
        };
        debug!(session_id, tenant_id = %task.tenant_id, "token exchange successful");

        let (credential_ids, credential_types, notification_ids) = self
            .request_and_store_credentials(session_id, &token_response, task, context)
            .await?;

        let completed = IssuanceEvent::Completed(SseCompletedEvent::new(
            session_id,
            credential_ids,
            credential_types,
        ));
        self.event_publisher.publish(&completed).await?;
        self.terminate_session(session_store, session_id).await?;

        // Best-effort notification: must not fail the flow.
        self.send_notifications(context, &token_response.access_token, notification_ids)
            .await;

        info!(session_id, tenant_id = %task.tenant_id, "issuance completed successfully");
        Ok(())
    }

    async fn request_and_store_credentials(
        &self,
        session_id: &str,
        token: &TokenResponse,
        task: &IssuanceTask,
        context: &ResolvedOfferContext,
    ) -> Result<(Vec<String>, Vec<String>, Vec<String>)> {
        let signer = self.build_signer(task.tenant_id).await?;
        self.emit_processing(session_id, ProcessingStep::RequestingCredential)
            .await;

        let responses = self
            .client
            .request_credentials(context, token, &signer)
            .await?;

        debug!(
            session_id,
            count = responses.len(),
            "credential responses received"
        );

        let mut credential_ids = Vec::with_capacity(responses.len());
        let mut credential_types = Vec::with_capacity(responses.len());
        let mut notification_ids = Vec::with_capacity(responses.len());

        for (idx, response) in responses.into_iter().enumerate() {
            let config_id = context
                .offer
                .credential_configuration_ids
                .get(idx)
                .cloned()
                .ok_or_else(|| IssuanceError::offer_resolution("malformed credential offer"))?;

            match response {
                CredentialResponse::Immediate(immediate) => {
                    debug!(session_id, config_id, "immediate credential received");
                    let notify_id = self
                        .store_credentials(
                            task.tenant_id,
                            context,
                            &config_id,
                            immediate,
                            &mut credential_ids,
                            &mut credential_types,
                        )
                        .await?;
                    notification_ids.extend(notify_id);
                }
                CredentialResponse::Deferred(pending) => {
                    debug!(
                        session_id,
                        transaction_id = %pending.transaction_id,
                        interval = pending.interval_seconds(),
                        "deferred credential, starting polling"
                    );

                    self.emit_processing(session_id, ProcessingStep::AwaitingDeferredCredential)
                        .await;

                    let token = &token.access_token;
                    let tx_id = pending.transaction_id.clone();
                    let interval = pending.interval_seconds();
                    let immediate = self
                        .poll_deferred(context, token, tx_id, interval, session_id)
                        .await?;

                    let notify_id = self
                        .store_credentials(
                            task.tenant_id,
                            context,
                            &config_id,
                            immediate,
                            &mut credential_ids,
                            &mut credential_types,
                        )
                        .await?;
                    notification_ids.extend(notify_id);
                }
            }
        }
        Ok((credential_ids, credential_types, notification_ids))
    }

    /// Store all credentials from an immediate response.
    ///
    /// Returns the `notification_id` from the response if present.
    async fn store_credentials(
        &self,
        tenant_id: Uuid,
        context: &ResolvedOfferContext,
        config_id: &str,
        immediate: ImmediateCredentialResponse,
        credential_ids: &mut Vec<String>,
        credential_types: &mut Vec<String>,
    ) -> Result<Option<String>> {
        let notification_id = immediate.notification_id;
        let display_metadata =
            extract_display_metadata(context, config_id, &self.preferred_display_locales);

        for cred_obj in immediate.credentials {
            let raw = match cred_obj.credential {
                serde_json::Value::String(s) => s,
                _ => {
                    return Err(IssuanceError::credential_request(
                        "the received credential is not a string",
                    ));
                }
            };
            let cred_id = self
                .store_credential(tenant_id, context, config_id, raw, display_metadata.clone())
                .await?;

            credential_ids.push(cred_id.to_string());
            credential_types.push(config_id.to_owned());
        }
        Ok(notification_id)
    }

    /// Poll the deferred credential endpoint.
    #[instrument(skip(self, context, access_token))]
    async fn poll_deferred(
        &self,
        context: &ResolvedOfferContext,
        access_token: &str,
        initial_tx_id: String,
        initial_interval: u64,
        session_id: &str,
    ) -> Result<ImmediateCredentialResponse> {
        let mut tx_id = initial_tx_id;
        let mut interval_secs = initial_interval;

        for attempt in 1..=MAX_DEFERRED_RETRIES {
            let wait = Duration::from_secs(interval_secs);
            debug!(
                session_id,
                attempt,
                wait_secs = interval_secs,
                transaction_id = %tx_id,
                "waiting before deferred poll"
            );
            tokio::time::sleep(wait).await;

            let result = self
                .client
                .poll_deferred_credential(context, access_token, &tx_id)
                .await?;

            match result {
                DeferredCredentialResult::Ready(response) => {
                    debug!(
                        session_id,
                        attempt,
                        credentials = response.credentials.len(),
                        "deferred credential ready"
                    );
                    return Ok(response);
                }
                DeferredCredentialResult::Pending(pending) => {
                    debug!(
                        session_id,
                        attempt,
                        new_transaction_id = %pending.transaction_id,
                        new_interval = pending.interval_seconds(),
                        "deferred credential still pending"
                    );
                    interval_secs = pending.interval_seconds();
                    tx_id = pending.transaction_id;
                }
            }
        }
        Err(IssuanceError::deferred_credential(format!(
            "credential not ready after {MAX_DEFERRED_RETRIES} polling attempts"
        )))
    }

    /// Build a `CryptoSigner` from the tenant's stored key material.
    #[instrument(skip(self))]
    async fn build_signer(&self, tenant_id: Uuid) -> Result<CryptoSigner> {
        let key = self.tenant_repo.find_key(tenant_id).await?;

        let signer = tokio::task::spawn_blocking(move || {
            let der = key.der_bytes.expose();
            match key.algorithm {
                SignAlgorithm::Ecdsa => CryptoSigner::from_ecdsa_der(der),
                SignAlgorithm::EdDsa => CryptoSigner::from_ed25519_der(der),
                SignAlgorithm::Rsa => CryptoSigner::from_rsa_der(der),
            }
        })
        .await??;
        Ok(signer)
    }

    /// Store a raw credential string and its associated display metadata.
    #[instrument(skip(self, raw_credential, display_metadata))]
    async fn store_credential(
        &self,
        tenant_id: Uuid,
        context: &ResolvedOfferContext,
        credential_config_id: &str,
        raw_credential: String,
        display_metadata: CredentialDisplayMetadata,
    ) -> Result<Uuid> {
        let config = context
            .issuer_metadata
            .credential_configurations_supported
            .get(credential_config_id)
            .ok_or_else(|| {
                IssuanceError::credential_request(format!(
                    "unknown credential configuration '{credential_config_id}'"
                ))
            })?;

        let receipt_time = time::UtcDateTime::now();
        let issuer = context.offer.credential_issuer.as_str();
        let credential = self
            .build_credential(tenant_id, issuer, config, raw_credential, receipt_time)
            .await?;

        let id = self
            .credential_repo
            .upsert(credential, Some(display_metadata))
            .await?;

        info!(credential_id = %id, tenant_id = %tenant_id, "credential stored successfully");
        Ok(id)
    }

    async fn build_credential(
        &self,
        tenant_id: Uuid,
        issuer: &str,
        config: &CredentialConfiguration,
        raw_credential: String,
        receipt_time: time::UtcDateTime,
    ) -> Result<Credential> {
        match &config.format_details {
            CredentialFormatDetails::DcSdJwt(sd_config) => {
                let sd_jwt = SdJwt::parse(&raw_credential)?;
                sd_jwt.to_disclosed_payload()?;

                let algorithm = sd_jwt
                    .verify_signature(self.client.http_client(), X5cTrustAnchors::default())
                    .await?;
                validate_credential_signing_alg(config, algorithm)?;

                let claims = sd_jwt.into_jwt().into_claims();
                if claims.vct != sd_config.vct {
                    return Err(IssuanceError::credential_request(format!(
                        "SD-JWT VC vct '{}' does not match credential configuration vct '{}'",
                        claims.vct, sd_config.vct
                    )));
                }
                credential_from_sd_jwt(tenant_id, issuer, claims, raw_credential, receipt_time)
            }
            other => Err(IssuanceError::credential_request(format!(
                "unsupported credential format '{}'",
                other.format_str()
            ))),
        }
    }

    /// Emit a processing SSE event (best-effort, non-fatal on failure).
    async fn emit_processing(&self, session_id: &str, step: ProcessingStep) {
        let event = IssuanceEvent::Processing(SseProcessingEvent::new(session_id, step));
        if let Err(e) = self.event_publisher.publish(&event).await {
            warn!(error = %e, "failed to publish processing event");
        }
    }

    /// Send issuer notifications for accepted credentials (best-effort).
    ///
    /// If the issuer's metadata declares a `notification_endpoint`, this sends
    /// a `credential_accepted` notification for each `notification_id` received
    /// in the credential responses.
    async fn send_notifications(
        &self,
        context: &ResolvedOfferContext,
        access_token: &str,
        notification_ids: Vec<String>,
    ) {
        let Some(endpoint) = context.issuer_metadata.notification_endpoint.as_ref() else {
            return;
        };
        for id in notification_ids {
            let req = NotificationRequest::new(id, NotificationEvent::CredentialAccepted);
            if let Err(e) = self
                .client
                .send_notification(endpoint, access_token, &req)
                .await
            {
                warn!(error = %e, "notification to issuer failed");
            }
        }
    }

    /// Remove a session from the session store.
    #[inline]
    async fn terminate_session<S: SessionStore>(
        &self,
        session_store: &S,
        session_id: &str,
    ) -> Result<()> {
        session_store.remove(session_id).await?;
        Ok(())
    }
}

/// Transition a session's state.
pub async fn transition_session<S: SessionStore>(
    session_store: &S,
    session_id: &str,
    new_state: IssuanceState,
) -> Result<()> {
    let mut session: IssuanceSession = session_store.get(session_id).await?.ok_or_else(|| {
        IssuanceError::internal_message(format!("session {session_id} not found"))
    })?;

    transition(&mut session, new_state)?;
    session_store.upsert(session_id, &session).await?;
    Ok(())
}

fn default_worker_count() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
}

fn credential_from_sd_jwt(
    tenant_id: Uuid,
    issuer: &str,
    claims: SdJwtClaims,
    raw_credential: String,
    receipt_time: time::UtcDateTime,
) -> Result<Credential> {
    let issuer = claims.rfc7519.iss.unwrap_or(issuer.to_owned());
    let issued_at = claims
        .rfc7519
        .iat
        .map(utc_from_numeric_date)
        .transpose()?
        .unwrap_or(receipt_time);
    let valid_until = claims.rfc7519.exp.map(utc_from_numeric_date).transpose()?;
    let (status_location, status_index) = status_list_metadata(claims.status)?;

    Ok(Credential {
        id: Uuid::new_v4(),
        tenant_id,
        issuer,
        subject: claims.rfc7519.sub,
        credential_types: vec![claims.vct],
        format: CredentialFormat::SdJwtVc,
        external_id: claims.rfc7519.jti,
        status: CredentialStatus::Active,
        issued_at,
        valid_until,
        is_revoked: false,
        status_location,
        status_index,
        raw_credential,
    })
}

fn validate_credential_signing_alg(
    config: &CredentialConfiguration,
    alg: JwtAlgorithm,
) -> Result<()> {
    let Some(supported) = config.credential_signing_alg_values_supported.as_ref() else {
        return Ok(());
    };

    if supported
        .iter()
        .any(|candidate| candidate.as_str() == Some(&format!("{alg:?}")))
    {
        Ok(())
    } else {
        Err(IssuanceError::credential_request(format!(
            "SD-JWT VC signing alg '{alg:?}' is not supported by credential configuration"
        )))
    }
}

fn utc_from_numeric_date(value: i64) -> Result<time::UtcDateTime> {
    time::UtcDateTime::from_unix_timestamp(value).map_err(|err| {
        IssuanceError::credential_request(format!("invalid JWT NumericDate '{value}': {err}"))
    })
}

fn status_list_metadata(status: Option<StatusClaim>) -> Result<(Option<url::Url>, Option<i64>)> {
    let Some(status_list) = status.and_then(|status| status.status_list) else {
        return Ok((None, None));
    };

    let index = i64::try_from(status_list.idx).map_err(|_| {
        IssuanceError::credential_request(format!(
            "status_list.idx '{}' exceeds supported range",
            status_list.idx
        ))
    })?;
    Ok((Some(status_list.uri), Some(index)))
}

/// Extracts display metadata from the resolved offer context for a given
/// credential configuration ID.
fn extract_display_metadata(
    context: &ResolvedOfferContext,
    credential_config_id: &str,
    preferred: &[String],
) -> CredentialDisplayMetadata {
    let issuer_name = context
        .issuer_metadata
        .display
        .as_deref()
        .and_then(|displays| select_preferred(displays, |d| d.locale.as_deref(), preferred))
        .and_then(|d| d.name.clone())
        .unwrap_or(context.offer.credential_issuer.to_string());

    let cred_display = context
        .issuer_metadata
        .credential_configurations_supported
        .get(credential_config_id)
        .and_then(|config| config.credential_metadata.as_ref())
        .and_then(|meta| meta.display.as_deref())
        .and_then(|displays| select_preferred(displays, |d| d.locale.as_deref(), preferred));

    let display = match cred_display {
        Some(entry) => entry.clone(),
        None => CredentialDisplay {
            name: credential_config_id.to_owned(),
            ..Default::default()
        },
    };

    CredentialDisplayMetadata {
        display,
        issuer_name,
        credential_type: credential_config_id.to_owned(),
    }
}

/// Selects the preferred display entry from a locale-tagged list.
fn select_preferred<'a, T, F, S>(items: &'a [T], locale_fn: F, preferred: &[S]) -> Option<&'a T>
where
    F: Fn(&T) -> Option<&str>,
    S: AsRef<str>,
{
    if items.is_empty() {
        return None;
    }

    for prefix in preferred {
        if let Some(entry) = items.iter().find(|item| {
            locale_fn(item)
                .map(|l| l.starts_with(prefix.as_ref()))
                .unwrap_or(false)
        }) {
            return Some(entry);
        }
    }
    items.first()
}

#[cfg(test)]
mod tests {
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
}
