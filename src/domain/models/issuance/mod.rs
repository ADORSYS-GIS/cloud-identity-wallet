mod error;
mod events;
mod task;

pub use error::{IssuanceError, IssuanceErrorCode};
pub use events::*;
use serde::{Deserialize, Serialize};
pub use task::{IssuanceTask, TaskResult};

type Result<T> = std::result::Result<T, IssuanceError>;

use std::sync::Arc;
use std::time::Duration;

use cloud_wallet_openid4vc::issuance::client::{CryptoSigner, Oid4vciClient, ResolvedOfferContext};
use cloud_wallet_openid4vc::issuance::credential_response::{
    CredentialResponse, DeferredCredentialResult, ImmediateCredentialResponse,
};
use cloud_wallet_openid4vc::issuance::notification::{NotificationEvent, NotificationRequest};
use cloud_wallet_openid4vc::issuance::token_response::TokenResponse;
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

use crate::domain::models::credential::{Credential, CredentialFormat, CredentialStatus};
use crate::domain::models::tenants::SignAlgorithm;
use crate::domain::ports::{CredentialRepo, IssuanceEventPublisher, IssuanceTaskQueue, TenantRepo};
use crate::session::{IssuanceSession, IssuanceState, SessionStore, transition};

/// Maximum number of deferred credential polling attempts.
const MAX_DEFERRED_RETRIES: u32 = 60;

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
    pub credential_repo: Arc<dyn CredentialRepo>,
    pub tenant_repo: Arc<dyn TenantRepo>,
}

impl Clone for IssuanceEngine {
    fn clone(&self) -> Self {
        Self {
            client: Arc::clone(&self.client),
            task_queue: Arc::clone(&self.task_queue),
            event_publisher: Arc::clone(&self.event_publisher),
            credential_repo: Arc::clone(&self.credential_repo),
            tenant_repo: Arc::clone(&self.tenant_repo),
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
            .finish()
    }
}

impl IssuanceEngine {
    /// Create a new orchestrator with all required dependencies.
    pub fn new<Q, P, C, T>(
        client: Oid4vciClient,
        task_queue: Q,
        event_publisher: P,
        credential_repo: C,
        tenant_repo: T,
    ) -> Self
    where
        Q: IssuanceTaskQueue,
        P: IssuanceEventPublisher,
        C: CredentialRepo,
        T: TenantRepo,
    {
        Self {
            client: Arc::new(client),
            task_queue: Arc::new(task_queue),
            event_publisher: Arc::new(event_publisher),
            credential_repo: Arc::new(credential_repo),
            tenant_repo: Arc::new(tenant_repo),
        }
    }

    /// Enqueue a task and spawn its execution.
    ///
    /// This is the single entry point for handlers. It:
    /// 1. Pushes the task onto the queue
    /// 2. Spawns a task in a background worker to execute it.
    #[instrument(skip_all, fields(session_id = %task.session_id, tenant_id = %task.tenant_id))]
    pub async fn enqueue_and_spawn<S: SessionStore + Clone>(
        &self,
        task: IssuanceTask,
        session_store: &S,
    ) -> Result<()> {
        self.task_queue.push(&task).await?;

        let engine = self.clone();
        let sessions = session_store.clone();

        tokio::spawn(async move {
            if let Err(error) = engine.execute(&task, &sessions).await {
                error!(%error, session_id = %task.session_id, "issuance task failed");
            }
        });
        Ok(())
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
    /// Always acknowledges the task on the queue when done.
    pub async fn execute<S: SessionStore>(
        &self,
        task: &IssuanceTask,
        session_store: &S,
    ) -> Result<()> {
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
            error!(error = %err, step = %err.step(), "issuance failed");

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

        if let Err(ack_err) = self.task_queue.ack(task).await {
            warn!(error = %ack_err, "failed to acknowledge issuance task");
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
        let issuer = context.offer.credential_issuer.as_str();
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
                .store_credential(tenant_id, issuer, config_id, raw)
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

    /// Store a raw credential string.
    #[instrument(skip(self, raw_credential))]
    async fn store_credential(
        &self,
        tenant_id: Uuid,
        issuer: &str,
        credential_config_id: &str,
        raw_credential: String,
    ) -> Result<Uuid> {
        // TODO : Parse the raw credential to extract the fields
        let credential = Credential {
            id: Uuid::new_v4(),
            tenant_id,
            issuer: issuer.to_owned(),
            subject: None,
            credential_types: vec![credential_config_id.to_owned()],
            format: CredentialFormat::SdJwtVc,
            external_id: None,
            status: CredentialStatus::Active,
            issued_at: time::UtcDateTime::now(),
            valid_until: None,
            is_revoked: false,
            status_location: None,
            status_index: None,
            raw_credential,
        };

        let id = self.credential_repo.upsert(credential).await?;
        info!(credential_id = %id, "credential stored successfully");
        Ok(id)
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
