use std::borrow::Cow;

use serde::{Deserialize, Serialize};
use tracing::info;
use uuid::Uuid;

use crate::domain::models::issuance::{FlowType, events::IssuanceStep};
use crate::session::IssuanceSession;

/// A task representing a credential issuance job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuanceTask {
    /// Adapter-owned queue entry ID, set when the task is popped from Redis Streams.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue_id: Option<String>,
    /// The session ID this task belongs to.
    pub session_id: String,
    /// The tenant ID requesting the credential.
    pub tenant_id: Uuid,
    /// The flow type (auth code or pre-auth code).
    pub flow: FlowType,
    /// Authorization code (for auth code flow).
    pub authorization_code: Option<String>,
    /// PKCE code verifier (for auth code flow).
    pub pkce_verifier: Option<String>,
    /// Pre-authorized code (for pre-auth flow).
    pub pre_authorized_code: Option<String>,
    /// Transaction code (for pre-auth flow, if required).
    pub tx_code: Option<String>,
}

impl IssuanceTask {
    /// Create a new issuance task for the authorization code flow.
    pub fn new_authz_code(
        session: &IssuanceSession,
        authorization_code: impl Into<String>,
        pkce_verifier: impl Into<String>,
    ) -> Self {
        info!(
            session_id = %session.id,
            tenant_id = %session.tenant_id,
            "creating auth code issuance task"
        );
        Self {
            queue_id: None,
            session_id: session.id.clone(),
            tenant_id: session.tenant_id,
            flow: FlowType::AuthorizationCode,
            authorization_code: Some(authorization_code.into()),
            pkce_verifier: Some(pkce_verifier.into()),
            pre_authorized_code: None,
            tx_code: None,
        }
    }

    /// Create a new issuance task for the pre-authorized code flow.
    pub fn new_pre_authz_code(
        session: &IssuanceSession,
        pre_authorized_code: impl Into<String>,
        tx_code: Option<String>,
    ) -> Self {
        info!(
            session_id = %session.id,
            tenant_id = %session.tenant_id,
            "creating pre-auth issuance task"
        );
        Self {
            queue_id: None,
            session_id: session.id.clone(),
            tenant_id: session.tenant_id,
            flow: FlowType::PreAuthorizedCode,
            authorization_code: None,
            pkce_verifier: None,
            pre_authorized_code: Some(pre_authorized_code.into()),
            tx_code,
        }
    }

    /// Create a new issuance task for pre-auth flow without tx_code (consent given).
    pub fn new_pre_auth_no_tx_code(session: &IssuanceSession) -> Self {
        info!(
            session_id = %session.id,
            tenant_id = %session.tenant_id,
            "creating pre-auth issuance task (no tx_code)"
        );
        let offer = &session.context.offer;
        let pre_auth = offer
            .grants
            .as_ref()
            .and_then(|g| g.pre_authorized_code.as_ref());
        let pre_authorized_code = pre_auth
            .map(|g| g.pre_authorized_code.clone())
            .unwrap_or_default();

        Self {
            queue_id: None,
            session_id: session.id.clone(),
            tenant_id: session.tenant_id,
            flow: FlowType::PreAuthorizedCode,
            authorization_code: None,
            pkce_verifier: None,
            pre_authorized_code: Some(pre_authorized_code),
            tx_code: None,
        }
    }

    /// Serialize the task to a JSON vector for storage.
    pub fn to_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserialize a task from a JSON vector.
    pub fn from_json(json: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(json)
    }
}

/// Result of processing an issuance task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResult {
    /// Whether the task completed successfully.
    pub success: bool,
    /// The session ID this result belongs to.
    pub session_id: String,
    /// Credential IDs that were issued (if successful).
    pub credential_ids: Vec<String>,
    /// Credential types that were issued (if successful).
    pub credential_types: Vec<String>,
    /// Error message (if failed).
    pub error: Option<Cow<'static, str>>,
    /// Error step (if failed).
    pub error_step: Option<Cow<'static, str>>,
}

impl TaskResult {
    /// Create a successful task result.
    pub fn success(
        session_id: impl Into<String>,
        credential_ids: Vec<String>,
        credential_types: Vec<String>,
    ) -> Self {
        Self {
            success: true,
            session_id: session_id.into(),
            credential_ids,
            credential_types,
            error: None,
            error_step: None,
        }
    }

    /// Create a failed task result.
    pub fn failure(
        session_id: impl Into<String>,
        error: impl Into<Cow<'static, str>>,
        step: IssuanceStep,
    ) -> Self {
        Self {
            success: false,
            session_id: session_id.into(),
            credential_ids: vec![],
            credential_types: vec![],
            error: Some(error.into()),
            error_step: Some(step.as_str().into()),
        }
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserialize from JSON.
    pub fn from_json(json: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(json)
    }
}
