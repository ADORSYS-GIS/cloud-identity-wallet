use std::borrow::Cow;
use std::error::Error as StdError;
use std::fmt;

use cloud_wallet_openid4vc::issuance::client::ClientError;
use serde::{Deserialize, Serialize};

use crate::domain::models::credential::CredentialError;
use crate::domain::models::issuance::events::IssuanceStep;
use crate::domain::models::tenants::TenantError;
use crate::session::SessionError;

type DynError = Box<dyn StdError + Send + Sync>;

/// Machine-readable error codes exposed by issuance APIs and SSE failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuanceErrorCode {
    InvalidCredentialOffer,
    IssuerMetadataFetchFailed,
    AuthServerMetadataFetchFailed,
    SessionNotFound,
    InvalidSessionState,
    InvalidTxCode,
    InvalidRequest,
    CredentialNotFound,
    InternalError,
    Cancelled,
    External(Cow<'static, str>),
}

impl IssuanceErrorCode {
    pub fn as_str(&self) -> &str {
        match self {
            Self::InvalidCredentialOffer => "invalid_credential_offer",
            Self::IssuerMetadataFetchFailed => "issuer_metadata_fetch_failed",
            Self::AuthServerMetadataFetchFailed => "auth_server_metadata_fetch_failed",
            Self::SessionNotFound => "session_not_found",
            Self::InvalidSessionState => "invalid_session_state",
            Self::InvalidTxCode => "invalid_tx_code",
            Self::InvalidRequest => "invalid_request",
            Self::CredentialNotFound => "credential_not_found",
            Self::InternalError => "internal_error",
            Self::Cancelled => "cancelled",
            Self::External(code) => code.as_ref(),
        }
    }
}

impl fmt::Display for IssuanceErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error that can occur during credential issuance orchestration.
#[derive(Debug, thiserror::Error)]
#[error("{error}: {error_description:?}")]
pub struct IssuanceError {
    pub error: IssuanceErrorCode,
    pub error_description: Option<String>,
    pub step: IssuanceStep,
    #[source]
    pub source: Option<DynError>,
}

impl IssuanceError {
    /// Create a new issuance error.
    pub fn new(
        error: IssuanceErrorCode,
        error_description: impl Into<Option<String>>,
        step: IssuanceStep,
    ) -> Self {
        Self {
            error,
            error_description: error_description.into(),
            step,
            source: None,
        }
    }

    /// Attach a source error to this issuance error.
    pub fn with_source(self, source: impl StdError + Send + Sync + 'static) -> Self {
        Self {
            source: Some(Box::new(source)),
            ..self
        }
    }

    /// Create an external error.
    pub fn external(
        step: IssuanceStep,
        error: impl Into<Cow<'static, str>>,
        error_description: Option<String>,
    ) -> Self {
        Self::new(
            IssuanceErrorCode::External(error.into()),
            error_description,
            step,
        )
    }

    /// Create an internal error with the given source.
    pub fn internal(source: impl StdError + Send + Sync + 'static) -> Self {
        let message = source.to_string();
        Self::internal_message(message).with_source(source)
    }

    /// Create an internal error with a message.
    pub fn internal_message(message: impl fmt::Display) -> Self {
        Self::new(
            IssuanceErrorCode::InternalError,
            Some(message.to_string()),
            IssuanceStep::Internal,
        )
    }

    /// Create a cancel error with the given reason.
    pub fn cancelled(reason: impl fmt::Display) -> Self {
        Self::new(
            IssuanceErrorCode::Cancelled,
            Some(reason.to_string()),
            IssuanceStep::Internal,
        )
    }

    /// Create an offer resolution error with the given description.
    pub fn offer_resolution(description: impl fmt::Display) -> Self {
        Self::new(
            IssuanceErrorCode::InvalidCredentialOffer,
            Some(description.to_string()),
            IssuanceStep::OfferResolution,
        )
    }

    /// Create a metadata error with the given description.
    pub fn metadata(description: impl fmt::Display) -> Self {
        Self::new(
            IssuanceErrorCode::IssuerMetadataFetchFailed,
            Some(description.to_string()),
            IssuanceStep::Metadata,
        )
    }

    /// Create an authorization error with the given description.
    pub fn token(description: impl fmt::Display) -> Self {
        Self::external(
            IssuanceStep::Token,
            "token_error",
            Some(description.to_string()),
        )
    }

    /// Create a credential request error with the given description.
    pub fn credential_request(description: impl fmt::Display) -> Self {
        Self::external(
            IssuanceStep::CredentialRequest,
            "credential_request_failed",
            Some(description.to_string()),
        )
    }

    /// Create a deferred credential error with the given description.
    pub fn deferred_credential(description: impl fmt::Display) -> Self {
        Self::external(
            IssuanceStep::DeferredCredential,
            "deferred_credential_failed",
            Some(description.to_string()),
        )
    }

    /// Returns the issuance step this error corresponds to.
    pub fn step(&self) -> IssuanceStep {
        self.step
    }

    /// Returns the machine-readable error code for this error.
    pub fn error(&self) -> &str {
        self.error.as_str()
    }

    /// Returns the human-readable error details if any.
    pub fn error_description(&self) -> Option<&str> {
        self.error_description.as_deref()
    }
}

fn oid4vci_error_code<T: Serialize>(error: &T) -> String {
    serde_json::to_value(error)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_else(|| "external_error".to_owned())
}

impl From<ClientError> for IssuanceError {
    fn from(err: ClientError) -> Self {
        match err {
            ClientError::Authorization(e) => Self::external(
                IssuanceStep::Authorization,
                oid4vci_error_code(&e.error),
                e.error_description,
            ),
            ClientError::Token(e) => Self::external(
                IssuanceStep::Token,
                oid4vci_error_code(&e.error),
                e.error_description,
            ),
            ClientError::Credential(e) => Self::external(
                IssuanceStep::CredentialRequest,
                oid4vci_error_code(&e.error),
                e.error_description,
            ),
            ClientError::DeferredCredential(e) => Self::external(
                IssuanceStep::DeferredCredential,
                oid4vci_error_code(&e.error),
                e.error_description,
            ),
            ClientError::Notification(e) => Self::external(
                IssuanceStep::Notification,
                oid4vci_error_code(&e.error),
                e.error_description,
            ),
            ClientError::Validation { message } => Self::offer_resolution(message),
            ClientError::UnknownCredentialConfiguration { id } => Self::external(
                IssuanceStep::CredentialRequest,
                "unknown_credential_configuration",
                Some(format!("unknown credential configuration: {id}")),
            ),
            ClientError::NoSupportedGrantType => Self::offer_resolution(
                "no supported grant type found in credential offer or issuer metadata",
            ),
            ClientError::MetadataDiscovery { message } => Self::metadata(message),
            ClientError::IssuerMetadataDiscovery { message } => Self::metadata(message),
            ClientError::AsMetadataDiscovery { message } => Self::metadata(message),
            ClientError::Http {
                message,
                status,
                body,
                source,
            } => {
                let description = message
                    .map(|m| m.to_string())
                    .or(body)
                    .or_else(|| status.map(|s| format!("HTTP {s}")))
                    .unwrap_or_else(|| "external HTTP request failed".into());
                let mut error = Self::new(
                    IssuanceErrorCode::InternalError,
                    Some(description),
                    IssuanceStep::Internal,
                );
                error.source = source;
                error
            }
            ClientError::InvalidResponse { message } => Self::internal_message(message),
            ClientError::Configuration { message } => Self::internal_message(message),
            ClientError::Internal { message } => Self::internal_message(message),
        }
    }
}

impl From<CredentialError> for IssuanceError {
    fn from(err: CredentialError) -> Self {
        Self::internal_message(format!("error while storing credential: {err}")).with_source(err)
    }
}

impl From<SessionError> for IssuanceError {
    fn from(err: SessionError) -> Self {
        Self::internal_message(format!("error storing session: {err}")).with_source(err)
    }
}

impl From<serde_json::Error> for IssuanceError {
    fn from(err: serde_json::Error) -> Self {
        Self::internal_message(format!("error serializing/deserializing: {err}")).with_source(err)
    }
}

impl From<TenantError> for IssuanceError {
    fn from(err: TenantError) -> Self {
        Self::internal_message(format!("error handling tenant: {err}")).with_source(err)
    }
}

impl From<tokio::task::JoinError> for IssuanceError {
    fn from(err: tokio::task::JoinError) -> Self {
        Self::internal_message(format!("error executing task: {err}")).with_source(err)
    }
}

#[cfg(test)]
mod tests {
    use cloud_wallet_openid4vc::issuance::error::{AuthzErrorResponse, Oid4vciError};

    use super::*;

    #[test]
    fn step_display_matches_enum() {
        assert_eq!(IssuanceStep::OfferResolution.as_str(), "offer_resolution");
        assert_eq!(IssuanceStep::Metadata.as_str(), "metadata");
        assert_eq!(IssuanceStep::Authorization.as_str(), "authorization");
        assert_eq!(IssuanceStep::Token.as_str(), "token");
        assert_eq!(
            IssuanceStep::CredentialRequest.as_str(),
            "credential_request"
        );
        assert_eq!(
            IssuanceStep::DeferredCredential.as_str(),
            "deferred_credential"
        );
        assert_eq!(IssuanceStep::Internal.as_str(), "internal");
    }

    #[test]
    fn authorization_error_maps_to_external_error() {
        let authz_error =
            ClientError::Authorization(Oid4vciError::new(AuthzErrorResponse::InvalidRequest));
        let err: IssuanceError = authz_error.into();
        // check that it is an external error
        assert!(matches!(err.error, IssuanceErrorCode::External(_)));
        assert_eq!(err.error(), "invalid_request");
        assert_eq!(err.step(), IssuanceStep::Authorization);
    }

    #[test]
    fn storage_error_maps_to_internal_error() {
        let err: IssuanceError = CredentialError::Other("disk full".into()).into();
        assert_eq!(err.error(), "internal_error");
        assert_eq!(err.step(), IssuanceStep::Internal);
    }
}
