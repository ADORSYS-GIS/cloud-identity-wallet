use cloud_wallet_openid4vc::oid4vp::dcql::CredentialQuery;
use cloud_wallet_openid4vc::oid4vp::selection::SelectionResult;
use serde::Serialize;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

use super::PresentationError;
use crate::session::{PresentationFlow, PresentationSession};

const SESSION_TTL: Duration = Duration::minutes(15);

/// Request body for `POST /presentation/start`.
#[derive(Debug, serde::Deserialize)]
pub struct StartPresentationRequest {
    /// The raw OID4VP authorization request (JSON or URI-encoded).
    pub request: String,
    /// Optional origin for DC API flows.
    pub origin: Option<String>,
}

/// Response body for `POST /presentation/start`.
#[derive(Debug, Clone, Serialize)]
pub struct StartPresentationResponse {
    pub session_id: String,
    pub expires_at: String,
    pub flow: PresentationFlow,
    pub verifier: VerifierDisplay,
    pub credential_matches: Vec<CredentialMatchInfo>,
    pub has_transaction_data: bool,
    pub satisfies_query: bool,
}

/// Verifier display information extracted from the presentation context.
#[derive(Debug, Clone, Serialize)]
pub struct VerifierDisplay {
    /// The verifier's client_id value (without prefix).
    pub client_id: String,
    /// Optional verifier name from metadata.
    pub name: Option<String>,
    /// Optional verifier logo URI from metadata.
    pub logo_uri: Option<String>,
}

/// Information about a credential query match.
#[derive(Debug, Clone, Serialize)]
pub struct CredentialMatchInfo {
    /// The DCQL credential query ID.
    pub query_id: String,
    /// The credential format requested.
    pub format: String,
    /// Number of matching wallet credentials.
    pub candidate_count: usize,
    /// Whether multiple selections are allowed for this query.
    pub multiple_allowed: bool,
    /// Candidate credential summaries.
    pub candidates: Vec<CandidateInfo>,
}

/// A candidate credential that matches a query.
#[derive(Debug, Clone, Serialize)]
pub struct CandidateInfo {
    /// Credential identifier in the wallet.
    pub credential_id: String,
    /// Claim paths requested from this credential.
    pub requested_claims: Vec<String>,
}

impl StartPresentationResponse {
    /// Builds the start response from a presentation session.
    pub fn from_session(session: &PresentationSession) -> Result<Self, PresentationError> {
        let ctx = &session.context;

        let verifier = VerifierDisplay {
            client_id: ctx.client_id.value().to_string(),
            name: ctx
                .verifier_metadata
                .as_ref()
                .and_then(|m| m.client_metadata.client_name.clone()),
            logo_uri: ctx
                .verifier_metadata
                .as_ref()
                .and_then(|m| m.client_metadata.logo_uri.as_ref().map(|u| u.to_string())),
        };

        let credential_matches =
            build_credential_matches(&ctx.dcql_query.credentials, &session.dcql_result);

        let expires_at = (OffsetDateTime::now_utc() + SESSION_TTL)
            .format(&Rfc3339)
            .map_err(|e| {
                PresentationError::internal(format!("failed to format expiration timestamp: {e}"))
            })?;

        Ok(Self {
            session_id: session.id.clone(),
            expires_at,
            flow: session.flow,
            verifier,
            credential_matches,
            has_transaction_data: ctx.has_transaction_data(),
            satisfies_query: session.dcql_result.satisfies_query,
        })
    }
}

fn build_credential_matches(
    queries: &[CredentialQuery],
    result: &SelectionResult,
) -> Vec<CredentialMatchInfo> {
    queries
        .iter()
        .map(|query| {
            let candidates_list = result
                .candidates
                .get(&query.id)
                .map(|candidates| {
                    candidates
                        .iter()
                        .map(|c| CandidateInfo {
                            credential_id: c.credential_id.clone(),
                            requested_claims: c
                                .matched_claims
                                .iter()
                                .map(|m| format!("{:?}", m.path))
                                .collect(),
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            let multiple_allowed = result
                .multiple_allowed_by_query_id
                .get(&query.id)
                .copied()
                .unwrap_or(false);

            CredentialMatchInfo {
                query_id: query.id.clone(),
                format: query.format.to_string(),
                candidate_count: candidates_list.len(),
                multiple_allowed,
                candidates: candidates_list,
            }
        })
        .collect()
}
