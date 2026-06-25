use std::collections::HashMap;

use cloud_wallet_openid4vc::core::claim_path_pointer::ClaimPathElement;
use cloud_wallet_openid4vc::oid4vp::dcql::{CredentialQuery, CredentialSet};
use cloud_wallet_openid4vc::oid4vp::selection::CredentialCandidate;
use cloud_wallet_openid4vc::oid4vp::selection::SelectionResult;
use cloud_wallet_openid4vc::oid4vp::transaction_data::TransactionData;
use serde::Serialize;
use serde_json::{Map, Value};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

use super::PresentationError;
use crate::domain::models::credential::CredentialDisplayMetadata;
use crate::domain::models::presentation::StoredCredentialView;
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
    pub purpose: Option<String>,
    pub credential_matches: Vec<CredentialMatchInfo>,
    pub credential_set_options: Option<Vec<Vec<String>>>,
    pub transaction_data: Option<Vec<TransactionDataDisplay>>,
    pub requires_consent: bool,
}

/// Verifier display information extracted from the presentation context.
#[derive(Debug, Clone, Serialize)]
pub struct VerifierDisplay {
    /// Human-readable verifier name from metadata, falling back to client_id.
    pub name: String,
    /// Optional verifier logo URI from metadata.
    pub logo_uri: Option<String>,
    /// Optional verifier policy URI from metadata.
    pub policy_uri: Option<String>,
    /// Whether the verifier identity was cryptographically verified.
    pub verified: bool,
    /// Client identifier scheme used to verify or identify the verifier.
    pub verification_method: Option<String>,
}

/// Information about a credential query match.
#[derive(Debug, Clone, Serialize)]
pub struct CredentialMatchInfo {
    /// The DCQL credential query ID.
    pub query_id: String,
    /// Whether this query is required by the DCQL credential set rules.
    pub required: bool,
    /// Candidate credential summaries.
    pub candidates: Vec<CandidateInfo>,
}

/// A candidate credential that matches a query.
#[derive(Debug, Clone, Serialize)]
pub struct CandidateInfo {
    /// Credential identifier in the wallet.
    pub credential_id: String,
    /// Display metadata for rendering this credential option.
    pub display: CredentialDisplayMetadata,
    /// Claim paths requested from this credential.
    pub requested_claims: Vec<RequestedClaimInfo>,
}

/// Claim display information requested from a candidate credential.
#[derive(Debug, Clone, Serialize)]
pub struct RequestedClaimInfo {
    pub path: Vec<ClaimPathElement>,
    pub display_name: Option<String>,
    pub value_required: bool,
}

/// Transaction data display information for explicit user acknowledgment.
#[derive(Debug, Clone, Serialize)]
pub struct TransactionDataDisplay {
    #[serde(rename = "type")]
    pub data_type: String,
    pub credential_ids: Vec<String>,
    pub display_data: Value,
}

impl StartPresentationResponse {
    /// Builds the start response from a presentation session.
    pub fn from_session(
        session: &PresentationSession,
        credentials: &[StoredCredentialView],
    ) -> Result<Self, PresentationError> {
        let ctx = &session.context;
        let client_id_value = ctx.client_id.value().to_string();
        let client_metadata = ctx.verifier_metadata.as_ref().map(|m| &m.client_metadata);

        let verifier = VerifierDisplay {
            name: client_metadata
                .and_then(|m| m.client_name.clone())
                .unwrap_or_else(|| client_id_value.clone()),
            logo_uri: client_metadata.and_then(|m| m.logo_uri.as_ref().map(|u| u.to_string())),
            policy_uri: client_metadata.and_then(|m| m.policy_uri.as_ref().map(|u| u.to_string())),
            verified: ctx.verifier_metadata.is_some() && !ctx.client_id.is_redirect_uri(),
            verification_method: ctx
                .client_id
                .prefix()
                .map(|prefix| prefix.as_str().to_string())
                .or_else(|| Some("pre-registered".to_string())),
        };

        let display_by_id = credentials
            .iter()
            .map(|credential| (credential.view.id.as_str(), &credential.display))
            .collect::<HashMap<_, _>>();
        let credential_matches = build_credential_matches(
            &ctx.dcql_query.credentials,
            ctx.dcql_query.credential_sets.as_deref(),
            &session.dcql_result,
            &display_by_id,
        )?;

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
            purpose: None,
            credential_matches,
            credential_set_options: credential_set_options(
                ctx.dcql_query.credential_sets.as_deref(),
            ),
            transaction_data: transaction_data_display(&ctx.transaction_data),
            requires_consent: true,
        })
    }
}

fn build_credential_matches(
    queries: &[CredentialQuery],
    credential_sets: Option<&[CredentialSet]>,
    result: &SelectionResult,
    display_by_id: &HashMap<&str, &CredentialDisplayMetadata>,
) -> Result<Vec<CredentialMatchInfo>, PresentationError> {
    queries
        .iter()
        .map(|query| {
            let candidates = result
                .candidates
                .get(&query.id)
                .map(|candidates| build_candidate_info(candidates, display_by_id))
                .transpose()?
                .unwrap_or_default();

            Ok(CredentialMatchInfo {
                query_id: query.id.clone(),
                required: query_required(&query.id, credential_sets),
                candidates,
            })
        })
        .collect()
}

fn build_candidate_info(
    candidates: &[CredentialCandidate],
    display_by_id: &HashMap<&str, &CredentialDisplayMetadata>,
) -> Result<Vec<CandidateInfo>, PresentationError> {
    candidates
        .iter()
        .map(|candidate| {
            let display = display_by_id
                .get(candidate.credential_id.as_str())
                .ok_or_else(|| {
                    PresentationError::internal(format!(
                        "missing display metadata for credential {}",
                        candidate.credential_id
                    ))
                })?;

            Ok(CandidateInfo {
                credential_id: candidate.credential_id.clone(),
                display: (*display).clone(),
                requested_claims: candidate
                    .matched_claims
                    .iter()
                    .map(|claim| RequestedClaimInfo {
                        path: claim.path.elements().to_vec(),
                        display_name: claim.claim_query_id.clone(),
                        value_required: claim.selected_values.iter().any(|value| !value.is_null()),
                    })
                    .collect(),
            })
        })
        .collect()
}

fn query_required(query_id: &str, credential_sets: Option<&[CredentialSet]>) -> bool {
    let Some(credential_sets) = credential_sets else {
        return true;
    };

    credential_sets.iter().any(|set| {
        set.required.unwrap_or(true)
            && set
                .options
                .iter()
                .any(|option| option.iter().any(|id| id == query_id))
    })
}

fn credential_set_options(credential_sets: Option<&[CredentialSet]>) -> Option<Vec<Vec<String>>> {
    credential_sets.map(|sets| {
        sets.iter()
            .flat_map(|set| set.options.iter().cloned())
            .collect()
    })
}

fn transaction_data_display(
    transaction_data: &[TransactionData<'static>],
) -> Option<Vec<TransactionDataDisplay>> {
    if transaction_data.is_empty() {
        return None;
    }

    Some(
        transaction_data
            .iter()
            .map(|entry| {
                let mut display_data = Map::new();
                display_data.insert(
                    "hash_algorithms".to_string(),
                    Value::Array(
                        entry
                            .hash_algorithms()
                            .into_iter()
                            .map(Value::String)
                            .collect(),
                    ),
                );

                TransactionDataDisplay {
                    data_type: entry.transaction_type().to_string(),
                    credential_ids: entry.credential_ids().to_vec(),
                    display_data: Value::Object(display_data),
                }
            })
            .collect(),
    )
}
