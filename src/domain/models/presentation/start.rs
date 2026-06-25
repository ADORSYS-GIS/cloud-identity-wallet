use std::collections::HashMap;

use cloud_wallet_openid4vc::oid4vp::dcql::{CredentialQuery, CredentialSet};
use cloud_wallet_openid4vc::oid4vp::selection::SelectionResult;
use serde::Serialize;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

use super::PresentationError;
use crate::domain::models::credential::CredentialDisplayMetadata;
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
    pub credential_matches: Vec<CredentialMatch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_set_options: Option<Vec<Vec<String>>>,
    pub transaction_data: Option<Vec<TransactionDataDisplay>>,
    pub requires_consent: bool,
}

/// Verifier display information extracted from the presentation context.
#[derive(Debug, Clone, Serialize)]
pub struct VerifierDisplay {
    pub name: String,
    pub logo_uri: Option<String>,
    pub policy_uri: Option<String>,
    pub verified: bool,
    pub verification_method: Option<String>,
}

/// A credential query match as defined by the API spec.
#[derive(Debug, Clone, Serialize)]
pub struct CredentialMatch {
    pub query_id: String,
    pub required: bool,
    pub candidates: Vec<CredentialCandidate>,
}

/// A candidate credential that matches a query.
#[derive(Debug, Clone, Serialize)]
pub struct CredentialCandidate {
    pub credential_id: String,
    pub display: CredentialDisplayMetadata,
    pub requested_claims: Vec<RequestedClaim>,
}

/// A requested claim with its path and metadata.
#[derive(Debug, Clone, Serialize)]
pub struct RequestedClaim {
    pub path: cloud_wallet_openid4vc::core::claim_path_pointer::ClaimPathPointer,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_required: Option<bool>,
}

/// Transaction data display entry.
#[derive(Debug, Clone, Serialize)]
pub struct TransactionDataDisplay {
    #[serde(rename = "type")]
    pub data_type: String,
    pub credential_ids: Vec<String>,
    pub display_data: serde_json::Value,
}

impl From<&cloud_wallet_openid4vc::oid4vp::transaction_data::TransactionData<'_>>
    for TransactionDataDisplay
{
    fn from(td: &cloud_wallet_openid4vc::oid4vp::transaction_data::TransactionData<'_>) -> Self {
        use cloud_wallet_openid4vc::oid4vp::transaction_data::TransactionData;
        match td {
            TransactionData::Openid4vp { data, .. } => {
                let mut display_data = serde_json::Map::new();
                if let Some(algs) = &data.transaction_data_hashes_alg {
                    display_data.insert(
                        "transaction_data_hashes_alg".to_string(),
                        serde_json::to_value(algs).unwrap_or_default(),
                    );
                }
                Self {
                    data_type: data.data_type.to_string(),
                    credential_ids: data.credential_ids.clone(),
                    display_data: serde_json::Value::Object(display_data),
                }
            }
            TransactionData::Other {
                transaction_type,
                credential_ids,
                additional_params,
                ..
            } => Self {
                data_type: transaction_type.clone(),
                credential_ids: credential_ids.clone(),
                display_data: additional_params.clone(),
            },
        }
    }
}

impl StartPresentationResponse {
    /// Builds the start response from a presentation session and credential
    /// display metadata.
    pub fn from_session(
        session: &PresentationSession,
        credential_displays: &HashMap<String, CredentialDisplayMetadata>,
    ) -> Result<Self, PresentationError> {
        let ctx = &session.context;

        let verifier = VerifierDisplay {
            name: ctx
                .verifier_metadata
                .as_ref()
                .and_then(|m| m.client_metadata.client_name.clone())
                .unwrap_or_else(|| ctx.client_id.value().to_string()),
            logo_uri: ctx
                .verifier_metadata
                .as_ref()
                .and_then(|m| m.client_metadata.logo_uri.as_ref().map(|u| u.to_string())),
            policy_uri: ctx
                .verifier_metadata
                .as_ref()
                .and_then(|m| m.client_metadata.policy_uri.as_ref().map(|u| u.to_string())),
            verified: ctx.verifier_metadata.is_some(),
            verification_method: ctx.client_id.prefix().map(|p| p.as_str().to_string()),
        };

        let credential_matches = build_credential_matches(
            &ctx.dcql_query.credentials,
            &session.dcql_result,
            credential_displays,
            ctx.dcql_query.credential_sets.as_deref(),
        );

        let credential_set_options = ctx.dcql_query.credential_sets.as_ref().and_then(|sets| {
            let all_options: Vec<Vec<String>> =
                sets.iter().flat_map(|set| set.options.clone()).collect();
            if !all_options.is_empty() {
                Some(all_options)
            } else {
                None
            }
        });

        let transaction_data = if ctx.transaction_data.is_empty() {
            None
        } else {
            Some(
                ctx.transaction_data
                    .iter()
                    .map(TransactionDataDisplay::from)
                    .collect(),
            )
        };

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
            credential_set_options,
            transaction_data,
            requires_consent: true,
        })
    }
}

fn build_credential_matches(
    queries: &[CredentialQuery],
    result: &SelectionResult,
    credential_displays: &HashMap<String, CredentialDisplayMetadata>,
    credential_sets: Option<&[CredentialSet]>,
) -> Vec<CredentialMatch> {
    queries
        .iter()
        .map(|query| {
            let candidates_list = result
                .candidates
                .get(&query.id)
                .map(|candidates| {
                    candidates
                        .iter()
                        .map(|c| {
                            let display = credential_displays
                                .get(&c.credential_id)
                                .cloned()
                                .unwrap_or_default();

                            let requested_claims = c
                                .matched_claims
                                .iter()
                                .map(|m| RequestedClaim {
                                    path: m.path.clone(),
                                    display_name: None,
                                    value_required: lookup_value_required(query, &m.path),
                                })
                                .collect();

                            CredentialCandidate {
                                credential_id: c.credential_id.clone(),
                                display,
                                requested_claims,
                            }
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            CredentialMatch {
                query_id: query.id.clone(),
                required: is_query_required(&query.id, credential_sets),
                candidates: candidates_list,
            }
        })
        .collect()
}

/// Determines whether a query is required based on credential set membership.
fn is_query_required(query_id: &str, credential_sets: Option<&[CredentialSet]>) -> bool {
    let Some(sets) = credential_sets else {
        return true;
    };
    let mut in_any_set = false;
    let mut in_required_set = false;
    for set in sets {
        for option in &set.options {
            if option.iter().any(|id| id == query_id) {
                in_any_set = true;
                if set.required.unwrap_or(true) {
                    in_required_set = true;
                }
            }
        }
    }
    if !in_any_set {
        true // standalone queries are required
    } else {
        in_required_set
    }
}

/// Looks up whether a claims query had a `values` constraint for a given path.
fn lookup_value_required(
    query: &CredentialQuery,
    path: &cloud_wallet_openid4vc::core::claim_path_pointer::ClaimPathPointer,
) -> Option<bool> {
    let claims = query.claims.as_ref()?;
    for claim in claims {
        if &claim.path == path {
            return Some(claim.values.is_some());
        }
    }
    None
}
