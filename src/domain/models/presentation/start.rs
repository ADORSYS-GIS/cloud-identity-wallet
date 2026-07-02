use std::collections::HashMap;

use cloud_wallet_openid4vc::core::claim_path_pointer::ClaimPathElement;
use cloud_wallet_openid4vc::oid4vp::client_id::ClientIdPrefix;
use cloud_wallet_openid4vc::oid4vp::dcql::{ClaimsQuery, CredentialQuery, CredentialSet};
use cloud_wallet_openid4vc::oid4vp::selection::{CredentialCandidate, SelectionResult};
use cloud_wallet_openid4vc::oid4vp::transaction_data::TransactionData;
use serde::Serialize;
use serde_json::{Map, Value};

use super::PresentationError;
use crate::domain::models::credential::CredentialDisplayMetadata;
use crate::session::{PresentationFlow, PresentationSession};

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
    pub name: String,
    pub logo_uri: Option<String>,
    pub policy_uri: Option<String>,
    pub verified: bool,
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
        display_map: &HashMap<String, CredentialDisplayMetadata>,
        expires_at: String,
    ) -> Result<Self, PresentationError> {
        let ctx = &session.context;
        let verifier = build_verifier_display(ctx);

        let display_by_id = display_map
            .iter()
            .map(|(id, display)| (id.as_str(), display))
            .collect::<HashMap<_, _>>();
        let credential_matches = build_credential_matches(
            &ctx.dcql_query.credentials,
            ctx.dcql_query.credential_sets.as_deref(),
            &session.dcql_result,
            &display_by_id,
        )?;

        Ok(Self {
            session_id: session.id.clone(),
            expires_at,
            flow: session.flow,
            verifier,
            purpose: presentation_purpose(ctx),
            credential_matches,
            credential_set_options: credential_set_options(
                ctx.dcql_query.credential_sets.as_deref(),
            ),
            transaction_data: transaction_data_display(&ctx.transaction_data),
            requires_consent: true,
        })
    }
}

fn build_verifier_display(
    ctx: &cloud_wallet_openid4vc::oid4vp::client::PresentationContext,
) -> VerifierDisplay {
    let client_metadata = ctx
        .verifier_metadata
        .as_ref()
        .or(ctx.request.client_metadata.as_ref())
        .map(|metadata| &metadata.client_metadata);

    let verified = ctx.verifier_metadata.is_some()
        || ctx.client_id.is_x509_hash()
        || ctx.client_id.is_x509_san_dns();

    VerifierDisplay {
        name: client_metadata
            .and_then(|metadata| metadata.client_name.clone())
            .unwrap_or_else(|| verifier_fallback_name(ctx)),
        logo_uri: client_metadata
            .and_then(|metadata| metadata.logo_uri.as_ref().map(|uri| uri.to_string())),
        policy_uri: client_metadata
            .and_then(|metadata| metadata.policy_uri.as_ref().map(|uri| uri.to_string())),
        verified,
        verification_method: verified.then(|| verification_method(ctx)).flatten(),
    }
}

fn verifier_fallback_name(
    ctx: &cloud_wallet_openid4vc::oid4vp::client::PresentationContext,
) -> String {
    if ctx.client_id.is_x509_hash() {
        return ctx
            .response_uri
            .as_ref()
            .and_then(|uri| uri.host_str())
            .or_else(|| {
                ctx.request
                    .client_metadata_uri
                    .as_ref()
                    .and_then(|uri| uri.host_str())
            })
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| "Verified verifier".to_string());
    }

    ctx.client_id.value().to_string()
}

fn verification_method(
    ctx: &cloud_wallet_openid4vc::oid4vp::client::PresentationContext,
) -> Option<String> {
    match ctx.client_id.prefix() {
        Some(ClientIdPrefix::Origin) => None,
        Some(prefix) => Some(prefix.as_str().to_string()),
        None if ctx.verifier_metadata.is_some() => Some("pre-registered".to_string()),
        None => None,
    }
}

fn presentation_purpose(
    ctx: &cloud_wallet_openid4vc::oid4vp::client::PresentationContext,
) -> Option<String> {
    let metadata = ctx
        .verifier_metadata
        .as_ref()
        .or(ctx.request.client_metadata.as_ref())
        .map(|metadata| &metadata.client_metadata);

    metadata
        .and_then(|metadata| metadata.additional.get("purpose"))
        .and_then(Value::as_str)
        .filter(|purpose| !purpose.trim().is_empty())
        .map(ToOwned::to_owned)
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
                .map(|candidates| build_candidate_info(query, candidates, display_by_id))
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
    query: &CredentialQuery,
    candidates: &[CredentialCandidate],
    display_by_id: &HashMap<&str, &CredentialDisplayMetadata>,
) -> Result<Vec<CandidateInfo>, PresentationError> {
    candidates
        .iter()
        .map(|candidate| {
            let display = display_by_id
                .get(candidate.credential_id.as_str())
                .ok_or_else(|| {
                    PresentationError::internal_message(format!(
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
                        display_name: claim_display_name(claim.path.elements()),
                        value_required: claims_query_for_match(query, claim)
                            .map(|claims_query| claims_query.values.is_some())
                            .unwrap_or_else(|| {
                                claim.selected_values.iter().any(|value| !value.is_null())
                            }),
                    })
                    .collect(),
            })
        })
        .collect()
}

fn claims_query_for_match<'a>(
    query: &'a CredentialQuery,
    claim: &cloud_wallet_openid4vc::oid4vp::selection::MatchedClaim,
) -> Option<&'a ClaimsQuery> {
    let claims = query.claims.as_deref()?;

    claim
        .claim_query_id
        .as_deref()
        .and_then(|id| {
            claims
                .iter()
                .find(|claims_query| claims_query.id.as_deref() == Some(id))
        })
        .or_else(|| {
            claims
                .iter()
                .find(|claims_query| claims_query.path == claim.path)
        })
}

fn claim_display_name(path: &[ClaimPathElement]) -> Option<String> {
    path.iter()
        .rev()
        .find_map(|element| match element {
            ClaimPathElement::String(segment) => Some(humanize_claim_segment(segment)),
            ClaimPathElement::Index(_) | ClaimPathElement::Null => None,
        })
        .filter(|label| !label.is_empty())
}

fn humanize_claim_segment(segment: &str) -> String {
    let mut label = String::new();

    for (index, word) in segment
        .replace(['_', '-'], " ")
        .split_whitespace()
        .enumerate()
    {
        if index > 0 {
            label.push(' ');
        }

        let mut chars = word.chars();
        if let Some(first) = chars.next() {
            label.push(first.to_ascii_uppercase());
            label.extend(chars);
        }
    }

    label
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
            .map(|entry| TransactionDataDisplay {
                data_type: entry.transaction_type().to_string(),
                credential_ids: entry.credential_ids().to_vec(),
                display_data: transaction_display_data(entry),
            })
            .collect(),
    )
}

fn transaction_display_data(entry: &TransactionData<'static>) -> Value {
    let mut display_data = Map::new();

    match entry {
        TransactionData::Openid4vp { data, .. } => {
            if let Some(algorithms) = &data.transaction_data_hashes_alg {
                display_data.insert(
                    "transaction_data_hashes_alg".to_string(),
                    Value::Array(algorithms.iter().cloned().map(Value::String).collect()),
                );
            }
        }
        TransactionData::Other {
            transaction_data_hashes_alg,
            additional_params,
            ..
        } => {
            if let Value::Object(params) = additional_params {
                display_data.extend(params.clone());
            }
            if let Some(algorithms) = transaction_data_hashes_alg {
                display_data.insert(
                    "transaction_data_hashes_alg".to_string(),
                    Value::Array(algorithms.iter().cloned().map(Value::String).collect()),
                );
            }
        }
    }

    Value::Object(display_data)
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use cloud_wallet_openid4vc::core::claim_path_pointer::ClaimValue;
    use cloud_wallet_openid4vc::oauth::authorization::OAuthAuthorizationRequest;
    use cloud_wallet_openid4vc::oid4vp::authorization::{
        AuthorizationRequest, ResponseMode, ResponseType,
    };
    use cloud_wallet_openid4vc::oid4vp::client::PresentationContext;
    use cloud_wallet_openid4vc::oid4vp::client_id::ParsedClientId;
    use cloud_wallet_openid4vc::oid4vp::dcql::{
        ClaimsQuery, CredentialFormat, CredentialMeta, CredentialQuery, DcqlQuery,
    };
    use cloud_wallet_openid4vc::oid4vp::metadata::verifier::VerifierMetadata;
    use cloud_wallet_openid4vc::oid4vp::selection::MatchedClaim;
    use cloud_wallet_openid4vc::oid4vp::transaction_data::TransactionData;
    use serde_json::json;

    use super::*;

    fn presentation_context(client_id: &str) -> PresentationContext {
        let parsed_client_id = ParsedClientId::parse(client_id).unwrap();
        let response_uri = url::Url::parse("https://verifier.example.com/response").unwrap();
        let dcql_query = DcqlQuery {
            credentials: vec![CredentialQuery {
                id: "pid".to_string(),
                format: CredentialFormat::DcSdJwt,
                multiple: None,
                meta: CredentialMeta::SdJwt {
                    vct_values: vec!["https://example.com/vct".to_string()],
                },
                claims: None,
                claim_sets: None,
                trusted_authorities: None,
                require_cryptographic_holder_binding: None,
            }],
            credential_sets: None,
        };

        PresentationContext {
            request: AuthorizationRequest {
                response_type: ResponseType::VpToken,
                nonce: "test-nonce".to_string(),
                response_mode: ResponseMode::DirectPost,
                oauth: OAuthAuthorizationRequest {
                    client_id: parsed_client_id.raw().to_string(),
                    redirect_uri: None,
                    scope: None,
                    state: None,
                    nonce: None,
                    code_challenge: None,
                    code_challenge_method: None,
                },
                response_uri: Some(response_uri.clone()),
                request_uri: None,
                request_uri_method: None,
                dcql_query: Some(dcql_query.clone()),
                client_metadata: None,
                client_metadata_uri: None,
                request: None,
                transaction_data: None,
                verifier_info: None,
                expected_origins: None,
            },
            verifier_metadata: None,
            client_id: parsed_client_id,
            nonce: "test-nonce".to_string(),
            state: None,
            response_uri: Some(response_uri),
            response_mode: ResponseMode::DirectPost,
            dcql_query,
            transaction_data: vec![],
        }
    }

    fn verifier_metadata(name: &str) -> VerifierMetadata {
        serde_json::from_value(json!({
            "client_name": name,
            "vp_formats_supported": {
                "dc+sd-jwt": {
                    "sd-jwt_alg_values": ["ES256"],
                    "kb-jwt_alg_values": ["ES256"]
                }
            }
        }))
        .unwrap()
    }

    #[test]
    fn verifier_display_uses_inline_client_metadata_name() {
        let mut ctx = presentation_context("x509_hash:Uvo3HtuIxuhC92rShpgqcT3YXwrqRxWEviRiA0OZszk");
        ctx.request.client_metadata = Some(verifier_metadata("DATEV Verifier"));

        let display = build_verifier_display(&ctx);

        assert_eq!(display.name, "DATEV Verifier");
        assert!(display.verified);
        assert_eq!(display.verification_method.as_deref(), Some("x509_hash"));
    }

    #[test]
    fn verifier_display_does_not_fallback_to_x509_hash_value() {
        let ctx = presentation_context("x509_hash:Uvo3HtuIxuhC92rShpgqcT3YXwrqRxWEviRiA0OZszk");

        let display = build_verifier_display(&ctx);

        assert_eq!(display.name, "verifier.example.com");
        assert!(display.verified);
    }

    #[test]
    fn claim_display_name_humanizes_last_string_path_segment() {
        let path = vec![
            ClaimPathElement::from("credentialSubject"),
            "username".into(),
        ];

        assert_eq!(claim_display_name(&path).as_deref(), Some("Username"));
    }

    #[test]
    fn claim_display_name_ignores_array_selectors_for_label_fallback() {
        let path = vec![
            ClaimPathElement::from("addresses"),
            ClaimPathElement::Index(0),
            ClaimPathElement::from("street"),
            ClaimPathElement::Null,
        ];

        assert_eq!(claim_display_name(&path).as_deref(), Some("Street"));
    }

    #[test]
    fn claims_query_for_match_resolves_value_constraints_by_claim_query_id() {
        let path = cloud_wallet_openid4vc::core::claim_path_pointer::ClaimPathPointer::new(vec![
            ClaimPathElement::from("age_over_18"),
        ]);
        let query = CredentialQuery {
            id: "pid".to_string(),
            format: CredentialFormat::DcSdJwt,
            multiple: None,
            meta: CredentialMeta::SdJwt {
                vct_values: vec!["https://example.com/vct".to_string()],
            },
            claims: Some(vec![ClaimsQuery {
                path: path.clone(),
                id: Some("age".to_string()),
                values: Some(vec![ClaimValue::Boolean(true)]),
            }]),
            claim_sets: None,
            trusted_authorities: None,
            require_cryptographic_holder_binding: None,
        };
        let matched = MatchedClaim {
            claim_query_id: Some("age".to_string()),
            path,
            selected_values: vec![serde_json::Value::Bool(true)],
        };

        assert!(
            claims_query_for_match(&query, &matched)
                .and_then(|claims_query| claims_query.values.as_ref())
                .is_some()
        );
    }

    #[test]
    fn transaction_display_data_preserves_type_specific_payload() {
        let entry = TransactionData::Other {
            transaction_type: "payment_authorization".to_string(),
            credential_ids: vec!["pid".to_string()],
            transaction_data_hashes_alg: Some(vec!["sha-256".to_string()]),
            additional_params: json!({
                "amount": "250.00",
                "currency": "EUR",
                "payee": "ACME Corp"
            }),
            original_encoded: Cow::Borrowed("encoded"),
        };

        let display = transaction_display_data(&entry);

        assert_eq!(
            display.get("amount").and_then(Value::as_str),
            Some("250.00")
        );
        assert_eq!(
            display
                .get("transaction_data_hashes_alg")
                .and_then(Value::as_array)
                .and_then(|values| values.first())
                .and_then(Value::as_str),
            Some("sha-256")
        );
        assert!(display.get("hash_algorithms").is_none());
    }
}
