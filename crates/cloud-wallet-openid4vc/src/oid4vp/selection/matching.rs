use std::collections::HashMap;

use serde_json::Value;

use crate::core::claim_path_pointer::{ClaimPathPointer, ClaimValue};
use crate::oid4vp::dcql::{
    ClaimsQuery, CredentialFormat, CredentialMeta, CredentialQuery, CredentialSet, DcqlQuery,
    TrustedAuthorityQuery, TrustedAuthorityType,
};

/// The result of matching a full [`DcqlQuery`] against the Wallet's credentials.
#[derive(Debug, Clone)]
pub struct SelectionResult {
    /// All matching candidates, grouped by credential query ID.
    ///
    /// Each key is a `CredentialQuery::id`; the value is the (possibly empty)
    /// list of wallet credentials that satisfy that query.
    pub candidates: HashMap<String, Vec<CredentialCandidate>>,

    /// Credential query IDs for which no matching credential was found.
    pub unsatisfied_queries: Vec<String>,

    /// Whether the full DCQL query can be satisfied.
    pub satisfies_query: bool,

    /// Credential query IDs selected by the default credential-set logic.
    pub selected_credential_query_ids: Vec<String>,

    /// Whether each credential query allows returning multiple credentials.
    pub multiple_allowed_by_query_id: HashMap<String, bool>,
}

impl SelectionResult {
    /// Returns `true` when the DCQL query can be fully satisfied.
    ///
    /// If `credential_sets` are present, satisfaction is evaluated against the
    /// set logic.  Otherwise every credential query must have at least one
    /// candidate.
    pub fn is_satisfied(&self) -> bool {
        self.satisfies_query
    }

    /// Picks credentials for the selected credential query IDs, preferring the
    /// candidate with the most matched claims unless `multiple` is true.
    ///
    /// Returns an empty vec if the query is not satisfiable.
    pub fn select(&self) -> Vec<CredentialCandidate> {
        if !self.is_satisfied() {
            return vec![];
        }

        self.selected_credential_query_ids
            .iter()
            .flat_map(|id| {
                let Some(candidates) = self.candidates.get(id) else {
                    return vec![];
                };

                if self
                    .multiple_allowed_by_query_id
                    .get(id)
                    .copied()
                    .unwrap_or(false)
                {
                    let mut selected = candidates.clone();
                    selected
                        .sort_by_key(|candidate| std::cmp::Reverse(candidate.matched_claims.len()));
                    selected
                } else {
                    candidates
                        .iter()
                        .max_by_key(|c| c.matched_claims.len())
                        .cloned()
                        .into_iter()
                        .collect()
                }
            })
            .collect()
    }
}

/// A credential that matched a single [`CredentialQuery`].
#[derive(Debug, Clone)]
pub struct CredentialCandidate {
    /// Identifier of the [`CredentialQuery`] that this credential satisfies.
    pub credential_query_id: String,

    /// Identifier of the wallet credential (mirrors [`CredentialView::id`]).
    pub credential_id: String,

    /// Claims that matched the query. Empty when the query did not specify a
    /// `claims` filter; presentation builders must still disclose only the
    /// format's mandatory presentation material in that case.
    pub matched_claims: Vec<MatchedClaim>,

    /// Index of the chosen claim set within `CredentialQuery::claim_sets`,
    /// if claim sets were used.  `None` when claim sets are absent.
    pub matched_claim_set_index: Option<usize>,
}

/// A claim that was matched by a [`ClaimsQuery`].
#[derive(Debug, Clone)]
pub struct MatchedClaim {
    /// The claim query that produced this match.
    pub claim_query_id: Option<String>,

    /// The Claims Path Pointer that was matched.
    pub path: ClaimPathPointer,

    /// The concrete values selected by the path pointer.
    pub selected_values: Vec<Value>,
}

/// A format-agnostic view of a credential stored in the Wallet.
///
/// Callers construct this from their domain `Credential` model before passing
/// it into the matching engine.
#[derive(Debug, Clone)]
pub struct CredentialView {
    /// Opaque identifier for this credential (e.g., UUID string).
    pub id: String,

    /// The DCQL format identifier for this credential (e.g., `dc+sd-jwt`, `mso_mdoc`).
    pub format: CredentialFormat,

    /// Verifiable Credential Type URI — present for `dc+sd-jwt` credentials.
    pub vct: Option<String>,

    /// Document type — present for `mso_mdoc` credentials
    /// (e.g., `"org.iso.18013.5.1.mDL"`).
    pub doctype: Option<String>,

    /// W3C VC `type` values — present for `jwt_vc_json` / `ldp_vc` credentials.
    pub credential_types: Vec<String>,

    /// Decoded credential claims as a JSON value.
    ///
    /// For SD-JWT VC: the fully disclosed payload (all disclosures applied,
    /// metadata claims stripped).  For mdoc: a JSON object keyed by namespace,
    /// each value an object of data-element → value pairs.
    pub claims: Value,

    /// The credential issuer identifier (e.g., DID or URL).
    pub issuer: Option<String>,

    /// Type-specific trusted authority references extracted during validation.
    pub trusted_authorities: Vec<CredentialAuthority>,

    /// Whether the credential can produce cryptographic holder binding proof.
    pub holder_binding_supported: bool,
}

/// A trusted authority reference associated with a stored credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialAuthority {
    pub authority_type: TrustedAuthorityType,
    pub value: String,
}

/// Matches a full DCQL query against the Wallet's credentials.
///
/// This is the main entry point of the credential selection engine.  It
/// evaluates each [`CredentialQuery`] against every credential in the wallet,
/// then (if present) evaluates [`CredentialSet`] logic to determine overall
/// satisfiability.
pub fn match_dcql_query(query: &DcqlQuery, credentials: &[CredentialView]) -> SelectionResult {
    let mut candidates: HashMap<String, Vec<CredentialCandidate>> = HashMap::new();
    let multiple_allowed_by_query_id: HashMap<String, bool> = query
        .credentials
        .iter()
        .map(|credential_query| {
            (
                credential_query.id.clone(),
                credential_query.multiple.unwrap_or(false),
            )
        })
        .collect();

    // match each credential query independently.
    for cred_query in &query.credentials {
        let matches: Vec<CredentialCandidate> = credentials
            .iter()
            .filter_map(|wc| match_credential_query(cred_query, wc))
            .collect();

        candidates.insert(cred_query.id.clone(), matches);
    }

    // determine satisfaction and default selection.
    let (unsatisfied_queries, selected_credential_query_ids) =
        if let Some(ref credential_sets) = query.credential_sets {
            // With credential_sets, satisfaction is determined by the set logic.
            evaluate_credential_sets(credential_sets, &candidates)
        } else {
            // Without credential_sets, every credential query must have ≥ 1 match.
            let unsatisfied_queries: Vec<String> = candidates
                .iter()
                .filter(|(_, v)| v.is_empty())
                .map(|(k, _)| k.clone())
                .collect();
            let selected_credential_query_ids = if unsatisfied_queries.is_empty() {
                query.credentials.iter().map(|q| q.id.clone()).collect()
            } else {
                vec![]
            };
            (unsatisfied_queries, selected_credential_query_ids)
        };

    SelectionResult {
        candidates,
        satisfies_query: unsatisfied_queries.is_empty(),
        unsatisfied_queries,
        selected_credential_query_ids,
        multiple_allowed_by_query_id,
    }
}

/// Matches a single credential query against a single wallet credential.
///
/// Returns `Some(CredentialCandidate)` if the credential satisfies the query,
/// `None` otherwise.
///
/// # Matching rules (§6.4.2)
///
/// 1. **Format** — the credential's format must equal the query's format.
/// 2. **Meta** — if `meta` is present, the credential must match the
///    format-specific metadata (e.g., `vct_values` for SD-JWT VC).
/// 3. **Claims** — if `claims` is present, the credential must contain the
///    requested claims.  If `values` is specified on a claims query, at least
///    one selected value must be in the allowed set.
/// 4. **Claim sets** — if `claim_sets` is present, at least one claim set
///    must be fully satisfiable.
/// 5. **Trusted authorities** — if `trusted_authorities` is present, the
///    credential must contain a matching type-specific authority reference.
/// 6. **Holder binding** — if required, the credential must support producing
///    a cryptographic holder binding proof.
pub fn match_credential_query(
    query: &CredentialQuery,
    credential: &CredentialView,
) -> Option<CredentialCandidate> {
    if credential.format != query.format {
        return None;
    }

    if !matches_meta(&query.meta, credential) {
        return None;
    }

    if let Some(ref authorities) = query.trusted_authorities
        && !matches_any_authority(authorities, credential)
    {
        return None;
    }

    // Holder binding match. Per §6.1, absence defaults to true.
    if query.require_cryptographic_holder_binding.unwrap_or(true)
        && !credential.holder_binding_supported
    {
        return None;
    }

    // Claims + claim sets match
    let (matched_claims, matched_claim_set_index) = match_claims(query, &credential.claims)?;

    Some(CredentialCandidate {
        credential_query_id: query.id.clone(),
        credential_id: credential.id.clone(),
        matched_claims,
        matched_claim_set_index,
    })
}

/// Checks whether a credential satisfies the format-specific `meta` constraint.
fn matches_meta(meta: &CredentialMeta, credential: &CredentialView) -> bool {
    match meta {
        CredentialMeta::SdJwt { vct_values } => {
            // §B.3.5: the credential's `vct` must be one of the listed values.
            credential
                .vct
                .as_ref()
                .is_some_and(|vct| vct_values.iter().any(|v| v == vct))
        }
        CredentialMeta::MsoMdoc { doctype_value } => {
            // §B.2.3: the credential's `doctype` must match the value.
            credential
                .doctype
                .as_ref()
                .is_some_and(|dt| dt == doctype_value)
        }
        CredentialMeta::W3CFormat { type_values } => {
            // §B.1.1: the credential must match at least one type combination.
            // Each inner array represents an AND of required types.
            let cred_types = &credential.credential_types;
            type_values
                .iter()
                .any(|required| required.iter().all(|t| cred_types.contains(t)))
        }
    }
}

/// Returns `true` if the credential has a type-specific trusted authority
/// reference matching at least one query entry.
///
/// Per §6.1.1, if multiple entries are present, a credential is accepted
/// if it matches any of the authority queries.
fn matches_any_authority(
    authorities: &[TrustedAuthorityQuery],
    credential: &CredentialView,
) -> bool {
    authorities.iter().any(|authority| {
        credential.trusted_authorities.iter().any(|credential_ref| {
            credential_ref.authority_type == authority.authority_type
                && authority
                    .values
                    .iter()
                    .any(|value| value == &credential_ref.value)
        })
    })
}

/// Evaluates the `claims` and optional `claim_sets` constraints of a
/// credential query against the credential's decoded claims.
///
/// Returns `None` if the claims constraint cannot be satisfied, otherwise
/// returns the list of matched claims and the optional claim set index.
fn match_claims(
    query: &CredentialQuery,
    claims_value: &Value,
) -> Option<(Vec<MatchedClaim>, Option<usize>)> {
    let Some(ref claims_queries) = query.claims else {
        // No selectively disclosable claims were requested. The credential can
        // still satisfy the query, but presentation code must disclose only
        // mandatory claims for the credential format.
        return Some((vec![], None));
    };

    if let Some(ref claim_sets) = query.claim_sets {
        // §6.4.1: When claim_sets is present, the Wallet MUST find at least
        // one claim set (an array of claim query IDs) where every referenced
        // claim query is satisfiable.
        match_with_claim_sets(claims_queries, claim_sets, claims_value)
    } else {
        // Without claim_sets, every claim query must be satisfiable.
        let matched = match_all_claims(claims_queries, claims_value)?;
        Some((matched, None))
    }
}

/// Matches all claim queries against the credential.  Returns `None` if any
/// required claim query fails to match.
fn match_all_claims(
    claims_queries: &[ClaimsQuery],
    claims_value: &Value,
) -> Option<Vec<MatchedClaim>> {
    let mut matched = Vec::with_capacity(claims_queries.len());
    for cq in claims_queries {
        matched.push(match_single_claim(cq, claims_value)?);
    }
    Some(matched)
}

/// Evaluates claim sets: tries each claim set in order and returns the first
/// one that is fully satisfiable.
fn match_with_claim_sets(
    claims_queries: &[ClaimsQuery],
    claim_sets: &[Vec<String>],
    claims_value: &Value,
) -> Option<(Vec<MatchedClaim>, Option<usize>)> {
    // Build a lookup from claim query ID -> claim query.
    let claims_by_id: HashMap<&str, &ClaimsQuery> = claims_queries
        .iter()
        .filter_map(|cq| cq.id.as_deref().map(|id| (id, cq)))
        .collect();

    for (set_idx, set) in claim_sets.iter().enumerate() {
        let mut matched = Vec::with_capacity(set.len());
        let mut all_satisfied = true;

        for claim_id in set {
            if let Some(cq) = claims_by_id.get(claim_id.as_str()) {
                if let Some(m) = match_single_claim(cq, claims_value) {
                    matched.push(m);
                } else {
                    all_satisfied = false;
                    break;
                }
            } else {
                // Unknown claim id in claim set — treat as unsatisfiable.
                all_satisfied = false;
                break;
            }
        }

        if all_satisfied {
            return Some((matched, Some(set_idx)));
        }
    }
    None
}

/// Matches a single [`ClaimsQuery`] against the credential's claims.
///
/// A claim query is satisfied when:
/// 1. The [`ClaimPathPointer`] selects at least one value from the claims.
/// 2. If `values` is specified, at least one selected value equals one of the
///    allowed values.
fn match_single_claim(cq: &ClaimsQuery, claims_value: &Value) -> Option<MatchedClaim> {
    let selected = cq.path.select(claims_value);

    if selected.is_empty() {
        return None;
    }

    // If values constraint is present, at least one selected value must match.
    if let Some(ref allowed) = cq.values {
        let has_match = selected.iter().any(|sv| value_matches_any(sv, allowed));
        if !has_match {
            return None;
        }
    }

    Some(MatchedClaim {
        claim_query_id: cq.id.clone(),
        path: cq.path.clone(),
        selected_values: selected,
    })
}

/// Checks whether a JSON `Value` is equal to any of the allowed `ClaimValue`s.
///
/// Type-aware comparison per §6.3:
/// - `ClaimValue::String` matches `Value::String`
/// - `ClaimValue::Integer` matches `Value::Number`
/// - `ClaimValue::Boolean` matches `Value::Bool`
fn value_matches_any(value: &Value, allowed: &[ClaimValue]) -> bool {
    allowed.iter().any(|cv| claim_value_eq(cv, value))
}

/// Compares a [`ClaimValue`] to a [`serde_json::Value`] for equality.
fn claim_value_eq(cv: &ClaimValue, v: &Value) -> bool {
    match (cv, v) {
        (ClaimValue::String(s), Value::String(vs)) => s == vs,
        (ClaimValue::Integer(i), Value::Number(n)) => n.as_i64() == Some(*i),
        (ClaimValue::Boolean(b), Value::Bool(vb)) => b == vb,
        _ => false,
    }
}

/// Evaluates credential sets and returns unsatisfied required query IDs plus
/// the default credential query IDs to present.
///
/// Per §6.2, a credential set defines `options` — an array of arrays.  Each
/// inner array is an AND group of credential query IDs.  The options form an
/// OR — at least one option must be fully satisfiable.
///
/// When `required` is omitted, it defaults to `true`. Optional sets do not make
/// the query unsatisfied and are not selected by default.
fn evaluate_credential_sets(
    credential_sets: &[CredentialSet],
    candidates: &HashMap<String, Vec<CredentialCandidate>>,
) -> (Vec<String>, Vec<String>) {
    let mut unsatisfied = vec![];
    let mut selected = vec![];

    for set in credential_sets {
        let is_required = set.required.unwrap_or(true);

        // Select the first option (OR branch) that is fully satisfiable.
        let satisfied_option = set.options.iter().find(|option| {
            // An option is satisfied when every credential query ID in it has
            // at least one candidate.
            option
                .iter()
                .all(|cq_id| candidates.get(cq_id).is_some_and(|c| !c.is_empty()))
        });

        if let Some(option) = satisfied_option {
            if is_required {
                for cq_id in option {
                    if !selected.contains(cq_id) {
                        selected.push(cq_id.clone());
                    }
                }
            }
        } else if is_required {
            // Collect the credential query IDs that are referenced by this set
            // and have no candidates.
            for option in &set.options {
                for cq_id in option {
                    let is_empty = candidates.get(cq_id).is_none_or(|c| c.is_empty());
                    if is_empty && !unsatisfied.contains(cq_id) {
                        unsatisfied.push(cq_id.clone());
                    }
                }
            }
        }
    }

    if !unsatisfied.is_empty() {
        selected.clear();
    }

    (unsatisfied, selected)
}
