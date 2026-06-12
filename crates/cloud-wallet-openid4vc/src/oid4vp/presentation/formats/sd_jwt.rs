//! SD-JWT VC presentation format as defined in [OpenID4VP Appendix B.3].
//!
//! Implements the Wallet-side logic for building SD-JWT VC presentations:
//!
//! 1. **Selective Disclosure** — selects only the disclosures needed to reveal
//!    claims requested by the Verifier via [`ClaimPathPointer`]s.
//! 2. **Key Binding JWT** — constructs and signs a KB-JWT (RFC 9901) that binds
//!    the presentation to the verifier audience and request nonce.
//! 3. **Presentation assembly** — produces the final compact SD-JWT presentation
//!    string: `<issuer-jwt>~<disc>*~<kb-jwt>`.
//!
//! # Example
//!
//! ```ignore
//! use cloud_wallet_openid4vc::oid4vp::presentation::sd_jwt::SdJwtPresentation;
//!
//! let sd_jwt_presentation = SdJwtPresentation::builder(raw_credential, client_id, nonce)
//!     .requested_claims(claim_paths)
//!     .signer(|claims| { /* sign KB-JWT */ })
//!     .build();
//!
//! let presentation = sd_jwt_presentation.create_presentation()?;
//!
//! ```
//!
//! [OpenID4VP Appendix B.3]: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.3

use std::collections::{HashMap, HashSet};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use cloud_wallet_crypto::digest::HashAlg;
use serde_json::Value;

use crate::core::claim_path_pointer::{ClaimPathElement, ClaimPathPointer};
use crate::formats::sd_jwt::{
    Disclosure, KeyBindingClaims, KeyBindingJwt, SdJwt, disclosure_digest,
    disclosure_hash_algorithm,
};
use crate::oid4vp::authorization::Presentation;
use crate::oid4vp::presentation::PresentationFactory;
use crate::oid4vp::presentation::error::ProofError;

/// Function type for signing a Key Binding JWT.
///
/// Receives the [`KeyBindingClaims`] and must return a compact JWS string
/// (header.payload.signature). The signer must use the holder private key
/// corresponding to the key material identified by the SD-JWT VC `cnf` claim.
/// Its JOSE header must contain `typ: "kb+jwt"` and an `alg` compatible with
/// that confirmation key.
pub type JwtSigner = Box<dyn Fn(&KeyBindingClaims) -> Result<String, ProofError> + Send + Sync>;

const SD_CLAIM: &str = "_sd";
const ARRAY_DIGEST_CLAIM: &str = "...";

/// SD-JWT VC presentation for building verifiable presentations.
///
/// Orchestrates selective disclosure, `sd_hash` computation, Key Binding JWT
/// construction, and final presentation assembly as specified in
/// [OpenID4VP Appendix B.3.6].
///
/// Use [`SdJwtPresentationBuilder`] (via [`SdJwtPresentation::builder`]) for
/// ergonomic construction.
///
/// [OpenID4VP Appendix B.3.6]: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.3.6
pub struct SdJwtPresentation {
    /// The raw SD-JWT VC credential string in issued form (`<jwt>~<disc>*~`).
    raw_credential: String,
    /// Claim paths requested by the Verifier (from the matched DCQL query).
    requested_claims: Vec<ClaimPathPointer>,
    /// Verifier's `client_id`, used as the `aud` claim in the KB-JWT.
    client_id: String,
    /// Transaction nonce from the Authorization Request.
    nonce: String,
    /// Issued-at timestamp for the KB-JWT.
    iat: i64,
    /// Optional transaction data hashes (OpenID4VP §8.4).
    transaction_data_hashes: Option<Vec<String>>,
    /// Optional hash algorithm identifier for transaction data hashes.
    transaction_data_hashes_alg: Option<String>,
    /// Signing function that produces the compact KB-JWT JWS.
    signer: Option<JwtSigner>,
}

impl SdJwtPresentation {
    /// Returns a builder for constructing an `SdJwtPresentation`.
    pub fn builder(
        raw_credential: impl Into<String>,
        client_id: impl Into<String>,
        nonce: impl Into<String>,
    ) -> SdJwtPresentationBuilder {
        SdJwtPresentationBuilder {
            raw_credential: raw_credential.into(),
            client_id: client_id.into(),
            nonce: nonce.into(),
            iat: time::UtcDateTime::now().unix_timestamp(),
            requested_claims: vec![],
            transaction_data_hashes: None,
            transaction_data_hashes_alg: None,
            signer: None,
        }
    }
}

impl PresentationFactory for SdJwtPresentation {
    fn create_presentation(self) -> Result<Presentation, ProofError> {
        let Self {
            raw_credential,
            requested_claims,
            client_id,
            nonce,
            iat,
            transaction_data_hashes,
            transaction_data_hashes_alg,
            signer,
        } = self;

        if !raw_credential.ends_with('~') {
            return Err(ProofError::InvalidInput(
                "SD-JWT VC credential must be in issued form and end with '~'".into(),
            ));
        }

        // Parse the raw credential.
        let sd_jwt = SdJwt::parse(&raw_credential)?;

        if transaction_data_hashes.as_ref().is_some_and(Vec::is_empty) {
            return Err(ProofError::InvalidInput(
                "transaction_data_hashes must be non-empty when present".into(),
            ));
        }

        if transaction_data_hashes.is_some() && signer.is_none() {
            return Err(ProofError::MissingRequiredField(
                "signer is required when transaction data is present".into(),
            ));
        }

        if signer.is_some() && sd_jwt.jwt().claims().cnf.is_none() {
            return Err(ProofError::MissingRequiredField(
                "cnf claim is required for SD-JWT holder binding".into(),
            ));
        }

        // Determine the hash algorithm from `_sd_alg`.
        let hash_alg = disclosure_hash_algorithm(sd_jwt.jwt().claims().sd_alg.as_deref())?;

        // Select disclosures for the requested claims.
        let selected = select_disclosures(&sd_jwt, &requested_claims)?;

        // Extract the issuer JWT raw string (the first part before '~').
        let issuer_jwt = sd_jwt.jwt().raw();

        // Build the presentation string without the KB-JWT.
        let presentation_without_kb = build_presentation_without_kb(issuer_jwt, &selected);

        // If no signer is provided, return without holder binding.
        let Some(signer) = signer else {
            return Ok(Presentation::String(presentation_without_kb));
        };

        // Compute sd_hash over the presentation-without-KB string.
        let sd_hash = compute_sd_hash(&presentation_without_kb, hash_alg);

        // Build Key Binding JWT claims.
        let mut kb_claims = KeyBindingClaims::new_with_iat(iat, client_id, nonce, sd_hash);

        if let Some(hashes) = transaction_data_hashes {
            kb_claims = kb_claims.with_transaction_data(hashes, transaction_data_hashes_alg);
        }

        // Sign the KB-JWT.
        let kb_jwt = signer(&kb_claims)?;
        KeyBindingJwt::decode_unverified(&kb_jwt).map_err(|err| {
            ProofError::InvalidInput(
                format!("signer returned invalid Key Binding JWT: {err}").into(),
            )
        })?;

        // Assemble the final presentation: <issuer-jwt>~<disc>*~<kb-jwt>
        let final_presentation = format!("{presentation_without_kb}{kb_jwt}");
        Ok(Presentation::String(final_presentation))
    }
}

impl std::fmt::Debug for SdJwtPresentation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SdJwtPresentation")
            .field("raw_credential", &"<redacted>")
            .field("requested_claims", &self.requested_claims)
            .field("client_id", &self.client_id)
            .field("nonce", &"<redacted>")
            .field("iat", &self.iat)
            .finish()
    }
}

/// Builder for [`SdJwtPresentation`].
pub struct SdJwtPresentationBuilder {
    raw_credential: String,
    client_id: String,
    nonce: String,
    iat: i64,
    requested_claims: Vec<ClaimPathPointer>,
    transaction_data_hashes: Option<Vec<String>>,
    transaction_data_hashes_alg: Option<String>,
    signer: Option<JwtSigner>,
}

impl SdJwtPresentationBuilder {
    /// Sets the claim paths requested by the Verifier.
    pub fn requested_claims(mut self, claims: impl IntoIterator<Item = ClaimPathPointer>) -> Self {
        self.requested_claims = claims.into_iter().collect();
        self
    }

    /// Sets the JWT signing function for the Key Binding JWT.
    ///
    /// The function receives serialized [`KeyBindingClaims`] and must return
    /// a compact JWS string with JOSE header `typ: "kb+jwt"`.
    ///
    /// When no signer is provided, the presentation is created without holder
    /// binding (per [OpenID4VP §5.3]).
    ///
    /// [OpenID4VP §5.3]: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.3
    pub fn signer<F>(mut self, f: F) -> Self
    where
        F: Fn(&KeyBindingClaims) -> Result<String, ProofError> + Send + Sync + 'static,
    {
        self.signer = Some(Box::new(f));
        self
    }

    /// Sets optional transaction data hashes per OpenID4VP §8.4.
    pub fn transaction_data(
        mut self,
        hashes: impl IntoIterator<Item = impl Into<String>>,
        alg: Option<impl Into<String>>,
    ) -> Self {
        self.transaction_data_hashes = Some(hashes.into_iter().map(Into::into).collect());
        self.transaction_data_hashes_alg = alg.map(Into::into);
        self
    }

    /// Overrides the Key Binding JWT issued-at timestamp.
    ///
    /// By default the builder uses the current timestamp. This is mainly useful
    /// for deterministic tests or externally controlled clocks.
    pub fn iat(mut self, iat: i64) -> Self {
        self.iat = iat;
        self
    }

    /// Builds the [`SdJwtPresentation`].
    pub fn build(self) -> SdJwtPresentation {
        SdJwtPresentation {
            raw_credential: self.raw_credential,
            requested_claims: self.requested_claims,
            client_id: self.client_id,
            nonce: self.nonce,
            iat: self.iat,
            transaction_data_hashes: self.transaction_data_hashes,
            transaction_data_hashes_alg: self.transaction_data_hashes_alg,
            signer: self.signer,
        }
    }
}

/// Resolves which disclosures are required to reveal a set of requested claims.
///
/// Given a parsed [`SdJwt`] and the requested [`ClaimPathPointer`]s from a DCQL
/// query, this function walks the SD-JWT payload tree and collects exactly the
/// disclosures whose digests must be included in the presentation.
///
/// # Returns
///
/// A deduplicated set of raw disclosure strings (base64url-encoded) that the
/// presentation must include.
fn select_disclosures<'a>(
    sd_jwt: &SdJwt<'a>,
    requested_claims: &[ClaimPathPointer],
) -> Result<Vec<&'a str>, ProofError> {
    let sd_alg = disclosure_hash_algorithm(sd_jwt.jwt().claims().sd_alg.as_deref())?;

    let mut digest_index = HashMap::with_capacity(sd_jwt.disclosures().len());
    for (index, disclosure) in sd_jwt.disclosures().iter().enumerate() {
        let digest = disclosure_digest(disclosure.raw(), sd_alg);
        if digest_index.insert(digest, (index, disclosure)).is_some() {
            return Err(ProofError::InvalidInput(
                "duplicate disclosure digest".into(),
            ));
        }
    }

    let issuer_payload = serde_json::to_value(sd_jwt.jwt().claims())?;
    let mut selected_indexes: HashSet<usize> = HashSet::new();

    for path in requested_claims {
        collect_disclosures_for_path(
            &issuer_payload,
            path.elements(),
            &digest_index,
            &mut selected_indexes,
        );
    }

    // Return in issued-credential order for reproducible presentations
    Ok(sd_jwt
        .disclosures()
        .iter()
        .enumerate()
        .filter(|(index, _)| selected_indexes.contains(index))
        .map(|(_, disclosure)| disclosure.raw())
        .collect())
}

/// Recursively walks the payload tree along `remaining_path`, collecting any
/// disclosures whose digests appear in `_sd` arrays or `{"...": digest}` array
/// placeholders along the way.
fn collect_disclosures_for_path<'a>(
    current: &Value,
    remaining_path: &[ClaimPathElement],
    digest_index: &HashMap<String, (usize, &Disclosure<'a>)>,
    selected: &mut HashSet<usize>,
) {
    if remaining_path.is_empty() {
        return;
    }

    let element = &remaining_path[0];
    let rest = &remaining_path[1..];

    match (current, element) {
        // Navigate into an object property, checking for selective disclosure.
        (Value::Object(obj), ClaimPathElement::String(key)) => {
            // Check if this claim is selectively disclosed via _sd.
            if let Some(sd_digests) = obj.get(SD_CLAIM).and_then(|v| v.as_array()) {
                for digest_value in sd_digests {
                    let Some(digest_str) = digest_value.as_str() else {
                        continue;
                    };
                    let Some((index, disc)) = digest_index.get(digest_str) else {
                        continue;
                    };
                    if disc.claim_name.as_deref() == Some(key) {
                        selected.insert(*index);
                        // Continue into the disclosed value for deeper paths.
                        if !rest.is_empty() {
                            collect_disclosures_for_path(
                                &disc.claim_value,
                                rest,
                                digest_index,
                                selected,
                            );
                        }
                        return;
                    }
                }
            }
            // Not selectively disclosed — check regular claims.
            if let Some(value) = obj.get(key) {
                collect_disclosures_for_path(value, rest, digest_index, selected);
            }
        }

        // Navigate into an array by index.
        (Value::Array(arr), ClaimPathElement::Index(idx)) => {
            if let Some(element_value) = arr.get(*idx as usize) {
                try_collect_array_element(element_value, rest, digest_index, selected);
            }
        }

        // Select all array elements (null = wildcard).
        (Value::Array(arr), ClaimPathElement::Null) => {
            for element_value in arr {
                try_collect_array_element(element_value, rest, digest_index, selected);
            }
        }
        _ => {}
    }
}

/// Handles a single array element, checking for `{"...": digest}` SD-JWT array
/// element disclosures.
fn try_collect_array_element<'a>(
    element_value: &Value,
    rest: &[ClaimPathElement],
    digest_index: &HashMap<String, (usize, &Disclosure<'a>)>,
    selected: &mut HashSet<usize>,
) {
    // Check for SD-JWT array element disclosure placeholder: {"...": digest}
    if let Some(obj) = element_value.as_object()
        && obj.len() == 1
        && let Some(Value::String(digest_str)) = obj.get(ARRAY_DIGEST_CLAIM)
        && let Some((index, disc)) = digest_index.get(digest_str)
    {
        selected.insert(*index);
        if !rest.is_empty() {
            collect_disclosures_for_path(&disc.claim_value, rest, digest_index, selected);
        }
        return;
    }
    // Regular array element.
    collect_disclosures_for_path(element_value, rest, digest_index, selected);
}

/// Computes the `sd_hash` over an SD-JWT presentation string.
///
/// The input is the issuer-signed JWT concatenated with selected disclosures
/// and a trailing `~` (i.e., `<issuer-jwt>~<disc1>~...~<discN>~`).
///
/// Returns the base64url-encoded hash, using the hash algorithm from the
/// credential's `_sd_alg` claim (defaulting to SHA-256).
pub fn compute_sd_hash(presentation_without_kb: &str, hash_alg: HashAlg) -> String {
    URL_SAFE_NO_PAD.encode(hash_alg.hash(presentation_without_kb.as_bytes()).as_ref())
}

/// Builds the SD-JWT presentation string without the Key Binding JWT.
///
/// Format: `<issuer-jwt>~<disc1>~...~<discN>~`
fn build_presentation_without_kb(issuer_jwt: &str, selected_disclosures: &[&str]) -> String {
    let mut presentation = String::with_capacity(
        issuer_jwt.len()
            + selected_disclosures
                .iter()
                .map(|d| d.len() + 1)
                .sum::<usize>()
            + 1,
    );
    presentation.push_str(issuer_jwt);
    for disc in selected_disclosures {
        presentation.push('~');
        presentation.push_str(disc);
    }
    presentation.push('~');
    presentation
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use cloud_wallet_crypto::digest::HashAlg;
    use serde_json::json;

    /// Encode a JSON value to unpadded base64url.
    fn b64(value: Value) -> String {
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value).unwrap())
    }

    /// Create a compact JWT from header and claims (with a dummy signature).
    fn compact_jwt(header: Value, claims: Value) -> String {
        format!("{}.{}.sig", b64(header), b64(claims))
    }

    /// Create a disclosure from a JSON array value.
    fn make_disclosure(value: Value) -> String {
        b64(value)
    }

    /// Calculate the disclosure digest using SHA-256.
    fn test_disclosure_digest(disc: &str) -> String {
        URL_SAFE_NO_PAD.encode(HashAlg::Sha256.hash(disc.as_bytes()).as_ref())
    }

    /// Build a minimal issued SD-JWT with the given claims and disclosures.
    fn build_test_sd_jwt(claims: Value, disclosures: &[String]) -> String {
        let jwt = compact_jwt(json!({ "alg": "ES256", "typ": "dc+sd-jwt" }), claims);
        let mut raw = jwt;
        for disc in disclosures {
            raw.push('~');
            raw.push_str(disc);
        }
        raw.push('~');
        raw
    }

    fn holder_binding_cnf() -> Value {
        json!({ "kid": "holder-key-1" })
    }

    /// A test signer that wraps the claims JSON in a fake compact JWS.
    fn test_signer(claims: &KeyBindingClaims) -> Result<String, ProofError> {
        let header = b64(json!({"alg": "ES256", "typ": "kb+jwt"}));
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
        Ok(format!("{header}.{payload}.test-sig"))
    }

    #[test]
    fn selects_no_disclosures_when_no_claims_requested() {
        let disc = make_disclosure(json!(["salt-1", "given_name", "Ada"]));
        let digest = test_disclosure_digest(&disc);
        let raw = build_test_sd_jwt(
            json!({
                "iss": "https://issuer.example.com",
                "vct": "https://credentials.example.com/identity",
                "_sd": [digest],
                "_sd_alg": "sha-256"
            }),
            &[disc],
        );

        let sd_jwt = SdJwt::parse(&raw).unwrap();
        let selected = select_disclosures(&sd_jwt, &[]).unwrap();

        assert!(selected.is_empty());
    }

    #[test]
    fn selects_matching_disclosure_for_requested_claim() {
        let disc_name = make_disclosure(json!(["salt-1", "given_name", "Ada"]));
        let disc_email = make_disclosure(json!(["salt-2", "email", "ada@example.com"]));
        let digest_name = test_disclosure_digest(&disc_name);
        let digest_email = test_disclosure_digest(&disc_email);

        let raw = build_test_sd_jwt(
            json!({
                "iss": "https://issuer.example.com",
                "vct": "https://credentials.example.com/identity",
                "_sd": [digest_name, digest_email],
                "_sd_alg": "sha-256"
            }),
            &[disc_name.clone(), disc_email],
        );

        let sd_jwt = SdJwt::parse(&raw).unwrap();
        let requested = vec![ClaimPathPointer::from_strings(["given_name"])];
        let selected = select_disclosures(&sd_jwt, &requested).unwrap();

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0], disc_name);
    }

    #[test]
    fn selects_multiple_disclosures_for_multiple_claims() {
        let disc_name = make_disclosure(json!(["salt-1", "given_name", "Ada"]));
        let disc_email = make_disclosure(json!(["salt-2", "email", "ada@example.com"]));
        let digest_name = test_disclosure_digest(&disc_name);
        let digest_email = test_disclosure_digest(&disc_email);

        let raw = build_test_sd_jwt(
            json!({
                "iss": "https://issuer.example.com",
                "vct": "https://credentials.example.com/identity",
                "_sd": [digest_name, digest_email],
                "_sd_alg": "sha-256"
            }),
            &[disc_name.clone(), disc_email.clone()],
        );

        let sd_jwt = SdJwt::parse(&raw).unwrap();
        let requested = vec![
            ClaimPathPointer::from_strings(["given_name"]),
            ClaimPathPointer::from_strings(["email"]),
        ];
        let selected = select_disclosures(&sd_jwt, &requested).unwrap();

        assert_eq!(selected.len(), 2);
        assert!(selected.contains(&disc_name.as_str()));
        assert!(selected.contains(&disc_email.as_str()));
    }

    #[test]
    fn does_not_select_disclosure_for_non_sd_claim() {
        // "given_name" is a regular (non-selectively-disclosed) claim.
        let raw = build_test_sd_jwt(
            json!({
                "iss": "https://issuer.example.com",
                "vct": "https://credentials.example.com/identity",
                "given_name": "Ada"
            }),
            &[],
        );

        let sd_jwt = SdJwt::parse(&raw).unwrap();
        let requested = vec![ClaimPathPointer::from_strings(["given_name"])];
        let selected = select_disclosures(&sd_jwt, &requested).unwrap();

        assert!(selected.is_empty());
    }

    #[test]
    fn selects_nested_disclosures_for_deep_path() {
        // address is selectively disclosed, and within it, street is also SD.
        let disc_street = make_disclosure(json!(["salt-2", "street", "Main St"]));
        let digest_street = test_disclosure_digest(&disc_street);

        let disc_address = make_disclosure(json!([
            "salt-1",
            "address",
            { "_sd": [digest_street], "_sd_alg": "sha-256" }
        ]));
        let digest_address = test_disclosure_digest(&disc_address);

        let raw = build_test_sd_jwt(
            json!({
                "iss": "https://issuer.example.com",
                "vct": "https://credentials.example.com/identity",
                "_sd": [digest_address],
                "_sd_alg": "sha-256"
            }),
            &[disc_address.clone(), disc_street.clone()],
        );

        let sd_jwt = SdJwt::parse(&raw).unwrap();
        let requested = vec![ClaimPathPointer::from_strings(["address", "street"])];
        let selected = select_disclosures(&sd_jwt, &requested).unwrap();

        // Both the parent "address" and child "street" disclosures must be included.
        assert_eq!(selected.len(), 2);
        assert!(selected.contains(&disc_address.as_str()));
        assert!(selected.contains(&disc_street.as_str()));
    }

    #[test]
    fn selects_array_element_disclosure_by_index_path() {
        let disc_de = make_disclosure(json!(["salt-1", "DE"]));
        let disc_fr = make_disclosure(json!(["salt-2", "FR"]));
        let digest_de = test_disclosure_digest(&disc_de);
        let digest_fr = test_disclosure_digest(&disc_fr);

        let raw = build_test_sd_jwt(
            json!({
                "iss": "https://issuer.example.com",
                "vct": "https://credentials.example.com/identity",
                "nationalities": [
                    { "...": digest_de },
                    { "...": digest_fr }
                ],
                "_sd_alg": "sha-256"
            }),
            &[disc_de, disc_fr.clone()],
        );

        let sd_jwt = SdJwt::parse(&raw).unwrap();
        let requested = vec![ClaimPathPointer::new(vec![
            ClaimPathElement::from("nationalities"),
            ClaimPathElement::from(1u64),
        ])];
        let selected = select_disclosures(&sd_jwt, &requested).unwrap();

        assert_eq!(selected, vec![disc_fr.as_str()]);
    }

    #[test]
    fn selects_array_element_disclosures_by_null_wildcard_path() {
        let disc_de = make_disclosure(json!(["salt-1", "DE"]));
        let disc_fr = make_disclosure(json!(["salt-2", "FR"]));
        let digest_de = test_disclosure_digest(&disc_de);
        let digest_fr = test_disclosure_digest(&disc_fr);

        let raw = build_test_sd_jwt(
            json!({
                "iss": "https://issuer.example.com",
                "vct": "https://credentials.example.com/identity",
                "nationalities": [
                    { "...": digest_de },
                    { "...": digest_fr }
                ],
                "_sd_alg": "sha-256"
            }),
            &[disc_de.clone(), disc_fr.clone()],
        );

        let sd_jwt = SdJwt::parse(&raw).unwrap();
        let requested = vec![ClaimPathPointer::new(vec![
            ClaimPathElement::from("nationalities"),
            ClaimPathElement::Null,
        ])];
        let selected = select_disclosures(&sd_jwt, &requested).unwrap();

        assert_eq!(selected, vec![disc_de.as_str(), disc_fr.as_str()]);
    }

    #[test]
    fn selects_nested_claims_through_array_object_wildcard_path() {
        let disc_degree_1_type = make_disclosure(json!(["salt-1-type", "type", "Bachelor"]));
        let disc_degree_2_type = make_disclosure(json!(["salt-2-type", "type", "Master"]));
        let digest_degree_1_type = test_disclosure_digest(&disc_degree_1_type);
        let digest_degree_2_type = test_disclosure_digest(&disc_degree_2_type);

        let disc_degree_1 = make_disclosure(json!([
            "salt-1-degree",
            { "_sd": [digest_degree_1_type], "_sd_alg": "sha-256" }
        ]));
        let disc_degree_2 = make_disclosure(json!([
            "salt-2-degree",
            { "_sd": [digest_degree_2_type], "_sd_alg": "sha-256" }
        ]));
        let digest_degree_1 = test_disclosure_digest(&disc_degree_1);
        let digest_degree_2 = test_disclosure_digest(&disc_degree_2);

        let raw = build_test_sd_jwt(
            json!({
                "iss": "https://issuer.example.com",
                "vct": "https://credentials.example.com/identity",
                "degrees": [
                    { "...": digest_degree_1 },
                    { "...": digest_degree_2 }
                ],
                "_sd_alg": "sha-256"
            }),
            &[
                disc_degree_1.clone(),
                disc_degree_1_type.clone(),
                disc_degree_2.clone(),
                disc_degree_2_type.clone(),
            ],
        );

        let sd_jwt = SdJwt::parse(&raw).unwrap();
        let requested = vec![ClaimPathPointer::new(vec![
            ClaimPathElement::from("degrees"),
            ClaimPathElement::Null,
            ClaimPathElement::from("type"),
        ])];
        let selected = select_disclosures(&sd_jwt, &requested).unwrap();

        assert_eq!(
            selected,
            vec![
                disc_degree_1.as_str(),
                disc_degree_1_type.as_str(),
                disc_degree_2.as_str(),
                disc_degree_2_type.as_str(),
            ]
        );
    }

    #[test]
    fn deduplicates_disclosures_requested_multiple_times() {
        let disc = make_disclosure(json!(["salt-1", "given_name", "Ada"]));
        let digest = test_disclosure_digest(&disc);

        let raw = build_test_sd_jwt(
            json!({
                "iss": "https://issuer.example.com",
                "vct": "https://credentials.example.com/identity",
                "_sd": [digest],
                "_sd_alg": "sha-256"
            }),
            std::slice::from_ref(&disc),
        );

        let sd_jwt = SdJwt::parse(&raw).unwrap();
        // Request the same claim twice.
        let requested = vec![
            ClaimPathPointer::from_strings(["given_name"]),
            ClaimPathPointer::from_strings(["given_name"]),
        ];
        let selected = select_disclosures(&sd_jwt, &requested).unwrap();

        assert_eq!(selected.len(), 1);
    }

    #[test]
    fn computes_sd_hash_correctly() {
        let presentation = "header.payload.sig~disc1~disc2~";
        let hash = compute_sd_hash(presentation, HashAlg::Sha256);
        let expected =
            URL_SAFE_NO_PAD.encode(HashAlg::Sha256.hash(presentation.as_bytes()).as_ref());

        // Verify it's non-empty base64url (no padding).
        assert!(!hash.is_empty());
        assert!(!hash.contains('='));
        assert!(!hash.contains('+'));
        assert!(!hash.contains('/'));
        assert_eq!(hash, expected);

        // Verify determinism.
        let hash2 = compute_sd_hash(presentation, HashAlg::Sha256);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn sd_hash_differs_for_different_presentations() {
        let hash1 = compute_sd_hash("a.b.c~d1~", HashAlg::Sha256);
        let hash2 = compute_sd_hash("a.b.c~d1~d2~", HashAlg::Sha256);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn builds_presentation_without_kb() {
        let result = build_presentation_without_kb("header.payload.sig", &["disc1", "disc2"]);
        assert_eq!(result, "header.payload.sig~disc1~disc2~");
    }

    #[test]
    fn builds_presentation_without_disclosures() {
        let result = build_presentation_without_kb("header.payload.sig", &[]);
        assert_eq!(result, "header.payload.sig~");
    }

    #[test]
    fn creates_presentation_without_holder_binding() {
        let disc = make_disclosure(json!(["salt-1", "given_name", "Ada"]));
        let digest = test_disclosure_digest(&disc);
        let raw = build_test_sd_jwt(
            json!({
                "iss": "https://issuer.example.com",
                "vct": "https://credentials.example.com/identity",
                "_sd": [digest],
                "_sd_alg": "sha-256"
            }),
            &[disc],
        );

        let presentation =
            SdJwtPresentation::builder(raw, "https://verifier.example.com", "test-nonce")
                .requested_claims(vec![ClaimPathPointer::from_strings(["given_name"])])
                .build()
                .create_presentation()
                .unwrap();

        let Presentation::String(ref s) = presentation else {
            panic!("expected string presentation");
        };

        // No KB-JWT -> ends with '~'.
        assert!(s.ends_with('~'));
        // Contains the issuer JWT.
        assert!(s.starts_with("eyJ"));
        // Contains exactly one disclosure.
        let parts: Vec<&str> = s.split('~').collect();
        // Format: <jwt> ~ <disc> ~ <empty trailing>
        assert_eq!(parts.len(), 3, "expected jwt~disc~ format, got {parts:?}");
    }

    #[test]
    fn creates_presentation_with_key_binding() {
        let disc = make_disclosure(json!(["salt-1", "given_name", "Ada"]));
        let digest = test_disclosure_digest(&disc);
        let raw = build_test_sd_jwt(
            json!({
                "iss": "https://issuer.example.com",
                "vct": "https://credentials.example.com/identity",
                "cnf": holder_binding_cnf(),
                "_sd": [digest],
                "_sd_alg": "sha-256"
            }),
            &[disc],
        );

        let presentation =
            SdJwtPresentation::builder(raw, "https://verifier.example.com", "test-nonce")
                .requested_claims(vec![ClaimPathPointer::from_strings(["given_name"])])
                .signer(test_signer)
                .build()
                .create_presentation()
                .unwrap();
        let Presentation::String(ref s) = presentation else {
            panic!("expected string presentation");
        };

        // With KB-JWT -> does NOT end with '~'.
        assert!(!s.ends_with('~'));
        // Format: <jwt>~<disc>~<kb-jwt>
        let parts: Vec<&str> = s.split('~').collect();
        assert_eq!(parts.len(), 3, "expected jwt~disc~kb-jwt format");

        // Verify the KB-JWT is a valid compact JWS (3 dot-separated parts).
        let kb_jwt = parts[2];
        assert_eq!(kb_jwt.split('.').count(), 3, "KB-JWT must be a compact JWS");
    }

    #[test]
    fn kb_jwt_contains_correct_claims() {
        let disc = make_disclosure(json!(["salt-1", "given_name", "Ada"]));
        let digest = test_disclosure_digest(&disc);
        let raw = build_test_sd_jwt(
            json!({
                "iss": "https://issuer.example.com",
                "vct": "https://credentials.example.com/identity",
                "cnf": holder_binding_cnf(),
                "_sd": [digest],
                "_sd_alg": "sha-256"
            }),
            &[disc],
        );

        let client_id = "https://verifier.example.com";
        let nonce = "test-nonce-123";
        let iat = 1683000000i64;

        // Capture the claims passed to the signer.
        let captured_claims = std::sync::Arc::new(std::sync::Mutex::new(None));
        let captured = captured_claims.clone();

        SdJwtPresentation::builder(raw, client_id, nonce)
            .iat(iat)
            .requested_claims(vec![ClaimPathPointer::from_strings(["given_name"])])
            .signer(move |claims: &KeyBindingClaims| {
                *captured.lock().unwrap() = Some(claims.clone());
                test_signer(claims)
            })
            .build()
            .create_presentation()
            .unwrap();

        let claims = captured_claims.lock().unwrap().clone().unwrap();
        assert_eq!(claims.iat, iat);
        assert_eq!(claims.aud, client_id);
        assert_eq!(claims.nonce, nonce);
        assert!(!claims.sd_hash.is_empty(), "sd_hash must be set");
        assert!(claims.transaction_data_hashes.is_none());
        assert!(claims.transaction_data_hashes_alg.is_none());
    }

    #[test]
    fn kb_jwt_includes_transaction_data_hashes() {
        let disc = make_disclosure(json!(["salt-1", "given_name", "Ada"]));
        let digest = test_disclosure_digest(&disc);
        let raw = build_test_sd_jwt(
            json!({
                "iss": "https://issuer.example.com",
                "vct": "https://credentials.example.com/identity",
                "cnf": holder_binding_cnf(),
                "_sd": [digest],
                "_sd_alg": "sha-256"
            }),
            &[disc],
        );

        let captured_claims = std::sync::Arc::new(std::sync::Mutex::new(None));
        let captured = captured_claims.clone();

        SdJwtPresentation::builder(raw, "https://verifier.example.com", "nonce")
            .requested_claims(vec![ClaimPathPointer::from_strings(["given_name"])])
            .transaction_data(vec!["hash1", "hash2"], Some("sha-256"))
            .signer(move |claims: &KeyBindingClaims| {
                *captured.lock().unwrap() = Some(claims.clone());
                test_signer(claims)
            })
            .build()
            .create_presentation()
            .unwrap();

        let claims = captured_claims.lock().unwrap().clone().unwrap();
        assert_eq!(
            claims.transaction_data_hashes,
            Some(vec!["hash1".to_string(), "hash2".to_string()])
        );
        assert_eq!(
            claims.transaction_data_hashes_alg,
            Some("sha-256".to_string())
        );
    }

    #[test]
    fn rejects_key_binding_when_credential_has_no_cnf() {
        let disc = make_disclosure(json!(["salt-1", "given_name", "Ada"]));
        let digest = test_disclosure_digest(&disc);
        let raw = build_test_sd_jwt(
            json!({
                "iss": "https://issuer.example.com",
                "vct": "https://credentials.example.com/identity",
                "_sd": [digest],
                "_sd_alg": "sha-256"
            }),
            &[disc],
        );

        let err = SdJwtPresentation::builder(raw, "https://verifier.example.com", "nonce")
            .requested_claims(vec![ClaimPathPointer::from_strings(["given_name"])])
            .signer(test_signer)
            .build()
            .create_presentation()
            .unwrap_err();
        assert!(
            matches!(err, ProofError::MissingRequiredField(ref field) if field.contains("cnf")),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_invalid_key_binding_jwt_from_signer() {
        let disc = make_disclosure(json!(["salt-1", "given_name", "Ada"]));
        let digest = test_disclosure_digest(&disc);
        let raw = build_test_sd_jwt(
            json!({
                "iss": "https://issuer.example.com",
                "vct": "https://credentials.example.com/identity",
                "cnf": holder_binding_cnf(),
                "_sd": [digest],
                "_sd_alg": "sha-256"
            }),
            &[disc],
        );

        let err = SdJwtPresentation::builder(raw, "https://verifier.example.com", "nonce")
            .requested_claims(vec![ClaimPathPointer::from_strings(["given_name"])])
            .signer(|_| Ok("not~a~compact~jws".to_string()))
            .build()
            .create_presentation()
            .unwrap_err();

        assert!(
            matches!(err, ProofError::InvalidInput(ref input) if input.contains("Key Binding JWT")),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_sd_jwt_presentation_input_for_presentation_builder() {
        let disc = make_disclosure(json!(["salt-1", "given_name", "Ada"]));
        let digest = test_disclosure_digest(&disc);
        let mut raw = build_test_sd_jwt(
            json!({
                "iss": "https://issuer.example.com",
                "vct": "https://credentials.example.com/identity",
                "cnf": holder_binding_cnf(),
                "_sd": [digest],
                "_sd_alg": "sha-256"
            }),
            &[disc],
        );
        raw.push_str("header.payload.signature");

        let err = SdJwtPresentation::builder(raw, "https://verifier.example.com", "nonce")
            .requested_claims(vec![ClaimPathPointer::from_strings(["given_name"])])
            .signer(test_signer)
            .build()
            .create_presentation()
            .unwrap_err();

        assert!(
            matches!(err, ProofError::InvalidInput(ref input) if input.contains("issued form")),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_transaction_data_without_signer() {
        let disc = make_disclosure(json!(["salt-1", "given_name", "Ada"]));
        let digest = test_disclosure_digest(&disc);
        let raw = build_test_sd_jwt(
            json!({
                "iss": "https://issuer.example.com",
                "vct": "https://credentials.example.com/identity",
                "cnf": holder_binding_cnf(),
                "_sd": [digest],
                "_sd_alg": "sha-256"
            }),
            &[disc],
        );

        let err = SdJwtPresentation::builder(raw, "https://verifier.example.com", "nonce")
            .requested_claims(vec![ClaimPathPointer::from_strings(["given_name"])])
            .transaction_data(vec!["hash1"], Some("sha-256"))
            .build()
            .create_presentation()
            .unwrap_err();
        assert!(
            matches!(err, ProofError::MissingRequiredField(ref field) if field.contains("signer")),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_empty_transaction_data_hashes() {
        let disc = make_disclosure(json!(["salt-1", "given_name", "Ada"]));
        let digest = test_disclosure_digest(&disc);
        let raw = build_test_sd_jwt(
            json!({
                "iss": "https://issuer.example.com",
                "vct": "https://credentials.example.com/identity",
                "cnf": holder_binding_cnf(),
                "_sd": [digest],
                "_sd_alg": "sha-256"
            }),
            &[disc],
        );

        let err = SdJwtPresentation::builder(raw, "https://verifier.example.com", "nonce")
            .requested_claims(vec![ClaimPathPointer::from_strings(["given_name"])])
            .transaction_data(Vec::<&str>::new(), Some("sha-256"))
            .signer(test_signer)
            .build()
            .create_presentation()
            .unwrap_err();

        assert!(
            matches!(err, ProofError::InvalidInput(ref input) if input.contains("non-empty")),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn presentation_without_requested_claims_includes_no_disclosures() {
        let disc = make_disclosure(json!(["salt-1", "given_name", "Ada"]));
        let digest = test_disclosure_digest(&disc);
        let raw = build_test_sd_jwt(
            json!({
                "iss": "https://issuer.example.com",
                "vct": "https://credentials.example.com/identity",
                "cnf": holder_binding_cnf(),
                "_sd": [digest],
                "_sd_alg": "sha-256"
            }),
            &[disc],
        );

        let issuer_jwt = raw
            .split('~')
            .next()
            .expect("test SD-JWT should contain issuer JWT")
            .to_string();

        let pres = SdJwtPresentation::builder(raw, "https://verifier.example.com", "nonce")
            // No requested_claims -> no disclosures should be included.
            .signer(test_signer)
            .build();

        let presentation = pres.create_presentation().unwrap();
        let Presentation::String(ref s) = presentation else {
            panic!("expected string presentation");
        };

        // The presentation should contain: <issuer-jwt>~<kb-jwt>
        assert!(s.starts_with(&issuer_jwt));
        let parts: Vec<&str> = s.split('~').collect();
        assert_eq!(
            parts.len(),
            2,
            "expected jwt~kb-jwt format with no disclosures, got {parts:?}"
        );
        assert_eq!(parts[0], issuer_jwt);
        assert_eq!(
            parts[1].split('.').count(),
            3,
            "KB-JWT must be a compact JWS"
        );
    }

    #[test]
    fn kb_claims_serializes_without_optional_fields() {
        let claims = KeyBindingClaims::new_with_iat(
            1683000000,
            "https://verifier.example.com",
            "nonce",
            "sd_hash_value",
        );

        let json = serde_json::to_value(&claims).unwrap();
        assert_eq!(json["iat"], 1683000000);
        assert_eq!(json["aud"], "https://verifier.example.com");
        assert_eq!(json["nonce"], "nonce");
        assert_eq!(json["sd_hash"], "sd_hash_value");
        assert!(json.get("transaction_data_hashes").is_none());
        assert!(json.get("transaction_data_hashes_alg").is_none());
    }

    #[test]
    fn kb_claims_serializes_with_transaction_data() {
        let claims = KeyBindingClaims::new_with_iat(1683000000, "aud", "nonce", "hash")
            .with_transaction_data(vec!["h1", "h2"], Some("sha-256"));

        let json = serde_json::to_value(&claims).unwrap();
        assert_eq!(json["transaction_data_hashes"], json!(["h1", "h2"]));
        assert_eq!(json["transaction_data_hashes_alg"], "sha-256");
    }

    #[test]
    fn kb_claims_round_trips_through_serde() {
        let original = KeyBindingClaims::new_with_iat(1683000000, "aud", "nonce", "hash")
            .with_transaction_data(vec!["h1"], None::<String>);

        let json_str = serde_json::to_string(&original).unwrap();
        let decoded: KeyBindingClaims = serde_json::from_str(&json_str).unwrap();
        assert_eq!(decoded, original);
    }
}
