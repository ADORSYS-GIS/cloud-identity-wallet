use std::collections::{HashMap, HashSet, hash_map::Entry};
use std::str::FromStr;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use cloud_wallet_crypto::digest::HashAlg;
use serde_json::{Map, Value};

use crate::formats::sd_jwt::{Disclosure, Error, IanaHashAlgorithm, ProcessingError, SdJwt};

const SD_CLAIM: &str = "_sd";
const SD_ALG_CLAIM: &str = "_sd_alg";
const ARRAY_DIGEST_CLAIM: &str = "...";
const MAX_JSON_NESTING_DEPTH: usize = 64;

/// Determines the hash algorithm to use for disclosure hashing.
///
/// Defaults to SHA-256 when `_sd_alg` is absent, per RFC 9901.
pub fn disclosure_hash_algorithm(sd_alg: Option<&str>) -> Result<HashAlg, Error> {
    sd_alg
        .map(IanaHashAlgorithm::from_str)
        .unwrap_or(Ok(IanaHashAlgorithm::Sha256))
        .map(Into::into)
}

/// Computes the base64url-encoded digest of a raw string using the specified hash algorithm.
pub fn disclosure_digest(raw_disclosure: &str, algorithm: HashAlg) -> String {
    URL_SAFE_NO_PAD.encode(algorithm.hash(raw_disclosure.as_bytes()).as_ref())
}

/// Processes the disclosures in the SD-JWT and returns the processed payload.
///
/// The processing is done according to [RFC 9901 Section 7].
///
/// [RFC 9901 Section 7]: https://www.rfc-editor.org/rfc/rfc9901.html#section-7
pub(super) fn process_disclosures(sd_jwt: &SdJwt<'_>) -> Result<Value, Error> {
    let algorithm = disclosure_hash_algorithm(sd_jwt.jwt().claims().sd_alg.as_deref())?;
    let mut disclosures = DigestIndex::new(sd_jwt.disclosures(), algorithm)?;

    let mut payload = serde_json::to_value(sd_jwt.jwt().claims())
        .map_err(|e| decode_error(ProcessingError::Json(e.to_string())))?;
    let mut state = ProcessingState::default();

    process_value(&mut payload, &mut disclosures, &mut state, 0, true)?;

    if let Some(digest) = disclosures.first_unreferenced_digest() {
        return Err(decode_error(ProcessingError::UnreferencedDisclosure(
            digest.to_owned(),
        )));
    }
    Ok(payload)
}

/// State used during the processing of the SD-JWT.
///
/// Used to track which digest references have been encountered.
#[derive(Default)]
struct ProcessingState {
    encountered_digests: HashSet<String>,
}

/// Index of disclosures by their digest.
struct DigestIndex<'a> {
    disclosures: HashMap<String, &'a Disclosure<'a>>,
}

impl<'a> DigestIndex<'a> {
    fn new(disclosures: &'a [Disclosure<'a>], algorithm: HashAlg) -> Result<Self, Error> {
        let mut index = HashMap::with_capacity(disclosures.len());

        for disclosure in disclosures {
            let digest = disclosure_digest(disclosure.raw(), algorithm);
            match index.entry(digest) {
                Entry::Vacant(entry) => {
                    entry.insert(disclosure);
                }
                Entry::Occupied(entry) => {
                    return Err(decode_error(ProcessingError::DuplicateDigest(
                        entry.key().to_owned(),
                    )));
                }
            }
        }
        Ok(Self { disclosures: index })
    }

    fn take(&mut self, digest: &str) -> Option<&'a Disclosure<'a>> {
        self.disclosures.remove(digest)
    }

    fn first_unreferenced_digest(&self) -> Option<&str> {
        self.disclosures.keys().next().map(String::as_str)
    }
}

/// Processes a JSON value according to the SD-JWT processing rules.
fn process_value(
    value: &mut Value,
    disclosures: &mut DigestIndex<'_>,
    state: &mut ProcessingState,
    depth: usize,
    is_root: bool,
) -> Result<(), Error> {
    if depth > MAX_JSON_NESTING_DEPTH {
        return Err(decode_error(ProcessingError::MaxDepthExceeded(
            MAX_JSON_NESTING_DEPTH,
        )));
    }

    match value {
        Value::Object(object) => process_object(object, disclosures, state, depth, is_root),
        Value::Array(array) => process_array(array, disclosures, state, depth),
        // Primitive values (string, number, boolean, null) are left unchanged
        _ => Ok(()),
    }
}

fn process_object(
    object: &mut Map<String, Value>,
    disclosures: &mut DigestIndex<'_>,
    state: &mut ProcessingState,
    depth: usize,
    is_root: bool,
) -> Result<(), Error> {
    let embedded_digests = object
        .remove(SD_CLAIM)
        .map(sd_digests)
        .transpose()?
        .unwrap_or_default();
    let mut insertions = vec![];
    let mut inserted_claim_names = object.keys().map(String::as_str).collect::<HashSet<_>>();

    for digest in embedded_digests {
        encounter_digest(&digest, state)?;

        let Some(disclosure) = disclosures.take(&digest) else {
            continue;
        };
        let Some(claim_name) = disclosure.claim_name.as_deref() else {
            return Err(decode_error(ProcessingError::ExpectedObjectDisclosure(
                digest,
            )));
        };
        if claim_name == SD_CLAIM || claim_name == ARRAY_DIGEST_CLAIM {
            return Err(decode_error(ProcessingError::ReservedClaimName(
                claim_name.to_owned(),
            )));
        }
        if !inserted_claim_names.insert(claim_name) {
            return Err(decode_error(ProcessingError::DuplicateClaimName(
                claim_name.to_owned(),
            )));
        }
        insertions.push((claim_name, &disclosure.claim_value));
    }

    for (claim_name, claim_value) in insertions {
        object.insert(claim_name.to_owned(), claim_value.clone());
    }

    if is_root {
        object.remove(SD_ALG_CLAIM);
    }

    for value in object.values_mut() {
        process_value(value, disclosures, state, depth + 1, false)?;
    }
    Ok(())
}

fn process_array(
    array: &mut Vec<Value>,
    disclosures: &mut DigestIndex<'_>,
    state: &mut ProcessingState,
    depth: usize,
) -> Result<(), Error> {
    let mut processed = Vec::with_capacity(array.len());

    for element in std::mem::take(array) {
        let mut element = match extract_array_digest(element)? {
            ArrayElement::Digest(digest) => {
                encounter_digest(&digest, state)?;

                let Some(disclosure) = disclosures.take(&digest) else {
                    continue;
                };
                if disclosure.claim_name.is_some() {
                    return Err(decode_error(ProcessingError::ExpectedArrayDisclosure(
                        digest,
                    )));
                }
                disclosure.claim_value.clone()
            }
            ArrayElement::Value(element) => element,
        };

        process_value(&mut element, disclosures, state, depth + 1, false)?;
        processed.push(element);
    }

    *array = processed;
    Ok(())
}

fn sd_digests(value: Value) -> Result<Vec<String>, Error> {
    match value {
        Value::Array(values) => values
            .into_iter()
            .map(|value| {
                let Value::String(digest) = value else {
                    return Err(decode_error(ProcessingError::InvalidSdClaim));
                };
                Ok(digest)
            })
            .collect(),
        _ => Err(decode_error(ProcessingError::InvalidSdClaim)),
    }
}

enum ArrayElement {
    Digest(String),
    Value(Value),
}

fn extract_array_digest(value: Value) -> Result<ArrayElement, Error> {
    let Value::Object(mut object) = value else {
        return Ok(ArrayElement::Value(value));
    };
    if object.len() != 1 || !object.contains_key(ARRAY_DIGEST_CLAIM) {
        return Ok(ArrayElement::Value(Value::Object(object)));
    }

    match object.remove(ARRAY_DIGEST_CLAIM) {
        Some(Value::String(digest)) => Ok(ArrayElement::Digest(digest)),
        _ => Err(decode_error(ProcessingError::InvalidSdClaim)),
    }
}

/// Tracks that a digest has been encountered during processing.
///
/// Returns an error if the digest has already been encountered.
fn encounter_digest(digest: &str, state: &mut ProcessingState) -> Result<(), Error> {
    if state.encountered_digests.insert(digest.to_owned()) {
        Ok(())
    } else {
        Err(decode_error(ProcessingError::DuplicateEmbeddedDigest(
            digest.to_owned(),
        )))
    }
}

fn decode_error(reason: ProcessingError) -> Error {
    Error::DisclosureProcessing { reason }
}
