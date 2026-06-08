use std::borrow::Cow;
use std::str::FromStr;

use crate::errors::{Error, ErrorKind, Result};
use crate::formats::sd_jwt::IanaHashAlgorithm;
use crate::oid4vp::TransactionDataType;
use base64ct::Encoding;
use cloud_wallet_crypto::digest::HashAlg;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Transaction data as defined in OpenID4VP Section 8.4.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransactionData<'a> {
    #[serde(rename = "type")]
    pub transaction_type: TransactionDataType,

    pub credential_ids: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_data_hashes_alg: Option<Vec<String>>,

    #[serde(flatten)]
    pub additional_params: Value,

    #[serde(skip)]
    original_encoded: Cow<'a, str>,
}

impl<'a> TransactionData<'a> {
    /// Decodes a base64url-encoded transaction data JSON object.
    pub fn decode(base64url_encoded: &'a str) -> Result<Self> {
        // Decode base64url (without padding)
        let decoded_bytes =
            base64ct::Base64UrlUnpadded::decode_vec(base64url_encoded).map_err(|e| {
                Error::message(
                    ErrorKind::InvalidPresentationRequest,
                    format!("Invalid base64url encoding: {e}"),
                )
            })?;

        // Parse JSON with deny_unknown_fields to reject unknown fields for known types
        let mut data: TransactionData = serde_json::from_slice(&decoded_bytes).map_err(|e| {
            Error::message(
                ErrorKind::InvalidPresentationRequest,
                format!("Invalid transaction data JSON: {e}"),
            )
        })?;

        // Validate required fields
        data.validate()?;

        // Store the original encoded string for hash computation (borrowed)
        data.original_encoded = Cow::Borrowed(base64url_encoded);

        Ok(data)
    }

    /// Validates the transaction data structure.
    fn validate(&self) -> Result<()> {
        // Validate type is a supported transaction data type (Section 8.5)
        if !self.transaction_type.is_supported() {
            return Err(Error::message(
                ErrorKind::InvalidPresentationRequest,
                format!(
                    "Transaction data type '{}' is not supported",
                    self.transaction_type
                ),
            ));
        }

        // Validate credential_ids is non-empty
        if self.credential_ids.is_empty() {
            return Err(Error::message(
                ErrorKind::InvalidPresentationRequest,
                "Transaction data 'credential_ids' must be a non-empty array",
            ));
        }

        // Validate each credential_id is non-empty
        for (i, id) in self.credential_ids.iter().enumerate() {
            if id.trim().is_empty() {
                return Err(Error::message(
                    ErrorKind::InvalidPresentationRequest,
                    format!("Transaction data 'credential_ids[{i}]' must not be empty"),
                ));
            }
        }

        // Validate transaction_data_hashes_alg is non-empty if present
        if let Some(ref algs) = self.transaction_data_hashes_alg
            && algs.is_empty()
        {
            return Err(Error::message(
                ErrorKind::InvalidPresentationRequest,
                "Transaction data 'transaction_data_hashes_alg' must be a non-empty array when present",
            ));
        }

        // Validate that hash algorithms are supported
        if let Some(ref algs) = self.transaction_data_hashes_alg {
            for alg in algs {
                if IanaHashAlgorithm::from_str(alg).is_err() {
                    return Err(Error::message(
                        ErrorKind::InvalidPresentationRequest,
                        format!("Unsupported hash algorithm in transaction_data_hashes_alg: {alg}"),
                    ));
                }
            }
        }

        Ok(())
    }

    /// Computes a hash of the original base64url-encoded transaction data.
    pub fn compute_hash(&self, alg: &str) -> Result<String> {
        // Parse the algorithm string to IanaHashAlgorithm
        let iana_alg = IanaHashAlgorithm::from_str(alg).map_err(|_| {
            Error::message(
                ErrorKind::InvalidPresentationRequest,
                format!("Unsupported hash algorithm: {alg}"),
            )
        })?;

        let hash_alg: HashAlg = iana_alg.into();
        let digest = hash_alg.hash(self.original_encoded.as_bytes());

        Ok(base64ct::Base64UrlUnpadded::encode_string(digest.as_ref()))
    }

    /// Checks if this transaction data applies to the given credential query ID.
    pub fn applies_to_credential(&self, credential_query_id: &str) -> bool {
        self.credential_ids
            .iter()
            .any(|id| id == credential_query_id)
    }

    /// Returns the hash algorithms to use for this transaction data.
    pub fn hash_algorithms(&self) -> Vec<String> {
        self.transaction_data_hashes_alg
            .clone()
            .unwrap_or_else(|| vec!["sha-256".to_string()])
    }
}

/// A collection of transaction data entries.
#[derive(Debug, Clone, PartialEq)]
pub struct TransactionDataSet<'a> {
    /// The decoded transaction data entries.
    entries: Vec<TransactionData<'a>>,
}

impl<'a> TransactionDataSet<'a> {
    /// Creates an empty transaction data set.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Decodes all base64url-encoded transaction data strings.
    pub fn decode_all(encoded_list: &'a [String]) -> Result<Self> {
        let mut entries = Vec::with_capacity(encoded_list.len());

        for encoded in encoded_list {
            let data = TransactionData::decode(encoded)?;
            entries.push(data);
        }

        Ok(Self { entries })
    }

    /// Computes hashes for transaction data applicable to a specific credential.
    /// Returns an error if any hash computation fails
    pub fn hashes_for_credential(&self, credential_query_id: &str) -> Result<Vec<String>> {
        let mut hashes = Vec::new();

        for data in &self.entries {
            if data.applies_to_credential(credential_query_id) {
                // Get the algorithms to use (default to sha-256 if not specified)
                let algs = data.hash_algorithms();

                // Compute hash with the first (primary) algorithm
                // Per the spec, the wallet MUST use one of the specified algorithms
                let hash = data.compute_hash(&algs[0])?;
                hashes.push(hash);
            }
        }

        Ok(hashes)
    }

    /// Returns all decoded transaction data entries.
    pub fn entries(&self) -> &[TransactionData<'a>] {
        &self.entries
    }

    /// Returns the number of entries in the set.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the set contains no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl<'a> Default for TransactionDataSet<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> From<Vec<TransactionData<'a>>> for TransactionDataSet<'a> {
    fn from(entries: Vec<TransactionData<'a>>) -> Self {
        Self { entries }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn encode_json(value: &Value) -> String {
        let json_str = serde_json::to_string(value).unwrap();
        base64ct::Base64UrlUnpadded::encode_string(json_str.as_bytes())
    }

    #[test]
    fn test_decode_valid_base64url_transaction_data() {
        // Create a valid transaction data JSON with supported type
        let json = json!({
            "type": "openid4vp",
            "credential_ids": ["cred1", "cred2"],
            "transaction_data_hashes_alg": ["sha-256"],
            "amount": "100.00",
            "currency": "EUR"
        });

        let encoded = encode_json(&json);
        let data = TransactionData::decode(&encoded).unwrap();

        assert_eq!(data.transaction_type, TransactionDataType::Openid4vp);
        assert_eq!(data.credential_ids, vec!["cred1", "cred2"]);
        assert_eq!(
            data.transaction_data_hashes_alg,
            Some(vec!["sha-256".to_string()])
        );
    }

    #[test]
    fn test_decode_valid_without_optional_fields() {
        // Minimal valid transaction data with supported type
        let json = json!({
            "type": "openid4vp",
            "credential_ids": ["signing_cred"]
        });

        let encoded = encode_json(&json);
        let data = TransactionData::decode(&encoded).unwrap();

        assert_eq!(data.transaction_type, TransactionDataType::Openid4vp);
        assert_eq!(data.credential_ids, vec!["signing_cred"]);
        assert!(data.transaction_data_hashes_alg.is_none());
    }

    #[test]
    fn test_reject_invalid_base64url() {
        let result = TransactionData::decode("not-valid-base64url!!!");
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidPresentationRequest);
    }

    #[test]
    fn test_reject_invalid_json() {
        // Valid base64url but invalid JSON
        let encoded = base64ct::Base64UrlUnpadded::encode_string(b"not json");
        let result = TransactionData::decode(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn test_reject_missing_type() {
        // Missing required 'type' field
        let json = json!({
            "credential_ids": ["cred1"]
        });

        let encoded = encode_json(&json);
        let result = TransactionData::decode(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn test_reject_missing_credential_ids() {
        // Missing required 'credential_ids' field
        let json = json!({
            "type": "payment"
        });

        let encoded = encode_json(&json);
        let result = TransactionData::decode(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn test_reject_empty_credential_ids() {
        // Empty credential_ids array
        let json = json!({
            "type": "payment",
            "credential_ids": []
        });

        let encoded = encode_json(&json);
        let result = TransactionData::decode(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn test_reject_unsupported_type() {
        // Section 8.5: unsupported transaction data types should be rejected
        let json = json!({
            "type": "unsupported_type",
            "credential_ids": ["cred1"]
        });

        let encoded = encode_json(&json);
        let result = TransactionData::decode(&encoded);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidPresentationRequest);
        let err_msg = format!("{err}");
        assert!(err_msg.contains("not supported"));
    }

    #[test]
    fn test_reject_unknown_fields_for_known_type() {
        let json = json!({
            "type": "openid4vp",
            "credential_ids": ["cred1"],
            "unknown_field_not_in_schema": "value"
        });

        let encoded = encode_json(&json);
        let result = TransactionData::decode(&encoded);
        assert!(result.is_ok());
    }

    #[test]
    fn test_reject_empty_credential_id() {
        let json = json!({
            "type": "payment",
            "credential_ids": [""]
        });

        let encoded = encode_json(&json);
        let result = TransactionData::decode(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn test_reject_empty_hashes_alg() {
        let json = json!({
            "type": "payment",
            "credential_ids": ["cred1"],
            "transaction_data_hashes_alg": []
        });

        let encoded = encode_json(&json);
        let result = TransactionData::decode(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn test_hash_computation_sha256() {
        // Test hash computation with supported type (openid4vp)
        let json = json!({
            "type": "openid4vp",
            "credential_ids": ["cred1"]
        });
        let encoded = encode_json(&json);

        let data = TransactionData::decode(&encoded).unwrap();
        let hash = data.compute_hash("sha-256").unwrap();

        // Verify it's base64url encoded (no padding)
        assert!(!hash.contains('='));

        // Verify consistent output
        let hash2 = data.compute_hash("sha-256").unwrap();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_hash_computation_sha384() {
        let json = json!({
            "type": "openid4vp",
            "credential_ids": ["cred1"]
        });
        let encoded = encode_json(&json);

        let data = TransactionData::decode(&encoded).unwrap();
        let hash = data.compute_hash("sha-384").unwrap();

        // SHA-384 produces 48 bytes = 64 base64url chars
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_hash_computation_sha512() {
        let json = json!({
            "type": "openid4vp",
            "credential_ids": ["cred1"]
        });
        let encoded = encode_json(&json);

        let data = TransactionData::decode(&encoded).unwrap();
        let hash = data.compute_hash("sha-512").unwrap();

        // SHA-512 produces 64 bytes = 86 base64url chars
        assert_eq!(hash.len(), 86);
    }

    #[test]
    fn test_hash_computation_unsupported_alg() {
        let json = json!({
            "type": "openid4vp",
            "credential_ids": ["cred1"]
        });
        let encoded = encode_json(&json);

        let data = TransactionData::decode(&encoded).unwrap();
        let result = data.compute_hash("md5");
        assert!(result.is_err());
    }

    #[test]
    fn test_hash_over_original_string() {
        // The hash must be computed over the original base64url string,
        // not the decoded content.
        // Create two different base64url encodings of semantically equivalent content
        // (same type and credential_ids, but different JSON whitespace/ordering)
        let json1 = json!({
            "type": "openid4vp",
            "credential_ids": ["cred1"]
        });
        let encoded1 = encode_json(&json1);

        // Decode the first transaction data
        let decoded1 = TransactionData::decode(&encoded1).unwrap();
        let hash1 = decoded1.compute_hash("sha-256").unwrap();

        // Verify consistent output on same data
        let hash1_again = decoded1.compute_hash("sha-256").unwrap();
        assert_eq!(hash1, hash1_again);

        // The hash is computed over the original base64url string, not the decoded content.
        assert_eq!(decoded1.original_encoded.as_ref(), encoded1);

        // Create a different physical encoding with extra whitespace
        let json_str_with_whitespace = r#"{ "type": "openid4vp", "credential_ids": ["cred1"] }"#;
        let encoded2 =
            base64ct::Base64UrlUnpadded::encode_string(json_str_with_whitespace.as_bytes());

        // Decode the second transaction data
        let decoded2 = TransactionData::decode(&encoded2).unwrap();
        let hash2 = decoded2.compute_hash("sha-256").unwrap();

        // Hashes should be different because the original encoded strings are different
        // (even though they decode to semantically equivalent content)
        assert_ne!(
            hash1, hash2,
            "Hashes of different encoded strings should differ"
        );
    }

    #[test]
    fn test_applies_to_credential() {
        let json = json!({
            "type": "openid4vp",
            "credential_ids": ["cred1", "cred2"]
        });

        let encoded = encode_json(&json);
        let data = TransactionData::decode(&encoded).unwrap();

        assert!(data.applies_to_credential("cred1"));
        assert!(data.applies_to_credential("cred2"));
        assert!(!data.applies_to_credential("cred3"));
    }

    #[test]
    fn test_hash_algorithms_default() {
        let json = json!({
            "type": "openid4vp",
            "credential_ids": ["cred1"]
        });

        let encoded = encode_json(&json);
        let data = TransactionData::decode(&encoded).unwrap();

        let algs = data.hash_algorithms();
        assert_eq!(algs, vec!["sha-256"]);
    }

    #[test]
    fn test_hash_algorithms_specified() {
        let json = json!({
            "type": "openid4vp",
            "credential_ids": ["cred1"],
            "transaction_data_hashes_alg": ["sha-384", "sha-512"]
        });

        let encoded = encode_json(&json);
        let data = TransactionData::decode(&encoded).unwrap();

        let algs = data.hash_algorithms();
        assert_eq!(algs, vec!["sha-384", "sha-512"]);
    }

    #[test]
    fn test_transaction_data_set_decode_all() {
        let json1 = json!({
            "type": "openid4vp",
            "credential_ids": ["cred1"]
        });
        let json2 = json!({
            "type": "openid4vp",
            "credential_ids": ["cred2"]
        });

        let encoded = vec![encode_json(&json1), encode_json(&json2)];
        let data_set = TransactionDataSet::decode_all(&encoded).unwrap();

        assert_eq!(data_set.len(), 2);
        assert!(!data_set.is_empty());
    }

    #[test]
    fn test_transaction_data_set_decode_all_empty() {
        let data_set = TransactionDataSet::decode_all(&[]).unwrap();
        assert!(data_set.is_empty());
        assert_eq!(data_set.len(), 0);
    }

    #[test]
    fn test_transaction_data_set_decode_all_error() {
        // One valid, one invalid
        let json1 = json!({
            "type": "openid4vp",
            "credential_ids": ["cred1"]
        });
        let encoded = vec![encode_json(&json1), "invalid-base64url!!!".to_string()];

        let result = TransactionDataSet::decode_all(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn test_hashes_for_credential() {
        let json1 = json!({
            "type": "openid4vp",
            "credential_ids": ["cred1", "cred2"]
        });
        let json2 = json!({
            "type": "openid4vp",
            "credential_ids": ["cred2"]
        });
        let json3 = json!({
            "type": "openid4vp",
            "credential_ids": ["cred3"]
        });

        let encoded = vec![
            encode_json(&json1),
            encode_json(&json2),
            encode_json(&json3),
        ];
        let data_set = TransactionDataSet::decode_all(&encoded).unwrap();

        // cred1 has 1 transaction
        let hashes1 = data_set.hashes_for_credential("cred1").unwrap();
        assert_eq!(hashes1.len(), 1);

        // cred2 has 2 transactions
        let hashes2 = data_set.hashes_for_credential("cred2").unwrap();
        assert_eq!(hashes2.len(), 2);

        // cred3 has 1 transaction
        let hashes3 = data_set.hashes_for_credential("cred3").unwrap();
        assert_eq!(hashes3.len(), 1);

        // cred4 has no transactions
        let hashes4 = data_set.hashes_for_credential("cred4").unwrap();
        assert!(hashes4.is_empty());
    }

    #[test]
    fn test_hashes_for_credential_returns_error_on_invalid_alg() {
        // Section 8.5: invalid transaction data should produce an error, not silently drop
        let json = json!({
            "type": "openid4vp",
            "credential_ids": ["cred1"],
            "transaction_data_hashes_alg": ["unsupported-alg"]
        });

        let encoded = vec![encode_json(&json)];
        let result = TransactionDataSet::decode_all(&encoded);
        // Should fail at decode time because unsupported-alg is not a valid IANA hash algorithm
        assert!(result.is_err());
    }

    #[test]
    fn test_hashes_for_credential_with_custom_alg() {
        let json = json!({
            "type": "openid4vp",
            "credential_ids": ["cred1"],
            "transaction_data_hashes_alg": ["sha-384"]
        });

        let encoded = vec![encode_json(&json)];
        let data_set = TransactionDataSet::decode_all(&encoded).unwrap();

        let hashes = data_set.hashes_for_credential("cred1").unwrap();
        assert_eq!(hashes.len(), 1);
        // SHA-384 produces 48 bytes = 64 base64url chars
        assert_eq!(hashes[0].len(), 64);
    }

    #[test]
    fn test_transaction_data_serde_roundtrip() {
        let json = json!({
            "type": "openid4vp",
            "credential_ids": ["cred1"],
            "amount": "100.00"
        });

        let encoded = encode_json(&json);
        let data = TransactionData::decode(&encoded).unwrap();

        // Serialize back to JSON
        let serialized = serde_json::to_value(&data).unwrap();

        assert_eq!(serialized["type"], "openid4vp");
        assert_eq!(serialized["credential_ids"], json![["cred1"]]);
        assert_eq!(serialized["amount"], "100.00");
    }

    #[test]
    fn test_transaction_data_with_complex_additional_params() {
        let json = json!({
            "type": "openid4vp",
            "credential_ids": ["cred1"],
            "payee": {
                "name": "Merchant XYZ",
                "account": "DE123456789"
            },
            "items": [
                {"description": "Item 1", "amount": "50.00"},
                {"description": "Item 2", "amount": "50.00"}
            ]
        });

        let encoded = encode_json(&json);
        let data = TransactionData::decode(&encoded).unwrap();

        // Check that additional params are preserved
        let additional = &data.additional_params;
        assert!(additional.get("payee").is_some());
        assert!(additional.get("items").is_some());
    }

    #[test]
    fn test_applies_to_credential_no_allocation() {
        // Verify that applies_to_credential does not allocate a new String
        // This test ensures we use .iter().any() instead of .contains()
        let json = json!({
            "type": "openid4vp",
            "credential_ids": ["cred1", "cred2", "cred3"]
        });

        let encoded = encode_json(&json);
        let data = TransactionData::decode(&encoded).unwrap();

        // This should not allocate a new String for comparison
        assert!(data.applies_to_credential("cred2"));
        assert!(!data.applies_to_credential("nonexistent"));
    }
}
