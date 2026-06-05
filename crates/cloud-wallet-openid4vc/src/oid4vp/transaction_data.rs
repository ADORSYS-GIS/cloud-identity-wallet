use crate::errors::{Error, ErrorKind, Result};
use base64ct::Encoding;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Transaction data as defined in OpenID4VP Section 8.4.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransactionData {
    #[serde(rename = "type")]
    pub transaction_type: String,

    pub credential_ids: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_data_hashes_alg: Option<Vec<String>>,

    #[serde(flatten)]
    pub additional_params: Value,
}

impl TransactionData {
    /// Decodes a base64url-encoded transaction data JSON object.
    pub fn decode(base64url_encoded: &str) -> Result<Self> {
        // Decode base64url (without padding)
        let decoded_bytes =
            base64ct::Base64UrlUnpadded::decode_vec(base64url_encoded).map_err(|e| {
                Error::message(
                    ErrorKind::InvalidPresentationRequest,
                    format!("Invalid base64url encoding: {e}"),
                )
            })?;

        // Parse JSON
        let data: TransactionData = serde_json::from_slice(&decoded_bytes).map_err(|e| {
            Error::message(
                ErrorKind::InvalidPresentationRequest,
                format!("Invalid transaction data JSON: {e}"),
            )
        })?;

        // Validate required fields
        data.validate()?;

        Ok(data)
    }

    /// Validates the transaction data structure.
    fn validate(&self) -> Result<()> {
        // Validate type is non-empty
        if self.transaction_type.trim().is_empty() {
            return Err(Error::message(
                ErrorKind::InvalidPresentationRequest,
                "Transaction data 'type' must not be empty",
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

        Ok(())
    }

    /// Computes a hash of the original base64url-encoded transaction data.
    pub fn compute_hash(base64url_encoded: &str, alg: &str) -> Result<String> {
        let hash_bytes = match alg.to_lowercase().as_str() {
            "sha-256" => {
                let mut hasher = Sha256::new();
                hasher.update(base64url_encoded.as_bytes());
                hasher.finalize().to_vec()
            }
            "sha-384" => {
                use sha2::Sha384;
                let mut hasher = Sha384::new();
                hasher.update(base64url_encoded.as_bytes());
                hasher.finalize().to_vec()
            }
            "sha-512" => {
                use sha2::Sha512;
                let mut hasher = Sha512::new();
                hasher.update(base64url_encoded.as_bytes());
                hasher.finalize().to_vec()
            }
            _ => {
                return Err(Error::message(
                    ErrorKind::InvalidPresentationRequest,
                    format!("Unsupported hash algorithm: {alg}"),
                ));
            }
        };

        Ok(base64ct::Base64UrlUnpadded::encode_string(&hash_bytes))
    }

    /// Checks if this transaction data applies to the given credential query ID.
    pub fn applies_to_credential(&self, credential_query_id: &str) -> bool {
        self.credential_ids
            .contains(&credential_query_id.to_string())
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
pub struct TransactionDataSet {
    /// The decoded transaction data entries along with their original encoded form.
    entries: Vec<(String, TransactionData)>,
}

impl TransactionDataSet {
    /// Creates an empty transaction data set.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Decodes all base64url-encoded transaction data strings.
    pub fn decode_all(encoded_list: &[String]) -> Result<Self> {
        let mut entries = Vec::with_capacity(encoded_list.len());

        for encoded in encoded_list {
            let data = TransactionData::decode(encoded)?;
            entries.push((encoded.clone(), data));
        }

        Ok(Self { entries })
    }

    /// Computes hashes for transaction data applicable to a specific credential.
    pub fn hashes_for_credential(&self, credential_query_id: &str) -> Vec<String> {
        let mut hashes = Vec::new();

        for (encoded, data) in &self.entries {
            if data.applies_to_credential(credential_query_id) {
                // Get the algorithms to use (default to sha-256 if not specified)
                let algs = data.hash_algorithms();

                // Compute hash with the first (primary) algorithm
                // Per the spec, the wallet MUST use one of the specified algorithms
                if let Ok(hash) = TransactionData::compute_hash(encoded, &algs[0]) {
                    hashes.push(hash);
                }
            }
        }

        hashes
    }

    /// Returns all decoded transaction data entries.
    pub fn entries(&self) -> &[(String, TransactionData)] {
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

impl Default for TransactionDataSet {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Vec<(String, TransactionData)>> for TransactionDataSet {
    fn from(entries: Vec<(String, TransactionData)>) -> Self {
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
        // Create a valid transaction data JSON
        let json = json!({
            "type": "payment",
            "credential_ids": ["cred1", "cred2"],
            "transaction_data_hashes_alg": ["sha-256"],
            "amount": "100.00",
            "currency": "EUR"
        });

        let encoded = encode_json(&json);
        let data = TransactionData::decode(&encoded).unwrap();

        assert_eq!(data.transaction_type, "payment");
        assert_eq!(data.credential_ids, vec!["cred1", "cred2"]);
        assert_eq!(
            data.transaction_data_hashes_alg,
            Some(vec!["sha-256".to_string()])
        );
    }

    #[test]
    fn test_decode_valid_without_optional_fields() {
        // Minimal valid transaction data
        let json = json!({
            "type": "document_signing",
            "credential_ids": ["signing_cred"]
        });

        let encoded = encode_json(&json);
        let data = TransactionData::decode(&encoded).unwrap();

        assert_eq!(data.transaction_type, "document_signing");
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
    fn test_reject_empty_type() {
        let json = json!({
            "type": "",
            "credential_ids": ["cred1"]
        });

        let encoded = encode_json(&json);
        let result = TransactionData::decode(&encoded);
        assert!(result.is_err());
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
        // Test hash computation
        let encoded = "eyJ0eXBlIjoicGF5bWVudCIsImNyZWRlbnRpYWxfaWRzIjpbImNyZWQxIl19";

        let hash = TransactionData::compute_hash(encoded, "sha-256").unwrap();

        // Verify it's base64url encoded (no padding)
        assert!(!hash.contains('='));

        // Verify consistent output
        let hash2 = TransactionData::compute_hash(encoded, "sha-256").unwrap();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_hash_computation_sha384() {
        let encoded = "eyJ0eXBlIjoicGF5bWVudCIsImNyZWRlbnRpYWxfaWRzIjpbImNyZWQxIl19";

        let hash = TransactionData::compute_hash(encoded, "sha-384").unwrap();

        // SHA-384 produces 48 bytes = 64 base64url chars
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_hash_computation_sha512() {
        let encoded = "eyJ0eXBlIjoicGF5bWVudCIsImNyZWRlbnRpYWxfaWRzIjpbImNyZWQxIl19";

        let hash = TransactionData::compute_hash(encoded, "sha-512").unwrap();

        // SHA-512 produces 64 bytes = 86 base64url chars
        assert_eq!(hash.len(), 86);
    }

    #[test]
    fn test_hash_computation_unsupported_alg() {
        let encoded = "eyJ0eXBlIjoicGF5bWVudCIsImNyZWRlbnRpYWxfaWRzIjpbImNyZWQxIl19";

        let result = TransactionData::compute_hash(encoded, "md5");
        assert!(result.is_err());
    }

    #[test]
    fn test_hash_over_original_string() {
        // The hash must be computed over the original base64url string,
        // not the decoded content.
        let encoded = "eyJ0eXBlIjoicGF5bWVudCIsImNyZWRlbnRpYWxfaWRzIjpbImNyZWQxIl19";

        // Compute hash of the encoded string
        let hash_from_encoded = TransactionData::compute_hash(encoded, "sha-256").unwrap();

        // Decode and re-encode to get potentially different representation
        let decoded = TransactionData::decode(encoded).unwrap();
        let re_encoded = encode_json(&serde_json::to_value(&decoded).unwrap());

        // Compute hash of the re-encoded string
        let hash_from_reencoded = TransactionData::compute_hash(&re_encoded, "sha-256").unwrap();

        // Hashes should be different because the encoded strings are different
        // (even though they decode to the same content)
        assert_ne!(hash_from_encoded, hash_from_reencoded);
    }

    #[test]
    fn test_applies_to_credential() {
        let json = json!({
            "type": "payment",
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
            "type": "payment",
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
            "type": "payment",
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
            "type": "payment",
            "credential_ids": ["cred1"]
        });
        let json2 = json!({
            "type": "signing",
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
            "type": "payment",
            "credential_ids": ["cred1"]
        });
        let encoded = vec![encode_json(&json1), "invalid-base64url!!!".to_string()];

        let result = TransactionDataSet::decode_all(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn test_hashes_for_credential() {
        let json1 = json!({
            "type": "payment",
            "credential_ids": ["cred1", "cred2"]
        });
        let json2 = json!({
            "type": "signing",
            "credential_ids": ["cred2"]
        });
        let json3 = json!({
            "type": "other",
            "credential_ids": ["cred3"]
        });

        let encoded = vec![
            encode_json(&json1),
            encode_json(&json2),
            encode_json(&json3),
        ];
        let data_set = TransactionDataSet::decode_all(&encoded).unwrap();

        // cred1 has 1 transaction
        let hashes1 = data_set.hashes_for_credential("cred1");
        assert_eq!(hashes1.len(), 1);

        // cred2 has 2 transactions
        let hashes2 = data_set.hashes_for_credential("cred2");
        assert_eq!(hashes2.len(), 2);

        // cred3 has 1 transaction
        let hashes3 = data_set.hashes_for_credential("cred3");
        assert_eq!(hashes3.len(), 1);

        // cred4 has no transactions
        let hashes4 = data_set.hashes_for_credential("cred4");
        assert!(hashes4.is_empty());
    }

    #[test]
    fn test_hashes_for_credential_with_custom_alg() {
        let json = json!({
            "type": "payment",
            "credential_ids": ["cred1"],
            "transaction_data_hashes_alg": ["sha-384"]
        });

        let encoded = vec![encode_json(&json)];
        let data_set = TransactionDataSet::decode_all(&encoded).unwrap();

        let hashes = data_set.hashes_for_credential("cred1");
        assert_eq!(hashes.len(), 1);
        // SHA-384 produces 48 bytes = 64 base64url chars
        assert_eq!(hashes[0].len(), 64);
    }

    #[test]
    fn test_transaction_data_serde_roundtrip() {
        let json = json!({
            "type": "payment",
            "credential_ids": ["cred1"],
            "amount": "100.00"
        });

        let encoded = encode_json(&json);
        let data = TransactionData::decode(&encoded).unwrap();

        // Serialize back to JSON
        let serialized = serde_json::to_value(&data).unwrap();

        assert_eq!(serialized["type"], "payment");
        assert_eq!(serialized["credential_ids"], json![["cred1"]]);
        assert_eq!(serialized["amount"], "100.00");
    }

    #[test]
    fn test_transaction_data_with_complex_additional_params() {
        let json = json!({
            "type": "payment",
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
}
