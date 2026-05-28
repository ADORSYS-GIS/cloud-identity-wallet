use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::core::claim_path_pointer::ClaimPathPointer;
use crate::errors::{DcqlValidationError, Error, ErrorKind};

/// The top-level DCQL query structure.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DcqlQuery {
    /// The list of credential queries.
    pub credentials: Vec<CredentialQuery>,

    /// Optional credential sets that define combinations of credentials
    /// that must be presented together.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_sets: Option<Vec<CredentialSetQuery>>,
}

impl DcqlQuery {
    /// Validates the DCQL query according to the OpenID4VP spec.
    pub fn validate(&self) -> Result<(), Error> {
        if self.credentials.is_empty() {
            return Err(Error::message(
                ErrorKind::InvalidDcqlQuery,
                "DCQL query must contain at least one credential query",
            ));
        }

        let mut ids = HashSet::new();
        for cred in &self.credentials {
            if !ids.insert(cred.id.clone()) {
                return Err(Error::message(
                    ErrorKind::InvalidDcqlQuery,
                    format!("duplicate credential query id: {}", cred.id),
                ));
            }
        }

        // Build a set of valid credential IDs for later validation
        let valid_credential_ids: HashSet<_> = self.credentials.iter().map(|c| &c.id).collect();

        if let Some(ref sets) = self.credential_sets {
            for set in sets {
                // All credential IDs in the set must exist in credentials
                for cred_id in &set.options {
                    if !valid_credential_ids.contains(cred_id) {
                        return Err(Error::message(
                            ErrorKind::InvalidDcqlQuery,
                            format!(
                                "credential set references unknown credential id: {}",
                                cred_id
                            ),
                        ));
                    }
                }
            }
        }

        for cred in &self.credentials {
            if let Some(ref claim_sets) = cred.claim_sets {
                // Build set of valid claim IDs for this credential
                let valid_claim_ids: HashSet<_> = cred
                    .claims
                    .as_ref()
                    .map(|claims| claims.iter().map(|c| &c.id).collect())
                    .unwrap_or_default();

                for claim_set in claim_sets {
                    for claim_id in claim_set {
                        if !valid_claim_ids.contains(claim_id) {
                            return Err(Error::message(
                                ErrorKind::InvalidDcqlQuery,
                                format!(
                                    "claim_set references unknown claim id: {} in credential {}",
                                    claim_id, cred.id
                                ),
                            ));
                        }
                    }
                }
            }

            // Validate individual claims
            if let Some(ref claims) = cred.claims {
                for claim in claims {
                    claim.validate().map_err(|e| {
                        Error::message(
                            ErrorKind::InvalidDcqlQuery,
                            format!(
                                "invalid claim query '{}' in credential '{}': {}",
                                claim.id, cred.id, e
                            ),
                        )
                    })?;
                }
            }
        }

        Ok(())
    }
}

/// A query for a specific credential.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialQuery {
    /// A unique identifier for this credential query.
    pub id: String,

    /// The format of the requested credential.
    pub format: String,

    /// Format-specific metadata for the credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<Value>,

    /// The specific claims being requested from this credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<ClaimsQuery>>,

    /// Sets of claims that can be presented as alternatives.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_sets: Option<Vec<Vec<String>>>,

    /// Optional trusted authorities for this credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusted_authorities: Option<Vec<TrustedAuthorityQuery>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_cryptographic_holder_binding: Option<bool>,
}

/// A query for a specific claim within a credential.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimsQuery {
    /// A unique identifier for this claim query within the credential.
    pub id: String,

    /// The path to the claim within the credential.
    pub path: ClaimPathPointer,

    /// Optional values that the claim must match.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<Value>>,

    /// Optional indication that the claim value must match all values (AND logic).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_all: Option<bool>,
}

impl ClaimsQuery {
    /// Validates this claims query.
    pub fn validate(&self) -> Result<(), DcqlValidationError> {
        // If values are specified, they must not be empty
        if let Some(ref values) = self.values {
            if values.is_empty() {
                return Err(DcqlValidationError::EmptyValuesList {
                    claim_id: self.id.clone(),
                });
            }
        }

        Ok(())
    }
}

/// A set of credentials that must be presented together.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialSetQuery {
    /// The credential IDs that form this set.
    pub options: Vec<String>,

    /// Whether this set is required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
}

/// A trusted authority that can issue the requested credential.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustedAuthorityQuery {
    /// The identifier of the trusted authority (e.g., issuer DID or URL).
    pub id: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Test: Simple single-credential query
    #[test]
    fn test_simple_single_credential_query() {
        let json = json!({
            "credentials": [
                {
                    "id": "pid",
                    "format": "vc+sd-jwt",
                    "meta": { "vct_values": ["https://example.org/PID"] },
                    "claims": [
                        { "id": "given_name", "path": ["given_name"] },
                        { "id": "family_name", "path": ["family_name"] }
                    ]
                }
            ]
        });

        let query: DcqlQuery = serde_json::from_value(json).unwrap();
        assert_eq!(query.credentials.len(), 1);
        assert_eq!(query.credentials[0].id, "pid");
        assert_eq!(query.credentials[0].format, "vc+sd-jwt");
        assert!(query.validate().is_ok());
    }

    // Test: Multi-credential query with credential sets
    #[test]
    fn test_multi_credential_with_credential_sets() {
        let json = json!({
            "credentials": [
                {
                    "id": "pid",
                    "format": "vc+sd-jwt",
                    "meta": { "vct_values": ["https://example.org/PID"] },
                    "claims": [
                        { "id": "given_name", "path": ["given_name"] }
                    ]
                },
                {
                    "id": "mdl",
                    "format": "mso_mdoc",
                    "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
                    "claims": [
                        { "id": "license_number", "path": ["org.iso.18013.5.1", "license_number"] }
                    ]
                }
            ],
            "credential_sets": [
                { "options": ["pid", "mdl"], "required": true }
            ]
        });

        let query: DcqlQuery = serde_json::from_value(json).unwrap();
        assert_eq!(query.credentials.len(), 2);
        assert!(query.credential_sets.is_some());
        assert!(query.validate().is_ok());
    }

    // Test: Claims with value filters
    #[test]
    fn test_claims_with_value_filters() {
        let json = json!({
            "credentials": [
                {
                    "id": "age_credential",
                    "format": "vc+sd-jwt",
                    "claims": [
                        {
                            "id": "age_over_18",
                            "path": ["age_over_18"],
                            "values": [true]
                        },
                        {
                            "id": "nationality",
                            "path": ["nationality"],
                            "values": ["DE", "AT", "CH"]
                        }
                    ]
                }
            ]
        });

        let query: DcqlQuery = serde_json::from_value(json).unwrap();
        assert!(query.validate().is_ok());

        let claims = query.credentials[0].claims.as_ref().unwrap();
        assert_eq!(claims[0].values.as_ref().unwrap().len(), 1);
        assert_eq!(claims[1].values.as_ref().unwrap().len(), 3);
    }

    // Test: Trusted authorities
    #[test]
    fn test_trusted_authorities() {
        let json = json!({
            "credentials": [
                {
                    "id": "pid",
                    "format": "vc+sd-jwt",
                    "trusted_authorities": [
                        { "id": "did:example:issuer1" },
                        { "id": "https://trusted-issuer.example.com" }
                    ]
                }
            ]
        });

        let query: DcqlQuery = serde_json::from_value(json).unwrap();
        assert!(query.validate().is_ok());

        let authorities = query.credentials[0].trusted_authorities.as_ref().unwrap();
        assert_eq!(authorities.len(), 2);
        assert_eq!(authorities[0].id, "did:example:issuer1");
    }

    // Test: Validation rejection - empty credentials
    #[test]
    fn test_validation_empty_credentials() {
        let query = DcqlQuery {
            credentials: vec![],
            credential_sets: None,
        };

        let result = query.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("at least one credential"));
    }

    // Test: Validation rejection - duplicate IDs
    #[test]
    fn test_validation_duplicate_ids() {
        let json = json!({
            "credentials": [
                {
                    "id": "same_id",
                    "format": "vc+sd-jwt"
                },
                {
                    "id": "same_id",
                    "format": "mso_mdoc"
                }
            ]
        });

        let query: DcqlQuery = serde_json::from_value(json).unwrap();
        let result = query.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("duplicate"));
    }

    // Test: Validation rejection - dangling credential reference in set
    #[test]
    fn test_validation_dangling_credential_ref() {
        let json = json!({
            "credentials": [
                {
                    "id": "pid",
                    "format": "vc+sd-jwt"
                }
            ],
            "credential_sets": [
                { "options": ["pid", "nonexistent"] }
            ]
        });

        let query: DcqlQuery = serde_json::from_value(json).unwrap();
        let result = query.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("unknown credential"));
    }

    // Test: Validation rejection - dangling claim reference in claim_set
    #[test]
    fn test_validation_dangling_claim_ref() {
        let json = json!({
            "credentials": [
                {
                    "id": "pid",
                    "format": "vc+sd-jwt",
                    "claims": [
                        { "id": "given_name", "path": ["given_name"] }
                    ],
                    "claim_sets": [
                        ["given_name", "nonexistent_claim"]
                    ]
                }
            ]
        });

        let query: DcqlQuery = serde_json::from_value(json).unwrap();
        let result = query.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("unknown claim"));
    }

    // Test: Serde round-trip
    #[test]
    fn test_serde_roundtrip() {
        let original = json!({
            "credentials": [
                {
                    "id": "pid",
                    "format": "vc+sd-jwt",
                    "meta": { "vct_values": ["https://example.org/PID"] },
                    "claims": [
                        { "id": "given_name", "path": ["given_name"] },
                        { "id": "family_name", "path": ["family_name"] }
                    ],
                    "claim_sets": [
                        ["given_name"],
                        ["family_name"]
                    ]
                }
            ],
            "credential_sets": [
                { "options": ["pid"], "required": true }
            ]
        });

        let query: DcqlQuery = serde_json::from_value(original.clone()).unwrap();
        let serialized = serde_json::to_value(&query).unwrap();

        // Verify key fields are preserved
        assert_eq!(serialized["credentials"][0]["id"], "pid");
        assert_eq!(serialized["credentials"][0]["format"], "vc+sd-jwt");
        assert!(serialized["credential_sets"].is_array());
    }

    // Test: Spec example from Section 7.4 - simple query
    #[test]
    fn test_spec_example_simple() {
        // Example from OpenID4VP Section 7.4
        let json = json!({
            "credentials": [
                {
                    "id": "pid",
                    "format": "vc+sd-jwt",
                    "meta": {
                        "vct_values": ["https://example.org/PID"]
                    },
                    "claims": [
                        {
                            "id": "given_name",
                            "path": ["given_name"]
                        },
                        {
                            "id": "family_name",
                            "path": ["family_name"]
                        },
                        {
                            "id": "birthdate",
                            "path": ["birthdate"]
                        }
                    ]
                }
            ]
        });

        let query: DcqlQuery = serde_json::from_value(json).unwrap();
        assert!(query.validate().is_ok());
        assert_eq!(query.credentials[0].claims.as_ref().unwrap().len(), 3);
    }

    // Test: Spec example with mso_mdoc
    #[test]
    fn test_spec_example_mso_mdoc() {
        // Example with ISO mdoc format
        let json = json!({
            "credentials": [
                {
                    "id": "mdl",
                    "format": "mso_mdoc",
                    "meta": {
                        "doctype_value": "org.iso.18013.5.1.mDL"
                    },
                    "claims": [
                        {
                            "id": "given_name",
                            "path": ["org.iso.18013.5.1", "given_name"]
                        },
                        {
                            "id": "family_name",
                            "path": ["org.iso.18013.5.1", "family_name"]
                        }
                    ]
                }
            ]
        });

        let query: DcqlQuery = serde_json::from_value(json).unwrap();
        assert!(query.validate().is_ok());

        let claims = query.credentials[0].claims.as_ref().unwrap();
        assert_eq!(
            claims[0].path.elements()[0].to_string(),
            "\"org.iso.18013.5.1\""
        );
    }

    // Test: Claim sets - alternative claims
    #[test]
    fn test_claim_sets_alternatives() {
        let json = json!({
            "credentials": [
                {
                    "id": "credential",
                    "format": "vc+sd-jwt",
                    "claims": [
                        { "id": "email", "path": ["email"] },
                        { "id": "phone", "path": ["phone"] }
                    ],
                    "claim_sets": [
                        ["email"],
                        ["phone"]
                    ]
                }
            ]
        });

        let query: DcqlQuery = serde_json::from_value(json).unwrap();
        assert!(query.validate().is_ok());

        let claim_sets = query.credentials[0].claim_sets.as_ref().unwrap();
        assert_eq!(claim_sets.len(), 2);
        assert_eq!(claim_sets[0], vec!["email"]);
        assert_eq!(claim_sets[1], vec!["phone"]);
    }

    // Test: Empty values list should fail validation
    #[test]
    fn test_empty_values_list_validation() {
        let json = json!({
            "credentials": [
                {
                    "id": "pid",
                    "format": "vc+sd-jwt",
                    "claims": [
                        {
                            "id": "age",
                            "path": ["age"],
                            "values": []
                        }
                    ]
                }
            ]
        });

        let query: DcqlQuery = serde_json::from_value(json).unwrap();
        let result = query.validate();
        assert!(result.is_err());
    }

    // Test: Complex path with array index
    #[test]
    fn test_complex_path_with_index() {
        let json = json!({
            "credentials": [
                {
                    "id": "credential",
                    "format": "jwt_vc_json",
                    "claims": [
                        {
                            "id": "first_address",
                            "path": ["addresses", 0, "street"]
                        }
                    ]
                }
            ]
        });

        let query: DcqlQuery = serde_json::from_value(json).unwrap();
        assert!(query.validate().is_ok());

        let path = &query.credentials[0].claims.as_ref().unwrap()[0].path;
        assert_eq!(path.len(), 3);
    }

    // Test: Path with null (all array elements)
    #[test]
    fn test_path_with_null_selector() {
        let json = json!({
            "credentials": [
                {
                    "id": "credential",
                    "format": "vc+sd-jwt",
                    "claims": [
                        {
                            "id": "all_nationalities",
                            "path": ["nationalities", null]
                        }
                    ]
                }
            ]
        });

        let query: DcqlQuery = serde_json::from_value(json).unwrap();
        assert!(query.validate().is_ok());
    }

    // Test: Optional fields omitted
    #[test]
    fn test_optional_fields_omitted() {
        let json = json!({
            "credentials": [
                {
                    "id": "simple",
                    "format": "vc+sd-jwt"
                }
            ]
        });

        let query: DcqlQuery = serde_json::from_value(json).unwrap();
        assert!(query.validate().is_ok());
        assert!(query.credentials[0].claims.is_none());
        assert!(query.credentials[0].meta.is_none());
        assert!(query.credentials[0].trusted_authorities.is_none());
    }

    // Test: Multiple credential sets
    #[test]
    fn test_multiple_credential_sets() {
        let json = json!({
            "credentials": [
                { "id": "pid", "format": "vc+sd-jwt" },
                { "id": "mdl", "format": "mso_mdoc" },
                { "id": "loyalty", "format": "jwt_vc_json" }
            ],
            "credential_sets": [
                { "options": ["pid", "mdl"], "required": true },
                { "options": ["loyalty"], "required": false }
            ]
        });

        let query: DcqlQuery = serde_json::from_value(json).unwrap();
        assert!(query.validate().is_ok());

        let sets = query.credential_sets.as_ref().unwrap();
        assert_eq!(sets.len(), 2);
        assert_eq!(sets[0].required, Some(true));
        assert_eq!(sets[1].required, Some(false));
    }
}
