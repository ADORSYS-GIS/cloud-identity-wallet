//! Digital Credentials Query Language (DCQL) models.
//!
//! See OpenID4VP Section 6.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::errors::{Error, ErrorKind};
use crate::shared::claim_path_pointer::ClaimPathPointer;

fn validate_identifier(value: &str, field: &str, kind: ErrorKind) -> Result<(), Error> {
    if value.is_empty() {
        return Err(Error::message(kind, format!("{field} must not be empty")));
    }

    if !value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
    {
        return Err(Error::message(
            kind,
            format!("{field} must contain only ASCII alphanumeric characters, '_' or '-'"),
        ));
    }

    Ok(())
}

/// Primitive claim values usable in DCQL `values` matching.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ClaimValueMatch {
    /// A string literal value.
    String(String),
    /// An integer literal value.
    Integer(i64),
    /// A boolean literal value.
    Boolean(bool),
}

/// Trusted authority constraint within a credential query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedAuthorityQuery {
    /// The trusted authority mechanism identifier, e.g. `aki` or `openid_federation`.
    #[serde(rename = "type")]
    pub authority_type: String,

    /// Non-empty set of values for the authority mechanism.
    pub values: Vec<String>,
}

impl TrustedAuthorityQuery {
    /// Validates the trusted authority query.
    pub fn validate(&self) -> Result<(), Error> {
        if self.authority_type.trim().is_empty() {
            return Err(Error::message(
                ErrorKind::InvalidDcqlQuery,
                "trusted_authorities.type must not be empty",
            ));
        }

        if self.values.is_empty() {
            return Err(Error::message(
                ErrorKind::InvalidDcqlQuery,
                "trusted_authorities.values must not be empty",
            ));
        }

        if self.values.iter().any(|value| value.trim().is_empty()) {
            return Err(Error::message(
                ErrorKind::InvalidDcqlQuery,
                "trusted_authorities.values must not contain empty strings",
            ));
        }

        Ok(())
    }
}

/// Claim selector within a DCQL credential query.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimQuery {
    /// Optional identifier referenced by `claim_sets`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Claim path pointer selecting the requested claim.
    pub path: ClaimPathPointer,

    /// Optional best-effort value restriction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<ClaimValueMatch>>,

    /// ISO mdoc-specific retention hint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent_to_retain: Option<bool>,
}

impl ClaimQuery {
    /// Validates the claim query.
    pub fn validate(&self) -> Result<(), Error> {
        if let Some(id) = &self.id {
            validate_identifier(id, "claims.id", ErrorKind::InvalidDcqlQuery)?;
        }

        if matches!(self.values.as_ref(), Some(values) if values.is_empty()) {
            return Err(Error::message(
                ErrorKind::InvalidDcqlQuery,
                "claims.values must not be empty when present",
            ));
        }

        Ok(())
    }
}

/// Credential query entry inside a DCQL request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialQuery {
    /// Identifier of this credential query within the request.
    pub id: String,

    /// Requested credential format identifier.
    pub format: String,

    /// Whether multiple credentials may satisfy this query.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub multiple: Option<bool>,

    /// Format-specific metadata constraints.
    pub meta: Map<String, Value>,

    /// Optional issuer trust constraints.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusted_authorities: Option<Vec<TrustedAuthorityQuery>>,

    /// Whether cryptographic holder binding is required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_cryptographic_holder_binding: Option<bool>,

    /// Optional claim selectors for selective disclosure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<ClaimQuery>>,

    /// Optional alternative combinations of claim identifiers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_sets: Option<Vec<Vec<String>>>,
}

impl CredentialQuery {
    /// Validates the credential query.
    pub fn validate(&self) -> Result<(), Error> {
        validate_identifier(&self.id, "credentials.id", ErrorKind::InvalidDcqlQuery)?;

        if self.format.trim().is_empty() {
            return Err(Error::message(
                ErrorKind::InvalidDcqlQuery,
                "credentials.format must not be empty",
            ));
        }

        if let Some(authorities) = &self.trusted_authorities {
            if authorities.is_empty() {
                return Err(Error::message(
                    ErrorKind::InvalidDcqlQuery,
                    "trusted_authorities must not be empty when present",
                ));
            }

            for authority in authorities {
                authority.validate()?;
            }
        }

        let mut claim_ids = HashSet::new();
        let mut claim_paths = HashSet::new();

        if let Some(claims) = &self.claims {
            if claims.is_empty() {
                return Err(Error::message(
                    ErrorKind::InvalidDcqlQuery,
                    "claims must not be empty when present",
                ));
            }

            for claim in claims {
                claim.validate()?;

                if let Some(id) = &claim.id
                    && !claim_ids.insert(id.clone())
                {
                    return Err(Error::message(
                        ErrorKind::InvalidDcqlQuery,
                        format!(
                            "duplicate claim id '{id}' in credential query '{}'",
                            self.id
                        ),
                    ));
                }

                let path = claim.path.to_string();
                if !claim_paths.insert(path.clone()) {
                    return Err(Error::message(
                        ErrorKind::InvalidDcqlQuery,
                        format!(
                            "duplicate claim path {path} in credential query '{}'",
                            self.id
                        ),
                    ));
                }
            }
        }

        if let Some(claim_sets) = &self.claim_sets {
            let claims = self.claims.as_ref().ok_or_else(|| {
                Error::message(
                    ErrorKind::InvalidDcqlQuery,
                    format!(
                        "claim_sets cannot be present for '{}' without claims",
                        self.id
                    ),
                )
            })?;

            if claim_sets.is_empty() {
                return Err(Error::message(
                    ErrorKind::InvalidDcqlQuery,
                    "claim_sets must not be empty when present",
                ));
            }

            if claims.iter().any(|claim| claim.id.is_none()) {
                return Err(Error::message(
                    ErrorKind::InvalidDcqlQuery,
                    format!(
                        "all claims in '{}' must define an id when claim_sets are used",
                        self.id
                    ),
                ));
            }

            for (index, claim_set) in claim_sets.iter().enumerate() {
                if claim_set.is_empty() {
                    return Err(Error::message(
                        ErrorKind::InvalidDcqlQuery,
                        format!("claim_sets[{index}] must not be empty"),
                    ));
                }

                for claim_id in claim_set {
                    validate_identifier(
                        claim_id,
                        "claim_sets[] entry",
                        ErrorKind::InvalidDcqlQuery,
                    )?;

                    if !claim_ids.contains(claim_id) {
                        return Err(Error::message(
                            ErrorKind::InvalidDcqlQuery,
                            format!("claim_sets[{index}] references unknown claim id '{claim_id}'"),
                        ));
                    }
                }
            }
        }

        Ok(())
    }
}

/// Credential set query constraining combinations of credential queries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialSetQuery {
    /// Alternative credential id combinations satisfying the set.
    pub options: Vec<Vec<String>>,

    /// Whether the verifier requires one of the options to be satisfied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
}

impl CredentialSetQuery {
    fn validate(&self) -> Result<(), Error> {
        if self.options.is_empty() {
            return Err(Error::message(
                ErrorKind::InvalidDcqlQuery,
                "credential_sets.options must not be empty",
            ));
        }

        for (index, option) in self.options.iter().enumerate() {
            if option.is_empty() {
                return Err(Error::message(
                    ErrorKind::InvalidDcqlQuery,
                    format!("credential_sets.options[{index}] must not be empty"),
                ));
            }

            for credential_id in option {
                validate_identifier(
                    credential_id,
                    "credential_sets.options[] entry",
                    ErrorKind::InvalidDcqlQuery,
                )?;
            }
        }

        Ok(())
    }
}

/// Top-level DCQL query.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DcqlQuery {
    /// Requested credential queries.
    pub credentials: Vec<CredentialQuery>,

    /// Optional combinations of requested credentials.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_sets: Option<Vec<CredentialSetQuery>>,
}

impl DcqlQuery {
    /// Returns `true` if any credential query explicitly allows presentations without holder binding.
    pub fn requests_unbound_presentations(&self) -> bool {
        self.credentials.iter().any(|credential| {
            matches!(credential.require_cryptographic_holder_binding, Some(false))
        })
    }

    /// Validates the query.
    pub fn validate(&self) -> Result<(), Error> {
        if self.credentials.is_empty() {
            return Err(Error::message(
                ErrorKind::InvalidDcqlQuery,
                "credentials must not be empty",
            ));
        }

        let mut credential_ids = HashSet::new();
        for credential in &self.credentials {
            credential.validate()?;
            if !credential_ids.insert(credential.id.clone()) {
                return Err(Error::message(
                    ErrorKind::InvalidDcqlQuery,
                    format!("duplicate credential id '{}'", credential.id),
                ));
            }
        }

        if let Some(credential_sets) = &self.credential_sets {
            if credential_sets.is_empty() {
                return Err(Error::message(
                    ErrorKind::InvalidDcqlQuery,
                    "credential_sets must not be empty when present",
                ));
            }

            for (index, credential_set) in credential_sets.iter().enumerate() {
                credential_set.validate()?;
                for option in &credential_set.options {
                    for credential_id in option {
                        if !credential_ids.contains(credential_id) {
                            return Err(Error::message(
                                ErrorKind::InvalidDcqlQuery,
                                format!(
                                    "credential_sets[{index}] references unknown credential id '{credential_id}'"
                                ),
                            ));
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::claim_path_pointer::ClaimPathPointer;

    fn minimal_query() -> DcqlQuery {
        DcqlQuery {
            credentials: vec![CredentialQuery {
                id: "pid".to_string(),
                format: "dc+sd-jwt".to_string(),
                multiple: None,
                meta: Map::new(),
                trusted_authorities: None,
                require_cryptographic_holder_binding: None,
                claims: Some(vec![ClaimQuery {
                    id: Some("family_name".to_string()),
                    path: ClaimPathPointer::from_strings(["family_name"]),
                    values: None,
                    intent_to_retain: None,
                }]),
                claim_sets: None,
            }],
            credential_sets: None,
        }
    }

    #[test]
    fn minimal_dcql_query_is_valid() {
        minimal_query().validate().unwrap();
    }

    #[test]
    fn duplicate_credential_ids_are_rejected() {
        let mut query = minimal_query();
        query.credentials.push(query.credentials[0].clone());

        let err = query.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidDcqlQuery);
    }

    #[test]
    fn claim_sets_require_named_claims() {
        let mut query = minimal_query();
        query.credentials[0].claims = Some(vec![ClaimQuery {
            id: None,
            path: ClaimPathPointer::from_strings(["family_name"]),
            values: None,
            intent_to_retain: None,
        }]);
        query.credentials[0].claim_sets = Some(vec![vec!["family_name".to_string()]]);

        let err = query.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidDcqlQuery);
    }

    #[test]
    fn credential_sets_must_reference_known_credentials() {
        let mut query = minimal_query();
        query.credential_sets = Some(vec![CredentialSetQuery {
            options: vec![vec!["unknown".to_string()]],
            required: None,
        }]);

        let err = query.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidDcqlQuery);
    }
}
