use serde::{Deserialize, Serialize};

use crate::{
    errors::{Error, ErrorKind},
    utils::{
        deserialize_non_empty_object_vec, deserialize_non_empty_string_vec,
        deserialize_single_attestation,
    },
};

/// The `proofs` object defined by OpenID4VCI §8.2.1.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proofs {
    #[serde(flatten)]
    inner: ProofsInner,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
enum ProofsInner {
    Jwt(JwtProofs),
    DiVp(DiVpProofs),
    Attestation(AttestationProofs),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JwtProofs {
    #[serde(deserialize_with = "deserialize_non_empty_string_vec")]
    jwt: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiVpProofs {
    #[serde(deserialize_with = "deserialize_non_empty_object_vec")]
    di_vp: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttestationProofs {
    #[serde(deserialize_with = "deserialize_single_attestation")]
    attestation: [String; 1],
}

impl Proofs {
    /// Creates a `proofs.jwt` array.
    pub fn jwt<I, S>(proofs: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            inner: ProofsInner::Jwt(JwtProofs {
                jwt: proofs.into_iter().map(Into::into).collect(),
            }),
        }
    }

    /// Creates a `proofs.di_vp` array.
    pub fn di_vp<I>(proofs: I) -> Self
    where
        I: IntoIterator<Item = serde_json::Value>,
    {
        Self {
            inner: ProofsInner::DiVp(DiVpProofs {
                di_vp: proofs.into_iter().collect(),
            }),
        }
    }

    /// Creates a single-entry `proofs.attestation` array.
    pub fn attestation(attestation: impl Into<String>) -> Self {
        Self {
            inner: ProofsInner::Attestation(AttestationProofs {
                attestation: [attestation.into()],
            }),
        }
    }

    /// Returns the total number of proof entries for the active proof type.
    pub fn len(&self) -> usize {
        match &self.inner {
            ProofsInner::Jwt(proofs) => proofs.jwt.len(),
            ProofsInner::DiVp(proofs) => proofs.di_vp.len(),
            ProofsInner::Attestation(_) => 1,
        }
    }

    /// Returns true when the active proof list has no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the JWT proof entries when the active proof type is `jwt`.
    pub fn jwt_proofs(&self) -> Option<&[String]> {
        match &self.inner {
            ProofsInner::Jwt(proofs) => Some(&proofs.jwt),
            ProofsInner::DiVp(_) | ProofsInner::Attestation(_) => None,
        }
    }

    /// Returns the Data Integrity proof entries when the active proof type is `di_vp`.
    pub fn di_vp_proofs(&self) -> Option<&[serde_json::Value]> {
        match &self.inner {
            ProofsInner::DiVp(proofs) => Some(&proofs.di_vp),
            ProofsInner::Jwt(_) | ProofsInner::Attestation(_) => None,
        }
    }

    /// Returns the attestation proof when the active proof type is `attestation`.
    pub fn attestation_proof(&self) -> Option<&str> {
        match &self.inner {
            ProofsInner::Attestation(proofs) => Some(&proofs.attestation[0]),
            ProofsInner::Jwt(_) | ProofsInner::DiVp(_) => None,
        }
    }

    fn validation_error(&self) -> Option<&'static str> {
        match &self.inner {
            ProofsInner::Jwt(proofs) if proofs.jwt.is_empty() => {
                Some("jwt proofs must contain at least one entry")
            }
            ProofsInner::Jwt(proofs) if proofs.jwt.iter().any(String::is_empty) => {
                Some("jwt proofs must not contain empty entries")
            }
            ProofsInner::DiVp(proofs) if proofs.di_vp.is_empty() => {
                Some("di_vp proofs must contain at least one entry")
            }
            ProofsInner::DiVp(proofs) if proofs.di_vp.iter().any(|value| !value.is_object()) => {
                Some("di_vp proofs must contain JSON objects")
            }
            ProofsInner::Attestation(proofs) if proofs.attestation[0].is_empty() => {
                Some("attestation proof must not be empty")
            }
            _ => None,
        }
    }

    /// Validates that the populated proof-type entry is spec-compliant.
    pub fn validate(&self) -> Result<(), Error> {
        if let Some(message) = self.validation_error() {
            return Err(invalid_credential_request(message));
        }

        Ok(())
    }
}

fn invalid_credential_request(message: impl Into<String>) -> Error {
    Error::message(ErrorKind::InvalidCredentialRequest, message.into())
}
