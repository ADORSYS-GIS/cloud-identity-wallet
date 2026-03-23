//! Credential Request Proof models for OpenID4VCI Appendix F.

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::errors::{Error, ErrorKind};

const JWT_PROOF_TYPE_HEADER: &str = "openid4vci-proof+jwt";

/// Proof type identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofType {
    Jwt,
    DiVp,
    Attestation,
}

/// JOSE header for JWT proof. Exactly one of `jwk`, `kid`, or `x5c` required.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwtProofHeader {
    /// MUST be `openid4vci-proof+jwt`.
    pub typ: String,
    /// Algorithm. MUST NOT be `none`.
    pub alg: String,
    /// JSON Web Key. Exactly one of `jwk`, `kid`, `x5c` required.
    pub jwk: Option<serde_json::Value>,
    /// Key ID (DID URL). Exactly one of `jwk`, `kid`, `x5c` required.
    pub kid: Option<String>,
    /// X.509 certificate chain. Exactly one of `jwk`, `kid`, `x5c` required.
    pub x5c: Option<Vec<String>>,
    /// Key attestation (Appendix D).
    pub key_attestation: Option<String>,
    /// OpenID Federation Trust Chain. Requires `kid` to be present.
    pub trust_chain: Option<String>,
}

impl JwtProofHeader {
    /// Validates: typ=openid4vci-proof+jwt, alg not empty/none, exactly one of jwk/kid/x5c, trust_chain requires kid.
    pub fn validate(&self) -> Result<(), Error> {
        if self.typ != JWT_PROOF_TYPE_HEADER {
            return Err(Error::message(
                ErrorKind::InvalidProof,
                format!(
                    "JWT proof typ must be '{}', got '{}'",
                    JWT_PROOF_TYPE_HEADER, self.typ
                ),
            ));
        }

        if self.alg.is_empty() || self.alg.eq_ignore_ascii_case("none") {
            return Err(Error::message(
                ErrorKind::InvalidProof,
                "JWT proof alg must not be empty or 'none'",
            ));
        }

        // Exactly one of jwk, kid, or x5c must be present
        let key_identifiers = [self.jwk.is_some(), self.kid.is_some(), self.x5c.is_some()];
        let present_count = key_identifiers.iter().filter(|&&v| v).count();

        if present_count == 0 {
            return Err(Error::message(
                ErrorKind::InvalidProof,
                "JWT proof header must contain exactly one of 'jwk', 'kid', or 'x5c'",
            ));
        }

        if present_count > 1 {
            return Err(Error::message(
                ErrorKind::InvalidProof,
                "JWT proof header must not contain more than one of 'jwk', 'kid', or 'x5c'",
            ));
        }

        // trust_chain requires kid to be present (per spec)
        if self.trust_chain.is_some() && self.kid.is_none() {
            return Err(Error::message(
                ErrorKind::InvalidProof,
                "JWT proof header with 'trust_chain' must also contain 'kid'",
            ));
        }

        Ok(())
    }
}

/// JWT payload claims. `nonce` carries c_nonce from Token Response or Nonce Endpoint.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwtProofClaims {
    /// Client ID. Omit for anonymous Pre-Authorized Code Flow.
    pub iss: Option<String>,
    /// Credential Issuer Identifier.
    pub aud: String,
    /// Issued-at timestamp.
    pub iat: i64,
    /// c_nonce value when required.
    pub nonce: Option<String>,
}

impl JwtProofClaims {
    pub fn validate(&self) -> Result<(), Error> {
        if self.aud.is_empty() {
            return Err(Error::message(
                ErrorKind::InvalidProof,
                "JWT proof 'aud' claim must not be empty",
            ));
        }

        if self.iat <= 0 {
            return Err(Error::message(
                ErrorKind::InvalidProof,
                "JWT proof 'iat' claim must be a positive Unix timestamp",
            ));
        }

        Ok(())
    }
}

/// Compact-serialized JWT string entry in `proofs.jwt` array.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwtProof {
    pub jwt: String,
}

impl JwtProof {
    pub fn validate(&self) -> Result<(), Error> {
        if self.jwt.is_empty() {
            return Err(Error::message(
                ErrorKind::InvalidProof,
                "JWT proof string must not be empty",
            ));
        }

        let parts: Vec<&str> = self.jwt.splitn(4, '.').collect();
        if parts.len() != 3 {
            return Err(Error::message(
                ErrorKind::InvalidProof,
                "JWT proof must be a compact serialization with three dot-separated parts",
            ));
        }

        Ok(())
    }
}

/// Data Integrity Proof. challenge required when c_nonce provided, MUST NOT be present otherwise.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataIntegrityProof {
    #[serde(rename = "type")]
    pub proof_type: String,
    /// MUST match proof_signing_alg_values_supported if issuer metadata provided.
    pub cryptosuite: String,
    /// MUST be "authentication".
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    pub created: String,
    /// c_nonce value. Required when issuer provided c_nonce, MUST NOT be present otherwise.
    pub challenge: Option<String>,
    /// Credential Issuer Identifier.
    pub domain: String,
    #[serde(rename = "proofValue")]
    pub proof_value: String,
}

impl DataIntegrityProof {
    pub fn validate(&self) -> Result<(), Error> {
        if self.cryptosuite.is_empty() {
            return Err(Error::message(
                ErrorKind::InvalidProof,
                "cryptosuite must not be empty",
            ));
        }
        if self.proof_purpose != "authentication" {
            return Err(Error::message(
                ErrorKind::InvalidProof,
                format!(
                    "proofPurpose must be 'authentication', got '{}'",
                    self.proof_purpose
                ),
            ));
        }
        if self.domain.is_empty() {
            return Err(Error::message(
                ErrorKind::InvalidProof,
                "domain must not be empty",
            ));
        }
        Ok(())
    }

    /// Validates challenge against c_nonce: required when c_nonce provided, MUST NOT be present otherwise.
    pub fn validate_with_nonce(&self, c_nonce: Option<&str>) -> Result<(), Error> {
        self.validate()?;
        match c_nonce {
            Some(expected) => match &self.challenge {
                Some(challenge) if challenge == expected => Ok(()),
                Some(challenge) => Err(Error::message(
                    ErrorKind::InvalidProof,
                    format!("challenge must match c_nonce, got '{}'", challenge),
                )),
                None => Err(Error::message(
                    ErrorKind::InvalidProof,
                    "challenge required when c_nonce provided",
                )),
            },
            None => {
                if self.challenge.is_some() {
                    return Err(Error::message(
                        ErrorKind::InvalidProof,
                        "challenge MUST NOT be present when no c_nonce provided",
                    ));
                }
                Ok(())
            }
        }
    }
}

/// W3C Verifiable Presentation with Data Integrity proof.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiVpProof {
    /// Holder DID. If present, must match controller of verificationMethod.
    pub holder: Option<String>,
    /// Data Integrity proofs. At least one required.
    pub proof: Vec<DataIntegrityProof>,
}

impl DiVpProof {
    pub fn validate(&self) -> Result<(), Error> {
        if self.proof.is_empty() {
            return Err(Error::message(
                ErrorKind::InvalidProof,
                "di_vp must contain at least one proof",
            ));
        }
        for proof in &self.proof {
            proof.validate()?;
        }
        Ok(())
    }

    /// Validates challenge against c_nonce for all proofs.
    pub fn validate_with_nonce(&self, c_nonce: Option<&str>) -> Result<(), Error> {
        if self.proof.is_empty() {
            return Err(Error::message(
                ErrorKind::InvalidProof,
                "di_vp must contain at least one proof",
            ));
        }
        for proof in &self.proof {
            proof.validate_with_nonce(c_nonce)?;
        }
        Ok(())
    }
}

/// Key attestation JWT. typ header must be openid4vci-proof+jwt with key_attestation header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationProof {
    pub attestation: String,
}

impl AttestationProof {
    pub fn validate(&self) -> Result<(), Error> {
        if self.attestation.is_empty() {
            return Err(Error::message(
                ErrorKind::InvalidProof,
                "attestation must not be empty",
            ));
        }
        let parts: Vec<&str> = self.attestation.splitn(4, '.').collect();
        if parts.len() != 3 {
            return Err(Error::message(
                ErrorKind::InvalidProof,
                "attestation must be compact JWT with three parts",
            ));
        }
        Ok(())
    }
}

/// Credential Request proofs. Exactly one proof type required.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proofs {
    pub jwt: Option<Vec<JwtProof>>,
    pub di_vp: Option<Vec<DiVpProof>>,
    pub attestation: Option<Vec<AttestationProof>>,
}

impl Proofs {
    pub fn validate(&self) -> Result<(), Error> {
        let present_count = [
            self.jwt.is_some(),
            self.di_vp.is_some(),
            self.attestation.is_some(),
        ]
        .into_iter()
        .filter(|v| *v)
        .count();

        if present_count == 0 {
            return Err(Error::message(
                ErrorKind::InvalidProof,
                "proofs must contain exactly one proof type",
            ));
        }
        if present_count > 1 {
            return Err(Error::message(
                ErrorKind::InvalidProof,
                "proofs must contain exactly one proof type",
            ));
        }

        if let Some(ref proofs) = self.jwt {
            if proofs.is_empty() {
                return Err(Error::message(
                    ErrorKind::InvalidProof,
                    "proofs.jwt must not be empty",
                ));
            }
            for proof in proofs {
                proof.validate()?;
            }
        }

        if let Some(ref proofs) = self.di_vp {
            if proofs.is_empty() {
                return Err(Error::message(
                    ErrorKind::InvalidProof,
                    "proofs.di_vp must not be empty",
                ));
            }
            for proof in proofs {
                proof.validate()?;
            }
        }

        if let Some(ref proofs) = self.attestation {
            if proofs.is_empty() {
                return Err(Error::message(
                    ErrorKind::InvalidProof,
                    "proofs.attestation must not be empty",
                ));
            }
            for proof in proofs {
                proof.validate()?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_jwt_proof_header_with_jwk() {
        let header = JwtProofHeader {
            typ: "openid4vci-proof+jwt".to_string(),
            alg: "ES256".to_string(),
            jwk: Some(serde_json::json!({"kty": "EC"})),
            kid: None,
            x5c: None,
            key_attestation: None,
            trust_chain: None,
        };
        assert!(header.validate().is_ok());
    }

    #[test]
    fn valid_jwt_proof_header_with_kid() {
        let header = JwtProofHeader {
            typ: "openid4vci-proof+jwt".to_string(),
            alg: "ES256".to_string(),
            jwk: None,
            kid: Some("key-1".to_string()),
            x5c: None,
            key_attestation: None,
            trust_chain: None,
        };
        assert!(header.validate().is_ok());
    }

    #[test]
    fn valid_jwt_proof_header_with_x5c() {
        let header = JwtProofHeader {
            typ: "openid4vci-proof+jwt".to_string(),
            alg: "ES256".to_string(),
            jwk: None,
            kid: None,
            x5c: Some(vec!["MIIBk...".to_string()]),
            key_attestation: None,
            trust_chain: None,
        };
        assert!(header.validate().is_ok());
    }

    #[test]
    fn valid_jwt_proof_header_with_key_attestation() {
        let header = JwtProofHeader {
            typ: "openid4vci-proof+jwt".to_string(),
            alg: "ES256".to_string(),
            jwk: None,
            kid: Some("0".to_string()),
            x5c: None,
            key_attestation: Some("eyJ...".to_string()),
            trust_chain: None,
        };
        assert!(header.validate().is_ok());
    }

    #[test]
    fn valid_jwt_proof_header_with_trust_chain() {
        let header = JwtProofHeader {
            typ: "openid4vci-proof+jwt".to_string(),
            alg: "ES256".to_string(),
            jwk: None,
            kid: Some("key-1".to_string()),
            x5c: None,
            key_attestation: None,
            trust_chain: Some("eyJ...".to_string()),
        };
        assert!(header.validate().is_ok());
    }

    #[test]
    fn rejects_wrong_typ() {
        let header = JwtProofHeader {
            typ: "JWT".to_string(),
            alg: "ES256".to_string(),
            jwk: None,
            kid: Some("key-1".to_string()),
            x5c: None,
            key_attestation: None,
            trust_chain: None,
        };
        let err = header.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidProof);
        assert!(err.to_string().contains("openid4vci-proof+jwt"));
    }

    #[test]
    fn rejects_empty_alg() {
        let header = JwtProofHeader {
            typ: "openid4vci-proof+jwt".to_string(),
            alg: String::new(),
            jwk: None,
            kid: Some("key-1".to_string()),
            x5c: None,
            key_attestation: None,
            trust_chain: None,
        };
        assert_eq!(
            header.validate().unwrap_err().kind(),
            ErrorKind::InvalidProof
        );
    }

    #[test]
    fn rejects_alg_none() {
        let header = JwtProofHeader {
            typ: "openid4vci-proof+jwt".to_string(),
            alg: "none".to_string(),
            jwk: None,
            kid: Some("key-1".to_string()),
            x5c: None,
            key_attestation: None,
            trust_chain: None,
        };
        assert_eq!(
            header.validate().unwrap_err().kind(),
            ErrorKind::InvalidProof
        );
    }

    #[test]
    fn rejects_multiple_key_identifiers() {
        // jwk + kid
        let header = JwtProofHeader {
            typ: "openid4vci-proof+jwt".to_string(),
            alg: "ES256".to_string(),
            jwk: Some(serde_json::json!({"kty": "EC"})),
            kid: Some("key-1".to_string()),
            x5c: None,
            key_attestation: None,
            trust_chain: None,
        };
        let err = header.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidProof);
        assert!(err.to_string().contains("more than one"));
    }

    #[test]
    fn rejects_jwk_and_x5c() {
        let header = JwtProofHeader {
            typ: "openid4vci-proof+jwt".to_string(),
            alg: "ES256".to_string(),
            jwk: Some(serde_json::json!({"kty": "EC"})),
            kid: None,
            x5c: Some(vec!["MIIBk...".to_string()]),
            key_attestation: None,
            trust_chain: None,
        };
        let err = header.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidProof);
        assert!(err.to_string().contains("more than one"));
    }

    #[test]
    fn rejects_kid_and_x5c() {
        let header = JwtProofHeader {
            typ: "openid4vci-proof+jwt".to_string(),
            alg: "ES256".to_string(),
            jwk: None,
            kid: Some("key-1".to_string()),
            x5c: Some(vec!["MIIBk...".to_string()]),
            key_attestation: None,
            trust_chain: None,
        };
        let err = header.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidProof);
        assert!(err.to_string().contains("more than one"));
    }

    #[test]
    fn rejects_no_key_identifier() {
        let header = JwtProofHeader {
            typ: "openid4vci-proof+jwt".to_string(),
            alg: "ES256".to_string(),
            jwk: None,
            kid: None,
            x5c: None,
            key_attestation: None,
            trust_chain: None,
        };
        let err = header.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidProof);
        assert!(err.to_string().contains("exactly one"));
    }

    #[test]
    fn rejects_trust_chain_without_kid() {
        let header = JwtProofHeader {
            typ: "openid4vci-proof+jwt".to_string(),
            alg: "ES256".to_string(),
            jwk: Some(serde_json::json!({"kty": "EC"})),
            kid: None,
            x5c: None,
            key_attestation: None,
            trust_chain: Some("eyJ...".to_string()),
        };
        let err = header.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidProof);
        assert!(err.to_string().contains("trust_chain") && err.to_string().contains("kid"));
    }

    // ── JwtProofClaims ────────────────────────────────────────────────────────

    #[test]
    fn valid_jwt_proof_claims_without_nonce() {
        let claims = JwtProofClaims {
            iss: None,
            aud: "https://issuer.example.com".to_string(),
            iat: 1700000000,
            nonce: None,
        };
        assert!(claims.validate().is_ok());
    }

    #[test]
    fn valid_jwt_proof_claims_with_nonce() {
        let claims = JwtProofClaims {
            iss: None,
            aud: "https://issuer.example.com".to_string(),
            iat: 1700000000,
            nonce: Some("wKI4LT17ac15ES9bw8ac4".to_string()),
        };
        assert!(claims.validate().is_ok());
    }

    #[test]
    fn valid_jwt_proof_claims_with_iss() {
        let claims = JwtProofClaims {
            iss: Some("s6BhdRkqt3".to_string()),
            aud: "https://issuer.example.com".to_string(),
            iat: 1700000000,
            nonce: Some("tZignsnFbp".to_string()),
        };
        assert!(claims.validate().is_ok());
    }

    #[test]
    fn rejects_empty_aud() {
        let claims = JwtProofClaims {
            iss: None,
            aud: String::new(),
            iat: 1700000000,
            nonce: None,
        };
        let err = claims.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidProof);
        assert!(err.to_string().contains("aud"));
    }

    #[test]
    fn rejects_zero_iat() {
        let claims = JwtProofClaims {
            iss: None,
            aud: "https://issuer.example.com".to_string(),
            iat: 0,
            nonce: None,
        };
        let err = claims.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidProof);
        assert!(err.to_string().contains("iat"));
    }

    #[test]
    fn rejects_negative_iat() {
        let claims = JwtProofClaims {
            iss: None,
            aud: "https://issuer.example.com".to_string(),
            iat: -1,
            nonce: None,
        };
        assert_eq!(
            claims.validate().unwrap_err().kind(),
            ErrorKind::InvalidProof
        );
    }

    #[test]
    fn nonce_skipped_when_absent() {
        let claims = JwtProofClaims {
            iss: None,
            aud: "https://issuer.example.com".to_string(),
            iat: 1700000000,
            nonce: None,
        };
        let json = serde_json::to_string(&claims).unwrap();
        assert!(!json.contains("nonce"));
    }

    #[test]
    fn nonce_present_when_set() {
        let claims = JwtProofClaims {
            iss: None,
            aud: "https://issuer.example.com".to_string(),
            iat: 1700000000,
            nonce: Some("abc123".to_string()),
        };
        let json = serde_json::to_string(&claims).unwrap();
        assert!(json.contains("\"nonce\":\"abc123\""));
    }

    #[test]
    fn iss_skipped_when_absent() {
        let claims = JwtProofClaims {
            iss: None,
            aud: "https://issuer.example.com".to_string(),
            iat: 1700000000,
            nonce: None,
        };
        let json = serde_json::to_string(&claims).unwrap();
        // Check for "iss" as a JSON key, not just substring (issuer contains "iss")
        assert!(!json.contains("\"iss\":"));
    }

    #[test]
    fn iss_present_when_set() {
        let claims = JwtProofClaims {
            iss: Some("client123".to_string()),
            aud: "https://issuer.example.com".to_string(),
            iat: 1700000000,
            nonce: None,
        };
        let json = serde_json::to_string(&claims).unwrap();
        assert!(json.contains("\"iss\":\"client123\""));
    }

    // ── JwtProof ──────────────────────────────────────────────────────────────

    #[test]
    fn valid_jwt_proof_entry() {
        let proof = JwtProof {
            jwt: "aaa.bbb.ccc".to_string(),
        };
        assert!(proof.validate().is_ok());
    }

    #[test]
    fn rejects_empty_jwt_string() {
        let proof = JwtProof { jwt: String::new() };
        assert_eq!(
            proof.validate().unwrap_err().kind(),
            ErrorKind::InvalidProof
        );
    }

    #[test]
    fn rejects_jwt_without_three_parts() {
        let proof = JwtProof {
            jwt: "aaa.bbb".to_string(),
        };
        let err = proof.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidProof);
        assert!(err.to_string().contains("three"));
    }

    // ── DiVpProof ─────────────────────────────────────────────────────────────

    #[test]
    fn valid_di_vp_proof() {
        let proof = DiVpProof {
            holder: Some("did:key:z6MkvrFpBNCoYewiaeBLgjUDvLxUtnK5R6mqh5XPvLsrPsro".to_string()),
            proof: vec![DataIntegrityProof {
                proof_type: "DataIntegrityProof".to_string(),
                cryptosuite: "eddsa-2022".to_string(),
                proof_purpose: "authentication".to_string(),
                verification_method: "did:key:z6Mk#z6Mk".to_string(),
                created: "2023-03-01T14:56:29.280619Z".to_string(),
                challenge: Some("wKI4LT17ac15ES9bw8ac4".to_string()),
                domain: "https://issuer.example.com".to_string(),
                proof_value: "z5hrbHz".to_string(),
            }],
        };
        assert!(proof.validate().is_ok());
    }

    #[test]
    fn valid_di_vp_proof_without_holder() {
        let proof = DiVpProof {
            holder: None,
            proof: vec![DataIntegrityProof {
                proof_type: "DataIntegrityProof".to_string(),
                cryptosuite: "eddsa-2022".to_string(),
                proof_purpose: "authentication".to_string(),
                verification_method: "did:key:z6Mk#z6Mk".to_string(),
                created: "2023-03-01T14:56:29.280619Z".to_string(),
                challenge: None,
                domain: "https://issuer.example.com".to_string(),
                proof_value: "z5hrbHz".to_string(),
            }],
        };
        assert!(proof.validate().is_ok());
    }

    #[test]
    fn rejects_di_vp_proof_empty_proof_array() {
        let proof = DiVpProof {
            holder: None,
            proof: vec![],
        };
        let err = proof.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidProof);
        assert!(err.to_string().contains("at least one"));
    }

    #[test]
    fn rejects_di_vp_proof_wrong_proof_purpose() {
        let proof = DiVpProof {
            holder: None,
            proof: vec![DataIntegrityProof {
                proof_type: "DataIntegrityProof".to_string(),
                cryptosuite: "eddsa-2022".to_string(),
                proof_purpose: "assertionMethod".to_string(), // wrong value
                verification_method: "did:key:z6Mk#z6Mk".to_string(),
                created: "2023-03-01T14:56:29.280619Z".to_string(),
                challenge: None,
                domain: "https://issuer.example.com".to_string(),
                proof_value: "z5hrbHz".to_string(),
            }],
        };
        let err = proof.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidProof);
        assert!(err.to_string().contains("authentication"));
    }

    #[test]
    fn rejects_di_vp_proof_empty_cryptosuite() {
        let proof = DiVpProof {
            holder: None,
            proof: vec![DataIntegrityProof {
                proof_type: "DataIntegrityProof".to_string(),
                cryptosuite: String::new(),
                proof_purpose: "authentication".to_string(),
                verification_method: "did:key:z6Mk#z6Mk".to_string(),
                created: "2023-03-01T14:56:29.280619Z".to_string(),
                challenge: None,
                domain: "https://issuer.example.com".to_string(),
                proof_value: "z5hrbHz".to_string(),
            }],
        };
        let err = proof.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidProof);
        assert!(err.to_string().contains("cryptosuite"));
    }

    #[test]
    fn rejects_di_vp_proof_empty_domain() {
        let proof = DiVpProof {
            holder: None,
            proof: vec![DataIntegrityProof {
                proof_type: "DataIntegrityProof".to_string(),
                cryptosuite: "eddsa-2022".to_string(),
                proof_purpose: "authentication".to_string(),
                verification_method: "did:key:z6Mk#z6Mk".to_string(),
                created: "2023-03-01T14:56:29.280619Z".to_string(),
                challenge: None,
                domain: String::new(),
                proof_value: "z5hrbHz".to_string(),
            }],
        };
        let err = proof.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidProof);
        assert!(err.to_string().contains("domain"));
    }

    #[test]
    fn di_vp_proof_deserializes_from_spec_example() {
        // Non-normative example from spec §8.2
        let json = r#"{
            "holder": "did:key:z6MkvrFpBNCoYewiaeBLgjUDvLxUtnK5R6mqh5XPvLsrPsro",
            "proof": [{
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-2022",
                "proofPurpose": "authentication",
                "verificationMethod": "did:key:z6Mk#z6Mk",
                "created": "2023-03-01T14:56:29.280619Z",
                "challenge": "82d4cb36-11f6-4273-b9c6-df1ac0ff17e9",
                "domain": "did:web:audience.company.com",
                "proofValue": "z5hrbHzZ"
            }]
        }"#;
        let proof: DiVpProof = serde_json::from_str(json).unwrap();
        assert!(proof.validate().is_ok());
        assert_eq!(
            proof.holder,
            Some("did:key:z6MkvrFpBNCoYewiaeBLgjUDvLxUtnK5R6mqh5XPvLsrPsro".to_string())
        );
        assert_eq!(proof.proof.len(), 1);
        assert_eq!(proof.proof[0].cryptosuite, "eddsa-2022");
    }

    #[test]
    fn di_vp_proof_serializes_correctly() {
        let proof = DiVpProof {
            holder: Some("did:key:z6Mk".to_string()),
            proof: vec![DataIntegrityProof {
                proof_type: "DataIntegrityProof".to_string(),
                cryptosuite: "eddsa-2022".to_string(),
                proof_purpose: "authentication".to_string(),
                verification_method: "did:key:z6Mk#z6Mk".to_string(),
                created: "2023-03-01T14:56:29.280619Z".to_string(),
                challenge: Some("abc123".to_string()),
                domain: "https://issuer.example.com".to_string(),
                proof_value: "z5hrbHz".to_string(),
            }],
        };
        let json = serde_json::to_string(&proof).unwrap();
        assert!(json.contains("\"holder\""));
        assert!(json.contains("\"proof\""));
        assert!(json.contains("\"type\":\"DataIntegrityProof\""));
        assert!(json.contains("\"cryptosuite\":\"eddsa-2022\""));
    }

    // ── DataIntegrityProof nonce validation ─────────────────────────────────────

    #[test]
    fn validate_with_nonce_matches() {
        let proof = DataIntegrityProof {
            proof_type: "DataIntegrityProof".to_string(),
            cryptosuite: "eddsa-2022".to_string(),
            proof_purpose: "authentication".to_string(),
            verification_method: "did:key:z6Mk#z6Mk".to_string(),
            created: "2023-03-01T14:56:29.280619Z".to_string(),
            challenge: Some("server-nonce-123".to_string()),
            domain: "https://issuer.example.com".to_string(),
            proof_value: "z5hrbHz".to_string(),
        };
        assert!(proof.validate_with_nonce(Some("server-nonce-123")).is_ok());
    }

    #[test]
    fn validate_with_nonce_missing_challenge() {
        let proof = DataIntegrityProof {
            proof_type: "DataIntegrityProof".to_string(),
            cryptosuite: "eddsa-2022".to_string(),
            proof_purpose: "authentication".to_string(),
            verification_method: "did:key:z6Mk#z6Mk".to_string(),
            created: "2023-03-01T14:56:29.280619Z".to_string(),
            challenge: None, // missing
            domain: "https://issuer.example.com".to_string(),
            proof_value: "z5hrbHz".to_string(),
        };
        let err = proof
            .validate_with_nonce(Some("server-nonce-123"))
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidProof);
        assert!(err.to_string().contains("challenge"));
        assert!(err.to_string().contains("required"));
    }

    #[test]
    fn validate_with_nonce_wrong_challenge() {
        let proof = DataIntegrityProof {
            proof_type: "DataIntegrityProof".to_string(),
            cryptosuite: "eddsa-2022".to_string(),
            proof_purpose: "authentication".to_string(),
            verification_method: "did:key:z6Mk#z6Mk".to_string(),
            created: "2023-03-01T14:56:29.280619Z".to_string(),
            challenge: Some("wrong-nonce".to_string()),
            domain: "https://issuer.example.com".to_string(),
            proof_value: "z5hrbHz".to_string(),
        };
        let err = proof
            .validate_with_nonce(Some("server-nonce-123"))
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidProof);
        assert!(err.to_string().contains("must match"));
    }

    #[test]
    fn validate_without_nonce_ok() {
        let proof = DataIntegrityProof {
            proof_type: "DataIntegrityProof".to_string(),
            cryptosuite: "eddsa-2022".to_string(),
            proof_purpose: "authentication".to_string(),
            verification_method: "did:key:z6Mk#z6Mk".to_string(),
            created: "2023-03-01T14:56:29.280619Z".to_string(),
            challenge: None, // no challenge - ok when no c_nonce
            domain: "https://issuer.example.com".to_string(),
            proof_value: "z5hrbHz".to_string(),
        };
        assert!(proof.validate_with_nonce(None).is_ok());
    }

    #[test]
    fn validate_without_nonce_rejects_challenge() {
        let proof = DataIntegrityProof {
            proof_type: "DataIntegrityProof".to_string(),
            cryptosuite: "eddsa-2022".to_string(),
            proof_purpose: "authentication".to_string(),
            verification_method: "did:key:z6Mk#z6Mk".to_string(),
            created: "2023-03-01T14:56:29.280619Z".to_string(),
            challenge: Some("unexpected".to_string()), // MUST NOT be present
            domain: "https://issuer.example.com".to_string(),
            proof_value: "z5hrbHz".to_string(),
        };
        let err = proof.validate_with_nonce(None).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidProof);
        assert!(err.to_string().contains("MUST NOT be present"));
    }

    #[test]
    fn di_vp_validate_with_nonce() {
        let proof = DiVpProof {
            holder: None,
            proof: vec![DataIntegrityProof {
                proof_type: "DataIntegrityProof".to_string(),
                cryptosuite: "eddsa-2022".to_string(),
                proof_purpose: "authentication".to_string(),
                verification_method: "did:key:z6Mk#z6Mk".to_string(),
                created: "2023-03-01T14:56:29.280619Z".to_string(),
                challenge: Some("server-nonce".to_string()),
                domain: "https://issuer.example.com".to_string(),
                proof_value: "z5hrbHz".to_string(),
            }],
        };
        assert!(proof.validate_with_nonce(Some("server-nonce")).is_ok());
    }

    #[test]
    fn di_vp_validate_without_nonce() {
        let proof = DiVpProof {
            holder: None,
            proof: vec![DataIntegrityProof {
                proof_type: "DataIntegrityProof".to_string(),
                cryptosuite: "eddsa-2022".to_string(),
                proof_purpose: "authentication".to_string(),
                verification_method: "did:key:z6Mk#z6Mk".to_string(),
                created: "2023-03-01T14:56:29.280619Z".to_string(),
                challenge: None,
                domain: "https://issuer.example.com".to_string(),
                proof_value: "z5hrbHz".to_string(),
            }],
        };
        assert!(proof.validate_with_nonce(None).is_ok());
    }

    // ── AttestationProof ──────────────────────────────────────────────────────

    #[test]
    fn valid_attestation_proof() {
        let proof = AttestationProof {
            attestation: "aaa.bbb.ccc".to_string(),
        };
        assert!(proof.validate().is_ok());
    }

    #[test]
    fn rejects_empty_attestation_string() {
        let proof = AttestationProof {
            attestation: String::new(),
        };
        assert_eq!(
            proof.validate().unwrap_err().kind(),
            ErrorKind::InvalidProof
        );
    }

    #[test]
    fn rejects_attestation_without_three_parts() {
        let proof = AttestationProof {
            attestation: "aaa.bbb".to_string(),
        };
        let err = proof.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidProof);
        assert!(err.to_string().contains("three"));
    }

    #[test]
    fn attestation_proof_serializes_with_attestation_key() {
        let proof = AttestationProof {
            attestation: "aaa.bbb.ccc".to_string(),
        };
        let json = serde_json::to_string(&proof).unwrap();
        assert!(json.contains("\"attestation\":\"aaa.bbb.ccc\""));
    }

    #[test]
    fn attestation_proof_deserializes_correctly() {
        let json = r#"{"attestation":"aaa.bbb.ccc"}"#;
        let proof: AttestationProof = serde_json::from_str(json).unwrap();
        assert_eq!(proof.attestation, "aaa.bbb.ccc");
    }

    // ── Proofs ────────────────────────────────────────────────────────────────

    #[test]
    fn valid_proofs_with_single_jwt() {
        let proofs = Proofs {
            jwt: Some(vec![JwtProof {
                jwt: "aaa.bbb.ccc".to_string(),
            }]),
            di_vp: None,
            attestation: None,
        };
        assert!(proofs.validate().is_ok());
    }

    #[test]
    fn valid_proofs_with_multiple_jwts() {
        let proofs = Proofs {
            jwt: Some(vec![
                JwtProof {
                    jwt: "aaa.bbb.ccc".to_string(),
                },
                JwtProof {
                    jwt: "ddd.eee.fff".to_string(),
                },
            ]),
            di_vp: None,
            attestation: None,
        };
        assert!(proofs.validate().is_ok());
    }

    #[test]
    fn valid_proofs_with_single_di_vp() {
        let proofs = Proofs {
            jwt: None,
            di_vp: Some(vec![DiVpProof {
                holder: None,
                proof: vec![DataIntegrityProof {
                    proof_type: "DataIntegrityProof".to_string(),
                    cryptosuite: "eddsa-2022".to_string(),
                    proof_purpose: "authentication".to_string(),
                    verification_method: "did:key:z6Mk#z6Mk".to_string(),
                    created: "2023-03-01T14:56:29.280619Z".to_string(),
                    challenge: None,
                    domain: "https://issuer.example.com".to_string(),
                    proof_value: "z5hrbHz".to_string(),
                }],
            }]),
            attestation: None,
        };
        assert!(proofs.validate().is_ok());
    }

    #[test]
    fn valid_proofs_with_single_attestation() {
        let proofs = Proofs {
            jwt: None,
            di_vp: None,
            attestation: Some(vec![AttestationProof {
                attestation: "aaa.bbb.ccc".to_string(),
            }]),
        };
        assert!(proofs.validate().is_ok());
    }

    #[test]
    fn rejects_proofs_with_no_proof_type() {
        let proofs = Proofs {
            jwt: None,
            di_vp: None,
            attestation: None,
        };
        let err = proofs.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidProof);
        assert!(err.to_string().contains("exactly one"));
    }

    #[test]
    fn rejects_proofs_with_multiple_proof_types() {
        // Spec §8.2: "exactly one parameter named as the proof type"
        let proofs = Proofs {
            jwt: Some(vec![JwtProof {
                jwt: "aaa.bbb.ccc".to_string(),
            }]),
            di_vp: Some(vec![DiVpProof {
                holder: None,
                proof: vec![DataIntegrityProof {
                    proof_type: "DataIntegrityProof".to_string(),
                    cryptosuite: "eddsa-2022".to_string(),
                    proof_purpose: "authentication".to_string(),
                    verification_method: "did:key:z6Mk#z6Mk".to_string(),
                    created: "2023-03-01T14:56:29.280619Z".to_string(),
                    challenge: None,
                    domain: "https://issuer.example.com".to_string(),
                    proof_value: "z5hrbHz".to_string(),
                }],
            }]),
            attestation: None,
        };
        let err = proofs.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidProof);
        assert!(err.to_string().contains("exactly one"));
    }

    #[test]
    fn rejects_empty_jwt_array() {
        let proofs = Proofs {
            jwt: Some(vec![]),
            di_vp: None,
            attestation: None,
        };
        let err = proofs.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidProof);
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn rejects_empty_di_vp_array() {
        let proofs = Proofs {
            jwt: None,
            di_vp: Some(vec![]),
            attestation: None,
        };
        let err = proofs.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidProof);
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn rejects_empty_attestation_array() {
        let proofs = Proofs {
            jwt: None,
            di_vp: None,
            attestation: Some(vec![]),
        };
        let err = proofs.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidProof);
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn invalid_jwt_entry_propagates_error() {
        let proofs = Proofs {
            jwt: Some(vec![JwtProof {
                jwt: "not-a-valid-jwt".to_string(),
            }]),
            di_vp: None,
            attestation: None,
        };
        assert_eq!(
            proofs.validate().unwrap_err().kind(),
            ErrorKind::InvalidProof
        );
    }

    #[test]
    fn invalid_di_vp_entry_propagates_error() {
        let proofs = Proofs {
            jwt: None,
            di_vp: Some(vec![DiVpProof {
                holder: None,
                proof: vec![], // empty proof array
            }]),
            attestation: None,
        };
        assert_eq!(
            proofs.validate().unwrap_err().kind(),
            ErrorKind::InvalidProof
        );
    }

    #[test]
    fn invalid_attestation_entry_propagates_error() {
        let proofs = Proofs {
            jwt: None,
            di_vp: None,
            attestation: Some(vec![AttestationProof {
                attestation: "bad".to_string(),
            }]),
        };
        assert_eq!(
            proofs.validate().unwrap_err().kind(),
            ErrorKind::InvalidProof
        );
    }

    // ── Proofs serialization ──────────────────────────────────────────────────

    #[test]
    fn proofs_serializes_jwt_key_only() {
        let proofs = Proofs {
            jwt: Some(vec![JwtProof {
                jwt: "aaa.bbb.ccc".to_string(),
            }]),
            di_vp: None,
            attestation: None,
        };
        let json = serde_json::to_string(&proofs).unwrap();
        assert!(json.contains("\"jwt\""));
        assert!(json.contains("aaa.bbb.ccc"));
        assert!(!json.contains("\"di_vp\""));
        assert!(!json.contains("\"attestation\""));
    }

    #[test]
    fn proofs_serializes_di_vp_key_only() {
        let proofs = Proofs {
            jwt: None,
            di_vp: Some(vec![DiVpProof {
                holder: Some("did:key:z6Mk".to_string()),
                proof: vec![DataIntegrityProof {
                    proof_type: "DataIntegrityProof".to_string(),
                    cryptosuite: "eddsa-2022".to_string(),
                    proof_purpose: "authentication".to_string(),
                    verification_method: "did:key:z6Mk#z6Mk".to_string(),
                    created: "2023-03-01T14:56:29.280619Z".to_string(),
                    challenge: None,
                    domain: "https://issuer.example.com".to_string(),
                    proof_value: "z5hrbHz".to_string(),
                }],
            }]),
            attestation: None,
        };
        let json = serde_json::to_string(&proofs).unwrap();
        assert!(json.contains("\"di_vp\""));
        assert!(!json.contains("\"jwt\""));
        assert!(!json.contains("\"attestation\""));
    }

    #[test]
    fn proofs_serializes_attestation_key_only() {
        let proofs = Proofs {
            jwt: None,
            di_vp: None,
            attestation: Some(vec![AttestationProof {
                attestation: "aaa.bbb.ccc".to_string(),
            }]),
        };
        let json = serde_json::to_string(&proofs).unwrap();
        assert!(json.contains("\"attestation\""));
        assert!(!json.contains("\"jwt\""));
        assert!(!json.contains("\"di_vp\""));
    }

    // ── ProofType enum ────────────────────────────────────────────────────────

    #[test]
    fn proof_type_serializes_to_snake_case() {
        assert_eq!(serde_json::to_string(&ProofType::Jwt).unwrap(), "\"jwt\"");
        assert_eq!(
            serde_json::to_string(&ProofType::DiVp).unwrap(),
            "\"di_vp\""
        );
        assert_eq!(
            serde_json::to_string(&ProofType::Attestation).unwrap(),
            "\"attestation\""
        );
    }

    #[test]
    fn proof_type_deserializes_from_snake_case() {
        let t: ProofType = serde_json::from_str("\"jwt\"").unwrap();
        assert_eq!(t, ProofType::Jwt);
        let t: ProofType = serde_json::from_str("\"di_vp\"").unwrap();
        assert_eq!(t, ProofType::DiVp);
        let t: ProofType = serde_json::from_str("\"attestation\"").unwrap();
        assert_eq!(t, ProofType::Attestation);
    }
}
