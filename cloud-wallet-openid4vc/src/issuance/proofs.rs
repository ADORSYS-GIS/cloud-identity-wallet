//! Credential Request Proof data models for OpenID4VCI.
//!
//! This module implements the data models required to represent credential
//! request proofs as defined in
//! [OpenID4VCI Appendix F](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-proof-types)
//! and the `proofs` parameter defined in
//! [OpenID4VCI Section 8.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-request).
//!
//! # Note on `c_nonce`
//!
//! The `nonce` claim inside a JWT proof carries a `c_nonce` value obtained
//! either from the Nonce Endpoint or from the Token Response. The Token
//! Response model will be introduced in Ticket 3 (AS Metadata). Until then,
//! `nonce` is represented as a plain `Option<String>` and callers are
//! responsible for supplying the correct value.

use serde::{Deserialize, Serialize};

use crate::errors::{Error, ErrorKind};

/// The `typ` header value required for JWT proofs (Appendix F.1).
const JWT_PROOF_TYPE_HEADER: &str = "openid4vci-proof+jwt";

/// Identifies the proof type used in a credential request.
///
/// The proof type determines which key inside the `proofs` object is present
/// and how the proof is structured. Defined in
/// [OpenID4VCI Appendix F](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-proof-types).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofType {
    /// JWT proof type (Appendix F.1).
    Jwt,
    /// Data Integrity VP proof type (Appendix F.2).
    DiVp,
    /// Attestation proof type (Appendix F.3).
    Attestation,
}

// ── F.1: jwt proof type ───────────────────────────────────────────────────────

/// JOSE header claims for a JWT proof.
///
/// Defined in [OpenID4VCI Appendix F.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-jwt-proof-type).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwtProofHeader {
    /// REQUIRED. MUST be `openid4vci-proof+jwt`.
    pub typ: String,

    /// REQUIRED. Algorithm used to sign the JWT. MUST NOT be `none`.
    pub alg: String,

    /// OPTIONAL. JSON Web Key the credential shall be bound to.
    ///
    /// Either `jwk` or `kid` MUST be present; both MUST NOT be present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<serde_json::Value>,

    /// OPTIONAL. Key ID the credential shall be bound to.
    ///
    /// Either `jwk` or `kid` MUST be present; both MUST NOT be present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

impl JwtProofHeader {
    /// Validates the JWT proof header claims.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `typ` is not `openid4vci-proof+jwt`
    /// - `alg` is empty or `none`
    /// - Neither `jwk` nor `kid` is present
    /// - Both `jwk` and `kid` are present
    #[must_use = "validation result must be checked"]
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

        match (&self.jwk, &self.kid) {
            (None, None) => {
                return Err(Error::message(
                    ErrorKind::InvalidProof,
                    "JWT proof header must contain either 'jwk' or 'kid'",
                ));
            }
            (Some(_), Some(_)) => {
                return Err(Error::message(
                    ErrorKind::InvalidProof,
                    "JWT proof header must not contain both 'jwk' and 'kid'",
                ));
            }
            _ => {}
        }

        Ok(())
    }
}

/// JWT payload claims for a JWT proof.
///
/// Defined in [OpenID4VCI Appendix F.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-jwt-proof-type).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwtProofClaims {
    /// REQUIRED. The Credential Issuer Identifier used as the `aud` claim.
    ///
    /// MUST be the `credential_issuer` URL from the Credential Issuer metadata.
    pub aud: String,

    /// REQUIRED. Unix timestamp at which the JWT was issued.
    pub iat: i64,

    /// OPTIONAL. Challenge value from the Credential Issuer.
    ///
    /// When the issuer has a Nonce Endpoint or returns a `c_nonce` in the
    /// Token Response, this value MUST be included. Sourced from T3 (Token
    /// Response) once that ticket lands.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

impl JwtProofClaims {
    /// Validates the JWT proof payload claims.
    ///
    /// # Errors
    ///
    /// Returns an error if `aud` is empty or `iat` is zero or negative.
    #[must_use = "validation result must be checked"]
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

/// A single entry in the `proofs.jwt` array.
///
/// Each entry is the compact-serialized signed JWT string (`header.claims.sig`).
/// Spec §8.2: the value of the `jwt` key is a non-empty array of JWT strings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwtProof {
    /// The compact-serialized JWT string (`<header>.<claims>.<signature>`).
    pub jwt: String,
}

impl JwtProof {
    /// Validates the JWT proof entry.
    ///
    /// # Errors
    ///
    /// Returns an error if the string is empty or does not have three
    /// dot-separated parts.
    #[must_use = "validation result must be checked"]
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

// ── F.2: di_vp proof type ─────────────────────────────────────────────────────

/// A single entry in the `proofs.di_vp` array.
///
/// Each entry is a W3C Verifiable Presentation secured with a Data Integrity
/// proof. The spec (§8.2, Appendix F.2) requires:
/// - The `proof.challenge` field MUST contain the `c_nonce` value.
/// - The `proof.domain` field MUST contain the Credential Issuer Identifier.
///
/// The full structure follows the W3C VC Data Model. This type models only
/// what OID4VCI mandates at the wire level — the VP as a JSON object.
///
/// Defined in [OpenID4VCI Appendix F.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-di_vp-proof-type).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiVpProof {
    /// The Verifiable Presentation as a JSON object.
    ///
    /// Must contain a `proof` field with at least one Data Integrity proof.
    #[serde(flatten)]
    pub verifiable_presentation: serde_json::Value,
}

impl DiVpProof {
    /// Validates the `di_vp` proof entry.
    ///
    /// # Errors
    ///
    /// Returns an error if the presentation is not a JSON object or is
    /// missing the required `proof` field.
    #[must_use = "validation result must be checked"]
    pub fn validate(&self) -> Result<(), Error> {
        let obj = self.verifiable_presentation.as_object().ok_or_else(|| {
            Error::message(ErrorKind::InvalidProof, "di_vp proof must be a JSON object")
        })?;

        if !obj.contains_key("proof") {
            return Err(Error::message(
                ErrorKind::InvalidProof,
                "di_vp proof object must contain a 'proof' field",
            ));
        }

        Ok(())
    }
}

// ── F.3: attestation proof type ───────────────────────────────────────────────

/// A single entry in the `proofs.attestation` array.
///
/// Each entry is a compact-serialized JWT representing a key attestation.
/// Unlike the `jwt` proof type, the attestation conveys key material without
/// a separate proof of possession — the key attestation JWT itself serves as
/// the binding mechanism.
///
/// The JWT MUST set the `typ` JOSE header to `openid4vci-proof+jwt` and
/// include a `key_attestation` header as defined in Appendix D.
///
/// Defined in [OpenID4VCI Appendix F.3](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-attestation-proof-type).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationProof {
    /// The compact-serialized attestation JWT (`<header>.<claims>.<signature>`).
    pub attestation: String,
}

impl AttestationProof {
    /// Validates the attestation proof entry.
    ///
    /// # Errors
    ///
    /// Returns an error if the string is empty or does not have three
    /// dot-separated parts of a compact JWT.
    #[must_use = "validation result must be checked"]
    pub fn validate(&self) -> Result<(), Error> {
        if self.attestation.is_empty() {
            return Err(Error::message(
                ErrorKind::InvalidProof,
                "attestation proof string must not be empty",
            ));
        }

        let parts: Vec<&str> = self.attestation.splitn(4, '.').collect();
        if parts.len() != 3 {
            return Err(Error::message(
                ErrorKind::InvalidProof,
                "attestation proof must be a compact serialization with three dot-separated parts",
            ));
        }

        Ok(())
    }
}

// ── Proofs wrapper ────────────────────────────────────────────────────────────

/// The `proofs` object included in a Credential Request.
///
/// Contains exactly one proof type key whose value is a non-empty array of
/// proofs of that type. Spec §8.2: "The `proofs` parameter contains exactly
/// one parameter named as the proof type in Appendix F."
///
/// Defined in [OpenID4VCI Section 8.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-request).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proofs {
    /// One or more JWT proofs (Appendix F.1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwt: Option<Vec<JwtProof>>,

    /// One or more Data Integrity VP proofs (Appendix F.2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub di_vp: Option<Vec<DiVpProof>>,

    /// One or more attestation proofs (Appendix F.3).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<Vec<AttestationProof>>,
}

impl Proofs {
    /// Validates the proofs object.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No proof type is present
    /// - More than one proof type is present (spec requires exactly one)
    /// - The present array is empty
    /// - Any individual proof entry is invalid
    #[must_use = "validation result must be checked"]
    pub fn validate(&self) -> Result<(), Error> {
        let present_count = [
            self.jwt.is_some(),
            self.di_vp.is_some(),
            self.attestation.is_some(),
        ]
        .iter()
        .filter(|&&v| v)
        .count();

        if present_count == 0 {
            return Err(Error::message(
                ErrorKind::InvalidProof,
                "proofs object must contain at least one proof type",
            ));
        }

        if present_count > 1 {
            return Err(Error::message(
                ErrorKind::InvalidProof,
                "proofs object must contain exactly one proof type",
            ));
        }

        if let Some(ref proofs) = self.jwt {
            if proofs.is_empty() {
                return Err(Error::message(
                    ErrorKind::InvalidProof,
                    "proofs.jwt must not be empty when present",
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
                    "proofs.di_vp must not be empty when present",
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
                    "proofs.attestation must not be empty when present",
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

    // ── JwtProofHeader ────────────────────────────────────────────────────────

    #[test]
    fn valid_jwt_proof_header_with_jwk() {
        let header = JwtProofHeader {
            typ: "openid4vci-proof+jwt".to_string(),
            alg: "ES256".to_string(),
            jwk: Some(serde_json::json!({"kty": "EC"})),
            kid: None,
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
        };
        assert_eq!(
            header.validate().unwrap_err().kind(),
            ErrorKind::InvalidProof
        );
    }

    #[test]
    fn rejects_both_jwk_and_kid() {
        let header = JwtProofHeader {
            typ: "openid4vci-proof+jwt".to_string(),
            alg: "ES256".to_string(),
            jwk: Some(serde_json::json!({"kty": "EC"})),
            kid: Some("key-1".to_string()),
        };
        let err = header.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidProof);
        assert!(err.to_string().contains("both"));
    }

    #[test]
    fn rejects_neither_jwk_nor_kid() {
        let header = JwtProofHeader {
            typ: "openid4vci-proof+jwt".to_string(),
            alg: "ES256".to_string(),
            jwk: None,
            kid: None,
        };
        let err = header.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidProof);
        assert!(err.to_string().contains("either"));
    }

    // ── JwtProofClaims ────────────────────────────────────────────────────────

    #[test]
    fn valid_jwt_proof_claims_without_nonce() {
        let claims = JwtProofClaims {
            aud: "https://issuer.example.com".to_string(),
            iat: 1700000000,
            nonce: None,
        };
        assert!(claims.validate().is_ok());
    }

    #[test]
    fn valid_jwt_proof_claims_with_nonce() {
        let claims = JwtProofClaims {
            aud: "https://issuer.example.com".to_string(),
            iat: 1700000000,
            nonce: Some("wKI4LT17ac15ES9bw8ac4".to_string()),
        };
        assert!(claims.validate().is_ok());
    }

    #[test]
    fn rejects_empty_aud() {
        let claims = JwtProofClaims {
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
            aud: "https://issuer.example.com".to_string(),
            iat: 1700000000,
            nonce: Some("abc123".to_string()),
        };
        let json = serde_json::to_string(&claims).unwrap();
        assert!(json.contains("\"nonce\":\"abc123\""));
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
            verifiable_presentation: serde_json::json!({
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiablePresentation"],
                "holder": "did:key:z6MkvrFpBNCoYewiaeBLgjUDvLxUtnK5R6mqh5XPvLsrPsro",
                "proof": [{
                    "type": "DataIntegrityProof",
                    "cryptosuite": "eddsa-2022",
                    "proofPurpose": "authentication",
                    "verificationMethod": "did:key:z6Mk#z6Mk",
                    "challenge": "wKI4LT17ac15ES9bw8ac4",
                    "domain": "https://issuer.example.com",
                    "proofValue": "z5hrbHz"
                }]
            }),
        };
        assert!(proof.validate().is_ok());
    }

    #[test]
    fn rejects_di_vp_proof_not_an_object() {
        let proof = DiVpProof {
            verifiable_presentation: serde_json::json!("not an object"),
        };
        let err = proof.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidProof);
        assert!(err.to_string().contains("JSON object"));
    }

    #[test]
    fn rejects_di_vp_proof_missing_proof_field() {
        let proof = DiVpProof {
            verifiable_presentation: serde_json::json!({
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiablePresentation"]
                // "proof" field absent
            }),
        };
        let err = proof.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidProof);
        assert!(err.to_string().contains("'proof'"));
    }

    #[test]
    fn di_vp_proof_serializes_flattened() {
        let proof = DiVpProof {
            verifiable_presentation: serde_json::json!({
                "type": ["VerifiablePresentation"],
                "proof": [{"type": "DataIntegrityProof"}]
            }),
        };
        let json = serde_json::to_string(&proof).unwrap();
        // Must be flattened — no "verifiable_presentation" wrapper key
        assert!(json.contains("\"type\""));
        assert!(json.contains("VerifiablePresentation"));
        assert!(!json.contains("verifiable_presentation"));
    }

    #[test]
    fn di_vp_proof_deserializes_from_spec_example() {
        // Non-normative example from spec §8.2
        let json = r#"{
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "type": ["VerifiablePresentation"],
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
            proof.verifiable_presentation["holder"],
            "did:key:z6MkvrFpBNCoYewiaeBLgjUDvLxUtnK5R6mqh5XPvLsrPsro"
        );
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
                verifiable_presentation: serde_json::json!({
                    "type": ["VerifiablePresentation"],
                    "proof": [{"type": "DataIntegrityProof"}]
                }),
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
        assert!(err.to_string().contains("at least one"));
    }

    #[test]
    fn rejects_proofs_with_multiple_proof_types() {
        // Spec §8.2: "exactly one parameter named as the proof type"
        let proofs = Proofs {
            jwt: Some(vec![JwtProof {
                jwt: "aaa.bbb.ccc".to_string(),
            }]),
            di_vp: Some(vec![DiVpProof {
                verifiable_presentation: serde_json::json!({
                    "type": ["VerifiablePresentation"],
                    "proof": [{}]
                }),
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
                verifiable_presentation: serde_json::json!({
                    "type": ["VerifiablePresentation"]
                    // missing "proof"
                }),
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
                verifiable_presentation: serde_json::json!({
                    "type": ["VerifiablePresentation"],
                    "proof": []
                }),
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
