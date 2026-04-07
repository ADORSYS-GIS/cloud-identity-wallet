//! OpenID4VP wallet and verifier metadata models.
//!
//! See OpenID4VP Sections 10 and 11.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::skip_serializing_none;

use crate::errors::{Error, ErrorKind};

fn validate_non_empty_strings(
    values: &[String],
    field: &str,
    kind: ErrorKind,
) -> Result<(), Error> {
    if values.is_empty() {
        return Err(Error::message(kind, format!("{field} must not be empty")));
    }

    if values.iter().any(|value| value.trim().is_empty()) {
        return Err(Error::message(
            kind,
            format!("{field} must not contain empty strings"),
        ));
    }

    Ok(())
}

/// `vp_formats_supported` parameters for JWT-based W3C VC presentations.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct JwtVcJsonPresentationFormat {
    /// Supported JWS algorithms.
    pub alg_values: Option<Vec<String>>,
}

/// `vp_formats_supported` parameters for JSON-LD/Data Integrity presentations.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct LdpVcPresentationFormat {
    /// Supported proof types.
    pub proof_type_values: Option<Vec<String>>,

    /// Supported cryptosuite identifiers.
    pub cryptosuite_values: Option<Vec<String>>,
}

/// `vp_formats_supported` parameters for ISO mdoc presentations.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MsoMdocPresentationFormat {
    /// Supported issuer authentication algorithms.
    pub issuerauth_alg_values: Option<Vec<i64>>,

    /// Supported device authentication algorithms.
    pub deviceauth_alg_values: Option<Vec<i64>>,
}

/// `vp_formats_supported` parameters for SD-JWT VC presentations.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SdJwtPresentationFormat {
    /// Supported issuer-signed SD-JWT algorithms.
    #[serde(rename = "sd-jwt_alg_values")]
    pub sd_jwt_alg_values: Option<Vec<String>>,

    /// Supported key-binding JWT algorithms.
    #[serde(rename = "kb-jwt_alg_values")]
    pub kb_jwt_alg_values: Option<Vec<String>>,
}

/// The OpenID4VP `vp_formats_supported` object.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct VpFormatsSupported {
    /// SD-JWT VC presentation capabilities.
    #[serde(rename = "dc+sd-jwt")]
    pub dc_sd_jwt: Option<SdJwtPresentationFormat>,

    /// ISO mdoc presentation capabilities.
    #[serde(rename = "mso_mdoc")]
    pub mso_mdoc: Option<MsoMdocPresentationFormat>,

    /// JWT VC presentation capabilities.
    #[serde(rename = "jwt_vc_json")]
    pub jwt_vc_json: Option<JwtVcJsonPresentationFormat>,

    /// Data Integrity VC presentation capabilities.
    #[serde(rename = "ldp_vc")]
    pub ldp_vc: Option<LdpVcPresentationFormat>,

    /// JWT VC JSON-LD presentation capabilities.
    #[serde(rename = "jwt_vc_json-ld")]
    pub jwt_vc_json_ld: Option<LdpVcPresentationFormat>,

    /// Extension formats not modelled explicitly.
    #[serde(flatten, default)]
    pub other: HashMap<String, Value>,
}

impl VpFormatsSupported {
    /// Returns `true` when no format capabilities are defined.
    pub fn is_empty(&self) -> bool {
        self.dc_sd_jwt.is_none()
            && self.mso_mdoc.is_none()
            && self.jwt_vc_json.is_none()
            && self.ldp_vc.is_none()
            && self.jwt_vc_json_ld.is_none()
            && self.other.is_empty()
    }

    /// Validates the format capabilities object.
    pub fn validate(&self, kind: ErrorKind) -> Result<(), Error> {
        if self.is_empty() {
            return Err(Error::message(
                kind,
                "vp_formats_supported must define at least one format",
            ));
        }

        if let Some(format) = &self.dc_sd_jwt {
            if let Some(values) = &format.sd_jwt_alg_values {
                validate_non_empty_strings(values, "dc+sd-jwt.sd-jwt_alg_values", kind)?;
            }
            if let Some(values) = &format.kb_jwt_alg_values {
                validate_non_empty_strings(values, "dc+sd-jwt.kb-jwt_alg_values", kind)?;
            }
        }

        if let Some(format) = &self.jwt_vc_json {
            if let Some(values) = &format.alg_values {
                validate_non_empty_strings(values, "jwt_vc_json.alg_values", kind)?;
            }
        }

        if let Some(format) = &self.ldp_vc {
            if let Some(values) = &format.proof_type_values {
                validate_non_empty_strings(values, "ldp_vc.proof_type_values", kind)?;
            }
            if let Some(values) = &format.cryptosuite_values {
                validate_non_empty_strings(values, "ldp_vc.cryptosuite_values", kind)?;
            }
        }

        if let Some(format) = &self.jwt_vc_json_ld {
            if let Some(values) = &format.proof_type_values {
                validate_non_empty_strings(values, "jwt_vc_json-ld.proof_type_values", kind)?;
            }
            if let Some(values) = &format.cryptosuite_values {
                validate_non_empty_strings(values, "jwt_vc_json-ld.cryptosuite_values", kind)?;
            }
        }

        if let Some(format) = &self.mso_mdoc {
            if matches!(format.issuerauth_alg_values.as_ref(), Some(values) if values.is_empty()) {
                return Err(Error::message(
                    kind,
                    "mso_mdoc.issuerauth_alg_values must not be empty when present",
                ));
            }
            if matches!(format.deviceauth_alg_values.as_ref(), Some(values) if values.is_empty()) {
                return Err(Error::message(
                    kind,
                    "mso_mdoc.deviceauth_alg_values must not be empty when present",
                ));
            }
        }

        Ok(())
    }
}

/// Verifier metadata conveyed via the `client_metadata` request parameter.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerifierMetadata {
    /// Optional JWK Set used for response encryption or verifier key conveyance.
    pub jwks: Option<Value>,

    /// Supported JWE `enc` values for encrypted responses.
    pub encrypted_response_enc_values_supported: Option<Vec<String>>,

    /// Supported presentation formats.
    pub vp_formats_supported: VpFormatsSupported,
}

impl VerifierMetadata {
    /// Validates the verifier metadata.
    pub fn validate(&self) -> Result<(), Error> {
        self.vp_formats_supported
            .validate(ErrorKind::InvalidVerifierMetadata)?;

        if let Some(jwks) = &self.jwks
            && !jwks.is_object()
        {
            return Err(Error::message(
                ErrorKind::InvalidVerifierMetadata,
                "jwks must be a JSON object when present",
            ));
        }

        if let Some(values) = &self.encrypted_response_enc_values_supported {
            validate_non_empty_strings(
                values,
                "encrypted_response_enc_values_supported",
                ErrorKind::InvalidVerifierMetadata,
            )?;
        }

        Ok(())
    }
}

/// Wallet metadata published by or conveyed for an OpenID4VP wallet.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WalletMetadata {
    /// Supported presentation formats.
    pub vp_formats_supported: VpFormatsSupported,

    /// Supported client identifier prefix values.
    pub client_id_prefixes_supported: Option<Vec<String>>,

    /// Supported request object signing algorithms.
    pub request_object_signing_alg_values_supported: Option<Vec<String>>,

    /// Supported JWE `alg` values for request encryption.
    pub authorization_encryption_alg_values_supported: Option<Vec<String>>,

    /// Supported JWE `enc` values for request encryption.
    pub authorization_encryption_enc_values_supported: Option<Vec<String>>,

    /// Optional wallet JWK Set.
    pub jwks: Option<Value>,
}

impl WalletMetadata {
    /// Validates the wallet metadata.
    pub fn validate(&self) -> Result<(), Error> {
        self.vp_formats_supported
            .validate(ErrorKind::InvalidWalletMetadata)?;

        if let Some(values) = &self.client_id_prefixes_supported {
            validate_non_empty_strings(
                values,
                "client_id_prefixes_supported",
                ErrorKind::InvalidWalletMetadata,
            )?;
        }

        if let Some(values) = &self.request_object_signing_alg_values_supported {
            validate_non_empty_strings(
                values,
                "request_object_signing_alg_values_supported",
                ErrorKind::InvalidWalletMetadata,
            )?;
        }

        if let Some(values) = &self.authorization_encryption_alg_values_supported {
            validate_non_empty_strings(
                values,
                "authorization_encryption_alg_values_supported",
                ErrorKind::InvalidWalletMetadata,
            )?;
        }

        if let Some(values) = &self.authorization_encryption_enc_values_supported {
            validate_non_empty_strings(
                values,
                "authorization_encryption_enc_values_supported",
                ErrorKind::InvalidWalletMetadata,
            )?;
        }

        if let Some(jwks) = &self.jwks
            && !jwks.is_object()
        {
            return Err(Error::message(
                ErrorKind::InvalidWalletMetadata,
                "jwks must be a JSON object when present",
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_formats() -> VpFormatsSupported {
        VpFormatsSupported {
            dc_sd_jwt: Some(SdJwtPresentationFormat {
                sd_jwt_alg_values: Some(vec!["ES256".to_string()]),
                kb_jwt_alg_values: Some(vec!["ES256".to_string()]),
            }),
            ..VpFormatsSupported::default()
        }
    }

    #[test]
    fn verifier_metadata_requires_format_support() {
        let metadata = VerifierMetadata {
            jwks: None,
            encrypted_response_enc_values_supported: None,
            vp_formats_supported: VpFormatsSupported::default(),
        };

        let err = metadata.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidVerifierMetadata);
    }

    #[test]
    fn wallet_metadata_with_minimal_formats_is_valid() {
        let metadata = WalletMetadata {
            vp_formats_supported: minimal_formats(),
            client_id_prefixes_supported: Some(vec!["pre-registered".to_string()]),
            request_object_signing_alg_values_supported: Some(vec!["ES256".to_string()]),
            authorization_encryption_alg_values_supported: None,
            authorization_encryption_enc_values_supported: None,
            jwks: None,
        };

        metadata.validate().unwrap();
    }
}
