use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::core::claim_path_pointer::{ClaimPathElement, ClaimPathPointer, ClaimValue};
use crate::errors::{Error, ErrorKind, Result};

/// A Digital Credentials Query Language (DCQL) query.
///
/// Defined in [OpenID4VP Section 5.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.1).
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DcqlQuery {
    /// REQUIRED. Array of credential queries. Must contain at least one element.
    pub credentials: Vec<CredentialQuery>,

    /// OPTIONAL. Credential sets for combining multiple credential queries (Section 6.2).
    pub credential_sets: Option<Vec<CredentialSet>>,
}

impl DcqlQuery {
    /// Validates the DCQL query structure.
    pub fn validate(&self) -> Result<()> {
        if self.credentials.is_empty() {
            return Err(invalid_dcql(
                "'dcql_query.credentials' must contain at least one credential query",
            ));
        }

        // validate each credential query and collect IDs for uniqueness + reference checks
        let mut seen_ids: Vec<&str> = Vec::new();
        for (i, cred) in self.credentials.iter().enumerate() {
            cred.validate(i)?;
            if seen_ids.contains(&cred.id.as_str()) {
                return Err(invalid_dcql(format!(
                    "'dcql_query.credentials[{i}].id' '{}' must be unique within the credentials array",
                    cred.id
                )));
            }
            seen_ids.push(cred.id.as_str());
        }

        // validate credential_sets, passing the set of valid credential IDs
        if let Some(ref sets) = self.credential_sets {
            // Section 6 says credential_sets, when present, must be a non-empty array
            if sets.is_empty() {
                return Err(invalid_dcql(
                    "'dcql_query.credential_sets' must be a non-empty array when present",
                ));
            }
            for (i, set) in sets.iter().enumerate() {
                set.validate(i, &seen_ids)?;
            }
        }

        Ok(())
    }
}

#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimsQuery {
    pub path: ClaimPathPointer,
    pub id: Option<String>,
    pub values: Option<Vec<ClaimValue>>,
}

impl ClaimsQuery {
    /// Validates the claims query.
    pub(crate) fn validate(
        &self,
        idx: usize,
        require_id: bool,
        format: &CredentialFormat,
    ) -> Result<()> {
        // ClaimPathPointer already validates non-empty on deserialization
        if let Some(ref id) = self.id
            && !is_dcql_identifier(id)
        {
            return Err(invalid_dcql(format!(
                "'claims[{idx}].id' must consist only of alphanumeric characters, '_', or '-'"
            )));
        }

        if require_id && self.id.is_none() {
            return Err(invalid_dcql(format!(
                "'claims[{idx}].id' is required when 'claim_sets' is present"
            )));
        }
        if let Some(ref values) = self.values
            && values.is_empty()
        {
            return Err(invalid_dcql(format!(
                "'claims[{idx}].values' must be a non-empty array when present"
            )));
        }

        // For mso_mdoc format, validate claim path structure per Section B.3.2
        if matches!(format, CredentialFormat::MsoMdoc) {
            let elements = self.path.elements();
            if elements.len() != 2 {
                return Err(invalid_dcql(format!(
                    "'claims[{idx}].path' for mso_mdoc format must contain exactly 2 elements (namespace and data element), found {}",
                    elements.len()
                )));
            }
            // Both elements must be strings (namespace and data element identifier)
            if !matches!(elements[0], ClaimPathElement::String(_)) {
                return Err(invalid_dcql(format!(
                    "'claims[{idx}].path[0]' for mso_mdoc format must be a string (namespace)"
                )));
            }
            if !matches!(elements[1], ClaimPathElement::String(_)) {
                return Err(invalid_dcql(format!(
                    "'claims[{idx}].path[1]' for mso_mdoc format must be a string (data element identifier)"
                )));
            }
        }

        Ok(())
    }
}

/// A single Credential Set option entry.
///
/// Defined in [OpenID4VP Section 6.2](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.2).
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialSet {
    /// REQUIRED. Non-empty array of options, each a non-empty list of credential query IDs.
    pub options: Vec<Vec<String>>,

    /// OPTIONAL. Defaults to `true`. Whether this credential set is required.
    pub required: Option<bool>,
}

impl CredentialSet {
    pub(crate) fn validate(&self, idx: usize, valid_ids: &[&str]) -> Result<()> {
        if self.options.is_empty() {
            return Err(invalid_dcql(format!(
                "'credential_sets[{idx}].options' must be a non-empty array"
            )));
        }
        for (oi, option) in self.options.iter().enumerate() {
            if option.is_empty() {
                return Err(invalid_dcql(format!(
                    "'credential_sets[{idx}].options[{oi}]' must be a non-empty array"
                )));
            }
            for id_ref in option {
                if !valid_ids.contains(&id_ref.as_str()) {
                    return Err(invalid_dcql(format!(
                        "'credential_sets[{idx}].options[{oi}]' references unknown credential id '{id_ref}'"
                    )));
                }
            }
        }
        Ok(())
    }
}

/// The type of trusted authority reference.
///
/// Defined in [OpenID4VP Section 6.1.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustedAuthorityType {
    /// Authority Key Identifier (AKI) from X.509 certificates.
    Aki,
    /// ETSI Trusted List.
    EtsiTl,
    /// OpenID Federation entity.
    OpenidFederation,
    /// Extension point for other authority types.
    #[serde(untagged)]
    Other(String),
}

impl std::fmt::Display for TrustedAuthorityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Aki => write!(f, "aki"),
            Self::EtsiTl => write!(f, "etsi_tl"),
            Self::OpenidFederation => write!(f, "openid_federation"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

/// A Trusted Authority Query object within a Credential Query.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustedAuthorityQuery {
    /// REQUIRED. The type of trusted authority reference.
    #[serde(rename = "type")]
    pub authority_type: TrustedAuthorityType,

    /// REQUIRED. Non-empty array of type-specific authority value(s).
    pub values: Vec<String>,
}

impl TrustedAuthorityQuery {
    pub(crate) fn validate(&self, idx: usize) -> Result<()> {
        if self.values.is_empty() {
            return Err(invalid_dcql(format!(
                "'trusted_authorities[{idx}].values' must be a non-empty array"
            )));
        }
        Ok(())
    }
}

/// Format-specific metadata for a credential query.
///
/// Defined in [OpenID4VP Section 6.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CredentialMeta {
    /// Metadata for W3C VC formats (jwt_vc_json, jwt_vc_json-ld, ldp_vc).
    /// Requires `type_values` - a non-empty array of credential type URIs.
    W3CFormat { type_values: Vec<Vec<String>> },
    /// Metadata for `dc+sd-jwt` format (Section B.3.1).
    SdJwt { vct_values: Vec<String> },
    /// Metadata for `mso_mdoc` format (Section B.3.2).
    MsoMdoc { doctype_value: String },
}

impl CredentialMeta {
    /// Validates the metadata structure for the given format.
    ///
    /// Each credential format must use its matching metadata shape:
    /// - W3C formats (jwt_vc_json, jwt_vc_json-ld, ldp_vc) use `type_values`
    /// - dc+sd-jwt format uses `vct_values`
    /// - mso_mdoc format uses `doctype_value`
    fn validate(&self, idx: usize, format: &CredentialFormat) -> Result<()> {
        match (self, format) {
            // W3C formats (jwt_vc_json, jwt_vc_json-ld, ldp_vc) use type_values
            (
                CredentialMeta::W3CFormat { type_values },
                CredentialFormat::JwtVcJson | CredentialFormat::LdpVc,
            ) => {
                validate_type_values(idx, type_values)?;
            }
            (CredentialMeta::W3CFormat { type_values }, CredentialFormat::Other(fmt)) => {
                // Only allow W3CFormat for known W3C credential formats
                if !is_w3c_format(fmt) {
                    return Err(invalid_dcql(format!(
                        "'dcql_query.credentials[{idx}].meta' has W3C format structure but format '{fmt}' is not a recognized W3C VC format"
                    )));
                }
                validate_type_values(idx, type_values)?;
            }
            (CredentialMeta::W3CFormat { .. }, CredentialFormat::DcSdJwt) => {
                return Err(invalid_dcql(format!(
                    "'dcql_query.credentials[{idx}].meta' has W3C format structure (type_values) but format is 'dc+sd-jwt' which requires 'vct_values'"
                )));
            }
            (CredentialMeta::W3CFormat { .. }, CredentialFormat::MsoMdoc) => {
                return Err(invalid_dcql(format!(
                    "'dcql_query.credentials[{idx}].meta' has W3C format structure (type_values) but format is 'mso_mdoc' which requires 'doctype_value'"
                )));
            }
            // dc+sd-jwt format uses vct_values
            (CredentialMeta::SdJwt { vct_values }, CredentialFormat::DcSdJwt) => {
                if vct_values.is_empty() {
                    return Err(invalid_dcql(format!(
                        "'dcql_query.credentials[{idx}].meta.vct_values' must be a non-empty array"
                    )));
                }
                for (vi, v) in vct_values.iter().enumerate() {
                    if v.trim().is_empty() {
                        return Err(invalid_dcql(format!(
                            "'dcql_query.credentials[{idx}].meta.vct_values[{vi}]' must not be empty"
                        )));
                    }
                }
            }
            (CredentialMeta::SdJwt { .. }, CredentialFormat::MsoMdoc) => {
                return Err(invalid_dcql(format!(
                    "'dcql_query.credentials[{idx}].meta' has dc+sd-jwt structure (vct_values) but format is 'mso_mdoc' which requires 'doctype_value'"
                )));
            }
            (
                CredentialMeta::SdJwt { .. },
                CredentialFormat::JwtVcJson | CredentialFormat::LdpVc,
            ) => {
                return Err(invalid_dcql(format!(
                    "'dcql_query.credentials[{idx}].meta' has dc+sd-jwt structure (vct_values) but format requires 'type_values'"
                )));
            }
            (CredentialMeta::SdJwt { .. }, CredentialFormat::Other(fmt)) => {
                return Err(invalid_dcql(format!(
                    "'dcql_query.credentials[{idx}].meta' has dc+sd-jwt structure (vct_values) but format is '{fmt}'"
                )));
            }
            // mso_mdoc format uses doctype_value
            (CredentialMeta::MsoMdoc { doctype_value }, CredentialFormat::MsoMdoc) => {
                if doctype_value.trim().is_empty() {
                    return Err(invalid_dcql(format!(
                        "'dcql_query.credentials[{idx}].meta.doctype_value' must not be empty"
                    )));
                }
            }
            (CredentialMeta::MsoMdoc { .. }, CredentialFormat::DcSdJwt) => {
                return Err(invalid_dcql(format!(
                    "'dcql_query.credentials[{idx}].meta' has mso_mdoc structure (doctype_value) but format is 'dc+sd-jwt' which requires 'vct_values'"
                )));
            }
            (
                CredentialMeta::MsoMdoc { .. },
                CredentialFormat::JwtVcJson | CredentialFormat::LdpVc,
            ) => {
                return Err(invalid_dcql(format!(
                    "'dcql_query.credentials[{idx}].meta' has mso_mdoc structure (doctype_value) but format requires 'type_values'"
                )));
            }
            (CredentialMeta::MsoMdoc { .. }, CredentialFormat::Other(fmt)) => {
                return Err(invalid_dcql(format!(
                    "'dcql_query.credentials[{idx}].meta' has mso_mdoc structure (doctype_value) but format is '{fmt}'"
                )));
            }
        }
        Ok(())
    }
}

fn validate_type_values(idx: usize, type_values: &[Vec<String>]) -> Result<()> {
    if type_values.is_empty() {
        return Err(invalid_dcql(format!(
            "'dcql_query.credentials[{idx}].meta.type_values' must be a non-empty array"
        )));
    }
    for (vi, values) in type_values.iter().enumerate() {
        if values.is_empty() {
            return Err(invalid_dcql(format!(
                "'dcql_query.credentials[{idx}].meta.type_values[{vi}]' must be a non-empty array"
            )));
        }
        for (ti, t) in values.iter().enumerate() {
            if t.trim().is_empty() {
                return Err(invalid_dcql(format!(
                    "'dcql_query.credentials[{idx}].meta.type_values[{vi}][{ti}]' must not be empty"
                )));
            }
        }
    }
    Ok(())
}

/// Checks if a format string is a recognized W3C VC format.
fn is_w3c_format(fmt: &str) -> bool {
    matches!(fmt, "jwt_vc_json" | "jwt_vc_json-ld" | "ldp_vc")
}

/// Supported credential formats for DCQL queries.
///
/// Defined in [OpenID4VP Section 6.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialFormat {
    /// VC signed as a JWT, not using JSON-LD as defined in Section B.1.3.1.
    JwtVcJson,
    /// LDP VC format as defined in Section B.1.3.2.
    LdpVc,
    /// SD-JWT VC format as defined in Section B.3.1.
    #[serde(rename = "dc+sd-jwt")]
    DcSdJwt,
    /// ISO mdoc format as defined in Section B.3.2.
    MsoMdoc,
    /// Extension point for other formats.
    #[serde(untagged)]
    Other(String),
}

impl std::fmt::Display for CredentialFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::JwtVcJson => write!(f, "jwt_vc_json"),
            Self::LdpVc => write!(f, "ldp_vc"),
            Self::DcSdJwt => write!(f, "dc+sd-jwt"),
            Self::MsoMdoc => write!(f, "mso_mdoc"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

/// A credential query within a DCQL query.
///
/// Defined in [OpenID4VP Section 6.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1).
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialQuery {
    pub id: String,
    pub format: CredentialFormat,
    pub multiple: Option<bool>,
    pub meta: CredentialMeta,
    pub claims: Option<Vec<ClaimsQuery>>,
    pub claim_sets: Option<Vec<Vec<String>>>,
    pub trusted_authorities: Option<Vec<TrustedAuthorityQuery>>,
    pub require_cryptographic_holder_binding: Option<bool>,
}

impl CredentialQuery {
    pub(crate) fn validate(&self, idx: usize) -> Result<()> {
        // id must be non-empty and match DCQL identifier charset
        if self.id.trim().is_empty() {
            return Err(invalid_dcql(format!(
                "'dcql_query.credentials[{idx}].id' must not be empty"
            )));
        }
        if !is_dcql_identifier(&self.id) {
            return Err(invalid_dcql(format!(
                "'dcql_query.credentials[{idx}].id' must consist only of alphanumeric characters, '_', or '-'"
            )));
        }

        // Validate format - for Other variant, check that it's not empty/whitespace
        if let CredentialFormat::Other(ref s) = self.format
            && s.trim().is_empty()
        {
            return Err(invalid_dcql(format!(
                "'dcql_query.credentials[{idx}].format' must not be empty"
            )));
        }

        // format-aware meta validation
        self.meta.validate(idx, &self.format)?;

        // claim_sets MUST NOT be present when claims is absent
        if self.claim_sets.is_some() && self.claims.is_none() {
            return Err(invalid_dcql(format!(
                "'dcql_query.credentials[{idx}].claim_sets' MUST NOT be present when 'claims' is absent"
            )));
        }

        let has_claim_sets = self.claim_sets.is_some();

        // validate claims entries
        if let Some(ref claims) = self.claims {
            let mut seen_ids: Vec<&str> = Vec::new();
            for (ci, claim) in claims.iter().enumerate() {
                claim.validate(ci, has_claim_sets, &self.format)?;
                if let Some(ref id) = claim.id {
                    if seen_ids.contains(&id.as_str()) {
                        return Err(invalid_dcql(format!(
                            "'dcql_query.credentials[{idx}].claims[{ci}].id' '{id}' is not unique within the claims array"
                        )));
                    }
                    seen_ids.push(id.as_str());
                }
            }
        }

        // validate claim_sets entries reference known claim IDs
        if let Some(ref claim_sets) = self.claim_sets {
            if claim_sets.is_empty() {
                return Err(invalid_dcql(format!(
                    "'dcql_query.credentials[{idx}].claim_sets' must be a non-empty array when present"
                )));
            }
            // collect valid claim ids for reference checking
            let valid_claim_ids: Vec<&str> = self
                .claims
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .filter_map(|c| c.id.as_deref())
                .collect();

            for (si, set) in claim_sets.iter().enumerate() {
                if set.is_empty() {
                    return Err(invalid_dcql(format!(
                        "'dcql_query.credentials[{idx}].claim_sets[{si}]' must be a non-empty array"
                    )));
                }
                for id_ref in set {
                    if !valid_claim_ids.contains(&id_ref.as_str()) {
                        return Err(invalid_dcql(format!(
                            "'dcql_query.credentials[{idx}].claim_sets[{si}]' references unknown claim id '{id_ref}'"
                        )));
                    }
                }
            }
        }

        // validate trusted_authorities
        if let Some(ref authorities) = self.trusted_authorities {
            if authorities.is_empty() {
                return Err(invalid_dcql(format!(
                    "'dcql_query.credentials[{idx}].trusted_authorities' must be a non-empty array when present"
                )));
            }
            for (ai, authority) in authorities.iter().enumerate() {
                authority.validate(ai)?;
            }
        }

        Ok(())
    }
}

/// Checks that `s` is a valid DCQL identifier: non-empty, alphanumeric + `_` + `-` (Section 6.1).
pub(crate) fn is_dcql_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn invalid_dcql(message: impl Into<String>) -> Error {
    Error::message(ErrorKind::InvalidPresentationRequest, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn dcql_query_happy_path() {
        // Valid DCQL query with dc+sd-jwt credential
        let query: DcqlQuery = serde_json::from_value(json!({
            "credentials": [{
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["https://example.com/vct"] },
                "claims": [
                    { "path": ["given_name"], "id": "gn" },
                    { "path": ["addresses", 0, "city"], "id": "city" }
                ],
                "claim_sets": [["gn"], ["gn", "city"]],
                "trusted_authorities": [
                    { "type": "aki", "values": ["key1"] },
                    { "type": "etsi_tl", "values": ["tl1"] }
                ]
            }]
        }))
        .unwrap();

        assert!(query.validate().is_ok());
        assert_eq!(query.credentials[0].id, "pid");
        assert_eq!(query.credentials[0].format, CredentialFormat::DcSdJwt);
    }

    #[test]
    fn dcql_query_with_credential_sets() {
        let query: DcqlQuery = serde_json::from_value(json!({
            "credentials": [
                { "id": "cred1", "format": "dc+sd-jwt", "meta": { "vct_values": ["vct1"] } },
                { "id": "cred2", "format": "mso_mdoc", "meta": { "doctype_value": "org.iso.18013.5.1.mDL" } }
            ],
            "credential_sets": [
                { "options": [["cred1"], ["cred2"]], "required": true }
            ]
        })).unwrap();

        assert!(query.validate().is_ok());
        assert_eq!(query.credentials.len(), 2);
        assert_eq!(query.credentials[1].format, CredentialFormat::MsoMdoc);
    }

    #[test]
    fn dcql_query_with_claim_values() {
        let query: DcqlQuery = serde_json::from_value(json!({
            "credentials": [{
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["vct"] },
                "claims": [
                    { "path": ["age"], "id": "age", "values": [18, 21, 25] },
                    { "path": ["active"], "id": "active", "values": [true, false] },
                    { "path": ["name"], "id": "name", "values": ["John", "Jane"] }
                ]
            }]
        }))
        .unwrap();

        assert!(query.validate().is_ok());
        let claims = query.credentials[0].claims.as_ref().unwrap();
        match &claims[0].values.as_ref().unwrap()[0] {
            ClaimValue::Integer(i) => assert_eq!(*i, 18),
            _ => panic!("expected Integer"),
        }
        match &claims[1].values.as_ref().unwrap()[0] {
            ClaimValue::Boolean(b) => assert!(*b),
            _ => panic!("expected Boolean"),
        }
    }

    #[test]
    fn dcql_serde_roundtrip() {
        let query = DcqlQuery {
            credentials: vec![CredentialQuery {
                id: "pid".to_string(),
                format: CredentialFormat::DcSdJwt,
                multiple: Some(true),
                meta: CredentialMeta::SdJwt {
                    vct_values: vec!["https://example.com/vct".to_string()],
                },
                claims: Some(vec![ClaimsQuery {
                    path: ClaimPathPointer::try_new(vec![ClaimPathElement::from("name")]).unwrap(),
                    id: Some("name_claim".to_string()),
                    values: Some(vec![
                        ClaimValue::String("John".to_string()),
                        ClaimValue::String("Jane".to_string()),
                    ]),
                }]),
                claim_sets: None,
                trusted_authorities: Some(vec![TrustedAuthorityQuery {
                    authority_type: TrustedAuthorityType::Aki,
                    values: vec!["auth1".to_string()],
                }]),
                require_cryptographic_holder_binding: Some(true),
            }],
            credential_sets: None,
        };

        let serialized = serde_json::to_string(&query).unwrap();
        let deserialized: DcqlQuery = serde_json::from_str(&serialized).unwrap();

        assert_eq!(query.credentials[0].id, deserialized.credentials[0].id);
        assert_eq!(
            query.credentials[0].format,
            deserialized.credentials[0].format
        );
    }

    #[test]
    fn display_traits() {
        assert_eq!(TrustedAuthorityType::Aki.to_string(), "aki");
        assert_eq!(TrustedAuthorityType::EtsiTl.to_string(), "etsi_tl");
        assert_eq!(
            TrustedAuthorityType::OpenidFederation.to_string(),
            "openid_federation"
        );
        assert_eq!(
            TrustedAuthorityType::Other("custom".to_string()).to_string(),
            "custom"
        );
        assert_eq!(CredentialFormat::DcSdJwt.to_string(), "dc+sd-jwt");
        assert_eq!(CredentialFormat::MsoMdoc.to_string(), "mso_mdoc");
    }
}
