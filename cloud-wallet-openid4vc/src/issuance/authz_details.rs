//! Authorization Detail types for Rich Authorization Requests (RAR).
//!
//! This module implements the authorization details object as defined in
//! [RFC 9396] and extended by [OID4VCI §5.1.1].
//!
//! # Spec References
//!
//! - [RFC 9396 Rich Authorization Requests](https://www.rfc-editor.org/rfc/rfc9396.html)
//! - [OID4VCI §5.1.1 Using Authorization Details](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-using-authorization-details)

use serde::{Deserialize, Serialize};
use url::Url;

use crate::issuance::claim_path_pointer::ClaimPathPointer;

/// The type of authorization detail.
///
/// For OID4VCI, this MUST be set to `openid_credential`.
/// See [OID4VCI §5.1.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-using-authorization-details).
///
/// Note: The spec only defines `openid_credential` as the normative type.
/// Extension types should be handled through proper spec-defined mechanisms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationDetailType {
    /// Standard OID4VCI credential authorization type.
    OpenidCredential,
}

/// A claims description object for Authorization Details.
///
/// As defined in [OID4VCI Appendix B.1]. It defines the requirements for the claims
/// that the Wallet requests to be included in the Credential.
///
/// [OID4VCI Appendix B.1]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-B.1
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthzDetailsClaim {
    /// REQUIRED. Claim path pointer to identify the claim(s) in the Credential.
    pub path: ClaimPathPointer,

    /// OPTIONAL. Indicates that the Wallet will only accept a Credential that includes
    /// this claim. Default is `false`.
    #[serde(default)]
    pub mandatory: bool,
}

impl From<ClaimPathPointer> for AuthzDetailsClaim {
    fn from(path: ClaimPathPointer) -> Self {
        Self {
            path,
            mandatory: false,
        }
    }
}

/// Rich Authorization Request (RAR) detail object for OID4VCI.
///
/// As defined in [RFC 9396 §2](https://www.rfc-editor.org/rfc/rfc9396.html) and
/// [OID4VCI §5.1.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-using-authorization-details).
///
/// Per §5.1.1, `credential_configuration_id` is REQUIRED. If the Credential Issuer
/// metadata contains an `authorization_servers` parameter, the `locations` field MUST
/// be set to the Credential Issuer Identifier value.
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationDetails {
    /// REQUIRED. The type of authorization detail. MUST be `openid_credential`.
    #[serde(rename = "type")]
    pub r#type: AuthorizationDetailType,

    /// REQUIRED. Unique identifier of the Credential in the issuer's
    /// `credential_configurations_supported` map.
    pub credential_configuration_id: String,

    /// OPTIONAL. Array of Credential Issuer Identifier URLs.
    /// MUST be set when the issuer metadata has an `authorization_servers` parameter,
    /// to allow the AS to identify which issuer is being targeted.
    pub locations: Option<Vec<Url>>,

    /// OPTIONAL. Non-empty array of claims description objects restricting which claims
    /// to include in the issued Credential. See [OID4VCI Appendix B.1].
    pub claims: Option<Vec<AuthzDetailsClaim>>,
}

impl AuthorizationDetails {
    /// Creates a new `AuthorizationDetail` specifying the credential by its configuration ID.
    ///
    /// This is the primary way to construct an authorization detail per [OID4VCI §5.1.1]:
    /// ```json
    /// [{ "type": "openid_credential", "credential_configuration_id": "UniversityDegreeCredential" }]
    /// ```
    pub fn for_configuration(id: impl Into<String>) -> Self {
        Self {
            r#type: AuthorizationDetailType::OpenidCredential,
            credential_configuration_id: id.into(),
            locations: None,
            claims: None,
        }
    }

    /// Sets the `locations` field.
    ///
    /// MUST be set when the issuer metadata contains an `authorization_servers` parameter,
    /// so the Authorization Server can identify the targeted Credential Issuer.
    pub fn with_locations(mut self, locations: Vec<Url>) -> Self {
        self.locations = Some(locations);
        self
    }

    /// Restricts which claims to request in the issued Credential.
    pub fn with_claims(mut self, claims: Vec<AuthzDetailsClaim>) -> Self {
        self.claims = Some(claims);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rar_detail_ser_matches_spec_example() {
        // OID4VCI §5.1.1 non-normative example:
        // [{ "type": "openid_credential", "credential_configuration_id": "UniversityDegreeCredential" }]
        let detail = AuthorizationDetails::for_configuration("UniversityDegreeCredential");
        let json = serde_json::to_value(&detail).unwrap();

        assert_eq!(json["type"], "openid_credential");
        assert_eq!(
            json["credential_configuration_id"],
            "UniversityDegreeCredential"
        );
        // `format` must NOT appear - it is not part of the final OID4VCI spec
        assert!(json.get("format").is_none());
        // Optional fields omitted when None
        assert!(json.get("locations").is_none());
        assert!(json.get("claims").is_none());
    }

    #[test]
    fn rar_detail_with_locations_for_remote_as() {
        // OID4VCI §5.1.1: locations MUST be set when authorization_servers is in metadata
        let detail = AuthorizationDetails::for_configuration("UniversityDegreeCredential")
            .with_locations(vec![
                Url::parse("https://credential-issuer.example.com").unwrap(),
            ]);

        let json = serde_json::to_value(&detail).unwrap();
        assert_eq!(
            json["locations"][0],
            "https://credential-issuer.example.com/"
        );
    }

    #[test]
    fn rar_detail_roundtrip_deserialization() {
        let original = AuthorizationDetails::for_configuration("MyCredential")
            .with_locations(vec![Url::parse("https://issuer.example.com").unwrap()]);

        let json = serde_json::to_string(&original).unwrap();
        let recovered: AuthorizationDetails = serde_json::from_str(&json).unwrap();

        assert_eq!(recovered.credential_configuration_id, "MyCredential");
        assert_eq!(
            recovered.locations,
            Some(vec![Url::parse("https://issuer.example.com/").unwrap()])
        );
    }
}
