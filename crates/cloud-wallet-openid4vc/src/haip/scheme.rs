//! HAIP custom URL scheme parsers for `haip-vci://` and `haip-vp://`.
//!
//! Spec references: HAIP §4.2 (Credential Offer), §5.1 (OpenID4VP), Appendix A.1 (URI Schemes)

use url::Url;

use crate::haip::error::{Error, Result};

const HAIP_VCI_SCHEME: &str = "haip-vci";
const HAIP_VP_SCHEME: &str = "haip-vp";

/// Extracts `credential_offer` and `credential_offer_uri` from URL query parameters.
////// Per OpenID4VCI / HAIP specifications, these parameters are mutually exclusive.
/// Duplicate parameter names are rejected as invalid.
////// # Errors
////// Returns an error if:
/// - Both parameters are present (mutually exclusive)
/// - Neither parameter is present
/// - Duplicate parameter names are detected (e.g., `credential_offer=A&credential_offer=B`)
pub fn extract_credential_offer_params(url: &Url) -> Result<CredentialOfferParams> {
    let mut credential_offer = None;
    let mut credential_offer_uri = None;

    for (k, v) in url.query_pairs() {
        match k.as_ref() {
            "credential_offer" => {
                if credential_offer.is_some() {
                    return Err(Error::DuplicateParameter("credential_offer"));
                }
                credential_offer = Some(v.into_owned());
            }
            "credential_offer_uri" => {
                if credential_offer_uri.is_some() {
                    return Err(Error::DuplicateParameter("credential_offer_uri"));
                }
                credential_offer_uri = Some(v.into_owned());
            }
            _ => {}
        }
    }

    match (credential_offer, credential_offer_uri) {
        (Some(_), Some(_)) => Err(Error::MutuallyExclusive(
            "credential_offer",
            "credential_offer_uri",
        )),
        (Some(json), None) => Ok(CredentialOfferParams::ByValue(json)),
        (None, Some(uri)) => Ok(CredentialOfferParams::ByReference(uri)),
        (None, None) => Err(Error::MissingParameter(
            "credential_offer or credential_offer_uri",
        )),
    }
}

/// Result of extracting credential offer parameters from a URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialOfferParams {
    /// Credential offer passed by value (embedded JSON).
    ByValue(String),
    /// Credential offer passed by reference (URL to fetch).
    ByReference(String),
}

/// Parsed HAIP VCI URI parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HaipVciUri {
    pub source: HaipVciSource,
}

/// Source of a HAIP VCI credential offer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HaipVciSource {
    ByValue(String),
    ByReference(String),
}

/// Parsed HAIP VP URI parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HaipVpUri {
    pub params: Vec<(String, String)>,
}

impl HaipVpUri {
    /// Converts parameters to a JSON object suitable for `AuthorizationRequest` deserialization.
    ///
    /// This is useful for constructing an authorization request from URI parameters.
    ///
    /// Note: Malformed JSON strings in parameter values are silently treated as plain strings.
    /// This is intentional for best-effort conversion where invalid JSON gracefully degrades
    /// to string representation.
    pub fn to_json(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        for (key, value) in &self.params {
            let json_value = serde_json::from_str(value)
                .unwrap_or_else(|_| serde_json::Value::String(value.clone()));
            map.insert(key.clone(), json_value);
        }
        serde_json::Value::Object(map)
    }
}

/// Parses `haip-vci://` URIs. Returns error if both `credential_offer` and
/// `credential_offer_uri` are present, or if neither is present, or if duplicates of either parameter.
pub fn parse_haip_vci_uri(uri: &str) -> Result<HaipVciUri> {
    let parsed = Url::parse(uri).map_err(|e| Error::MalformedUri(e.to_string()))?;

    if parsed.scheme().to_lowercase() != HAIP_VCI_SCHEME {
        return Err(Error::InvalidScheme(parsed.scheme().to_string()));
    }

    let params = extract_credential_offer_params(&parsed)?;
    Ok(HaipVciUri {
        source: match params {
            CredentialOfferParams::ByValue(json) => HaipVciSource::ByValue(json),
            CredentialOfferParams::ByReference(uri) => HaipVciSource::ByReference(uri),
        },
    })
}

/// Parses `haip-vp://` URIs, extracting query parameters for authorization requests.
pub fn parse_haip_vp_uri(uri: &str) -> Result<HaipVpUri> {
    let parsed = Url::parse(uri).map_err(|e| Error::MalformedUri(e.to_string()))?;

    if parsed.scheme().to_lowercase() != HAIP_VP_SCHEME {
        return Err(Error::InvalidScheme(parsed.scheme().to_string()));
    }

    Ok(HaipVpUri {
        params: parsed
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect(),
    })
}

/// Parses `openid4vp://` or `haip-vp://` URIs.
pub fn parse_vp_uri(uri: &str) -> Result<HaipVpUri> {
    let parsed = Url::parse(uri).map_err(|e| Error::MalformedUri(e.to_string()))?;

    let scheme = parsed.scheme().to_lowercase();
    if scheme != HAIP_VP_SCHEME && scheme != "openid4vp" {
        return Err(Error::InvalidScheme(parsed.scheme().to_string()));
    }

    Ok(HaipVpUri {
        params: parsed
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect(),
    })
}

/// Parses `openid-credential-offer://` or `haip-vci://` URIs.
/// Returns error if both `credential_offer` and `credential_offer_uri` are present,
/// or if neither is present, or if duplicates of either parameter are detected.
pub fn parse_credential_offer_uri(uri: &str) -> Result<HaipVciUri> {
    let parsed = Url::parse(uri).map_err(|e| Error::MalformedUri(e.to_string()))?;

    let scheme = parsed.scheme().to_lowercase();
    if scheme != HAIP_VCI_SCHEME && scheme != "openid-credential-offer" {
        return Err(Error::InvalidScheme(parsed.scheme().to_string()));
    }

    let params = extract_credential_offer_params(&parsed)?;
    Ok(HaipVciUri {
        source: match params {
            CredentialOfferParams::ByValue(json) => HaipVciSource::ByValue(json),
            CredentialOfferParams::ByReference(uri) => HaipVciSource::ByReference(uri),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_haip_vci_by_value() {
        let uri = "haip-vci://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fissuer.example.com%22%7D";
        let result = parse_haip_vci_uri(uri).unwrap();
        match result.source {
            HaipVciSource::ByValue(json) => assert!(json.contains("credential_issuer")),
            HaipVciSource::ByReference(_) => panic!("expected by value"),
        }
    }

    #[test]
    fn parse_haip_vci_by_reference() {
        let uri = "haip-vci://?credential_offer_uri=https%3A%2F%2Fissuer.example.com%2Foffer";
        let result = parse_haip_vci_uri(uri).unwrap();
        match result.source {
            HaipVciSource::ByReference(url) => assert_eq!(url, "https://issuer.example.com/offer"),
            HaipVciSource::ByValue(_) => panic!("expected by reference"),
        }
    }

    #[test]
    fn parse_haip_vci_rejects_both_parameters() {
        let uri = "haip-vci://?credential_offer=%7B%7D&credential_offer_uri=https://example.com";
        let err = parse_haip_vci_uri(uri).unwrap_err();
        assert!(matches!(
            err,
            Error::MutuallyExclusive("credential_offer", "credential_offer_uri")
        ));
    }

    #[test]
    fn parse_haip_vci_rejects_missing_parameter() {
        let uri = "haip-vci://?other=value";
        let err = parse_haip_vci_uri(uri).unwrap_err();
        assert!(matches!(err, Error::MissingParameter(_)));
    }

    #[test]
    fn parse_haip_vci_rejects_wrong_scheme() {
        let uri = "openid-credential-offer://?credential_offer=%7B%7D";
        let err = parse_haip_vci_uri(uri).unwrap_err();
        assert!(matches!(err, Error::InvalidScheme(_)));
    }

    #[test]
    fn parse_haip_vci_rejects_malformed_uri() {
        let uri = "haip-vci://[invalid";
        let err = parse_haip_vci_uri(uri).unwrap_err();
        assert!(matches!(err, Error::MalformedUri(_)));
    }

    #[test]
    fn parse_haip_vp_basic() {
        let uri = "haip-vp://?client_id=verifier&request_uri=https%3A%2F%2Fexample.com";
        let result = parse_haip_vp_uri(uri).unwrap();
        assert_eq!(result.params.len(), 2);
    }

    #[test]
    fn parse_haip_vp_empty_params() {
        let uri = "haip-vp://";
        let result = parse_haip_vp_uri(uri).unwrap();
        assert!(result.params.is_empty());
    }

    #[test]
    fn parse_haip_vp_rejects_wrong_scheme() {
        let uri = "openid4vp://?client_id=verifier";
        let err = parse_haip_vp_uri(uri).unwrap_err();
        assert!(matches!(err, Error::InvalidScheme(_)));
    }

    #[test]
    fn parse_vp_uri_haip_scheme() {
        let uri = "haip-vp://?client_id=verifier&nonce=test";
        let result = parse_vp_uri(uri).unwrap();
        assert_eq!(result.params.len(), 2);
    }

    #[test]
    fn parse_vp_uri_openid4vp_scheme() {
        let uri = "openid4vp://?client_id=verifier&response_type=vp_token";
        let result = parse_vp_uri(uri).unwrap();
        assert_eq!(result.params.len(), 2);
    }

    #[test]
    fn parse_vp_uri_rejects_wrong_scheme() {
        let uri = "https://example.com?client_id=verifier";
        let err = parse_vp_uri(uri).unwrap_err();
        assert!(matches!(err, Error::InvalidScheme(_)));
    }

    #[test]
    fn parse_credential_offer_uri_haip_scheme() {
        let uri = "haip-vci://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fissuer.example.com%22%7D";
        let result = parse_credential_offer_uri(uri).unwrap();
        match result.source {
            HaipVciSource::ByValue(json) => assert!(json.contains("credential_issuer")),
            _ => panic!("expected by value"),
        }
    }

    #[test]
    fn parse_credential_offer_uri_openid_scheme() {
        let uri = "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fissuer.example.com%22%7D";
        let result = parse_credential_offer_uri(uri).unwrap();
        match result.source {
            HaipVciSource::ByValue(json) => assert!(json.contains("credential_issuer")),
            _ => panic!("expected by value"),
        }
    }

    #[test]
    fn parse_credential_offer_uri_by_reference() {
        let uri = "haip-vci://?credential_offer_uri=https%3A%2F%2Fissuer.example.com";
        let result = parse_credential_offer_uri(uri).unwrap();
        match result.source {
            HaipVciSource::ByReference(url) => assert_eq!(url, "https://issuer.example.com"),
            _ => panic!("expected by reference"),
        }
    }

    #[test]
    fn parse_credential_offer_uri_rejects_unknown_scheme() {
        let uri = "https://example.com?credential_offer=%7B%7D";
        let err = parse_credential_offer_uri(uri).unwrap_err();
        assert!(matches!(err, Error::InvalidScheme(_)));
    }

    #[test]
    fn parse_credential_offer_uri_rejects_both_parameters() {
        let uri = "haip-vci://?credential_offer=%7B%7D&credential_offer_uri=https://example.com";
        let err = parse_credential_offer_uri(uri).unwrap_err();
        assert!(matches!(err, Error::MutuallyExclusive(_, _)));
    }

    #[test]
    fn parse_haip_vci_rejects_duplicate_credential_offer() {
        let uri = "haip-vci://?credential_offer=%7B%7D&credential_offer=%7B%7D";
        let err = parse_haip_vci_uri(uri).unwrap_err();
        assert!(matches!(err, Error::DuplicateParameter(_)));
    }

    #[test]
    fn parse_credential_offer_uri_rejects_duplicate_credential_offer() {
        let uri =
            "haip-vci://?credential_offer=%7B%7D&credential_offer=%7B%22test%22%3A%22value%22%7D";
        let err = parse_credential_offer_uri(uri).unwrap_err();
        assert!(matches!(err, Error::DuplicateParameter(_)));
    }

    #[test]
    fn haip_vp_uri_to_json() {
        let uri = "haip-vp://?client_id=verifier&response_type=vp_token&response_mode=direct_post";
        let result = parse_haip_vp_uri(uri).unwrap();
        let json = result.to_json();

        assert_eq!(json.get("client_id").unwrap().as_str(), Some("verifier"));
        assert_eq!(
            json.get("response_type").unwrap().as_str(),
            Some("vp_token")
        );
        assert_eq!(
            json.get("response_mode").unwrap().as_str(),
            Some("direct_post")
        );
    }
}
