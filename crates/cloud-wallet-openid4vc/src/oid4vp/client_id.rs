//! Client Identifier Prefix Parsing & Validation (OpenID4VP spec Section 5.9).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use url::Url;

/// Client identifier prefix types defined in OpenID4VP spec Section 5.9.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum ClientIdPrefix {
    /// Redirect URI-based client identifier. Format: `redirect_uri:<redirect-uri>`
    RedirectUri,
    /// OpenID Federation-based client identifier. Format: `openid_federation:<entity-id>`
    OpenidFederation,
    /// Decentralized identifier (DID). Format: `decentralized_identifier:<did>`
    DecentralizedIdentifier,
    /// Verifier attestation-based client identifier. Format: `verifier_attestation:<jwt-sub>`
    VerifierAttestation,
    /// X.509 certificate SAN DNS name-based client identifier. Format: `x509_san_dns:<dns-name>`
    X509SanDns,
    /// X.509 certificate hash-based client identifier. Format: `x509_hash:<cert-hash>`
    X509Hash,
    /// Origin-based client identifier (reserved for DC API). Format: `origin:<origin>`
    Origin,
}

impl ClientIdPrefix {
    /// Returns the prefix string as defined in the spec.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RedirectUri => "redirect_uri:",
            Self::OpenidFederation => "openid_federation:",
            Self::DecentralizedIdentifier => "decentralized_identifier:",
            Self::VerifierAttestation => "verifier_attestation:",
            Self::X509SanDns => "x509_san_dns:",
            Self::X509Hash => "x509_hash:",
            Self::Origin => "origin:",
        }
    }

    /// Returns all spec-defined prefixes.
    pub fn all() -> &'static [Self] {
        &[
            Self::RedirectUri,
            Self::OpenidFederation,
            Self::DecentralizedIdentifier,
            Self::VerifierAttestation,
            Self::X509SanDns,
            Self::X509Hash,
            Self::Origin,
        ]
    }
}

impl fmt::Display for ClientIdPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Error type for client identifier parsing failures.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ClientIdParseError {
    #[error("invalid redirect URI in redirect_uri client_id: {0}")]
    InvalidRedirectUri(String),
    #[error("invalid DNS name in x509_san_dns client_id: {0}")]
    InvalidDnsName(String),
    #[error("invalid origin in origin client_id: {0}")]
    InvalidOrigin(String),
}

/// A parsed client identifier with prefix information.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct ParsedClientId {
    /// The prefix type, or `None` for pre-registered clients.
    prefix: Option<ClientIdPrefix>,
    /// The identifier value (part after the prefix colon, or full string for pre-registered).
    value: String,
    /// The original full client_id string.
    raw: String,
}

impl ParsedClientId {
    /// Parses a raw client_id string according to OpenID4VP spec Section 5.9.
    ///
    /// For known prefixes, validates the value format:
    /// - `redirect_uri:`: validates that the value is a valid URI
    /// - `x509_san_dns:`: validates that the value is a valid DNS name
    /// - `origin:`: validates that the value is a valid origin URL
    /// - Other prefixes: accept any value (validation is separate)
    ///
    /// For unknown prefixes or no prefix, returns `None` for the prefix (pre-registered).
    pub fn parse(raw: impl Into<String>) -> Result<Self, ClientIdParseError> {
        let raw = raw.into();

        for prefix in ClientIdPrefix::all() {
            let prefix_str = prefix.as_str();
            if let Some(value) = raw.strip_prefix(prefix_str) {
                match prefix {
                    ClientIdPrefix::RedirectUri => validate_uri(value)?,
                    ClientIdPrefix::X509SanDns => validate_dns_name(value)?,
                    ClientIdPrefix::Origin => validate_origin(value)?,
                    ClientIdPrefix::OpenidFederation
                    | ClientIdPrefix::DecentralizedIdentifier
                    | ClientIdPrefix::VerifierAttestation
                    | ClientIdPrefix::X509Hash => {}
                }

                return Ok(Self {
                    prefix: Some(*prefix),
                    value: value.to_string(),
                    raw,
                });
            }
        }

        Ok(Self {
            prefix: None,
            value: raw.clone(),
            raw,
        })
    }

    /// Returns the prefix type, or `None` for pre-registered clients.
    pub fn prefix(&self) -> Option<ClientIdPrefix> {
        self.prefix
    }

    /// Returns the identifier value (part after the prefix colon, or full string).
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Returns the original full client_id string.
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// Returns `true` if this is a pre-registered client identifier (no recognized prefix).
    pub fn is_pre_registered(&self) -> bool {
        self.prefix.is_none()
    }

    /// Returns `true` if this is a redirect_uri client identifier.
    pub fn is_redirect_uri(&self) -> bool {
        matches!(self.prefix, Some(ClientIdPrefix::RedirectUri))
    }

    /// Returns `true` if this is an openid_federation client identifier.
    pub fn is_openid_federation(&self) -> bool {
        matches!(self.prefix, Some(ClientIdPrefix::OpenidFederation))
    }

    /// Returns `true` if this is a decentralized_identifier client identifier.
    pub fn is_decentralized_identifier(&self) -> bool {
        matches!(self.prefix, Some(ClientIdPrefix::DecentralizedIdentifier))
    }

    /// Returns `true` if this is a verifier_attestation client identifier.
    pub fn is_verifier_attestation(&self) -> bool {
        matches!(self.prefix, Some(ClientIdPrefix::VerifierAttestation))
    }

    /// Returns `true` if this is an x509_san_dns client identifier.
    pub fn is_x509_san_dns(&self) -> bool {
        matches!(self.prefix, Some(ClientIdPrefix::X509SanDns))
    }

    /// Returns `true` if this is an x509_hash client identifier.
    pub fn is_x509_hash(&self) -> bool {
        matches!(self.prefix, Some(ClientIdPrefix::X509Hash))
    }

    /// Returns `true` if this is an origin client identifier.
    pub fn is_origin(&self) -> bool {
        matches!(self.prefix, Some(ClientIdPrefix::Origin))
    }
}

impl fmt::Display for ParsedClientId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.raw)
    }
}

impl FromStr for ParsedClientId {
    type Err = ClientIdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for ParsedClientId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.raw)
    }
}

impl<'de> Deserialize<'de> for ParsedClientId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::parse(raw).map_err(serde::de::Error::custom)
    }
}

fn validate_uri(value: &str) -> Result<(), ClientIdParseError> {
    if value.is_empty() {
        return Err(ClientIdParseError::InvalidRedirectUri(
            "URI cannot be empty".to_string(),
        ));
    }

    Url::parse(value).map_err(|_| ClientIdParseError::InvalidRedirectUri(value.to_string()))?;

    Ok(())
}

fn validate_origin(value: &str) -> Result<(), ClientIdParseError> {
    let url =
        Url::parse(value).map_err(|_| ClientIdParseError::InvalidOrigin(value.to_string()))?;

    let scheme = url.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(ClientIdParseError::InvalidOrigin(format!(
            "scheme must be http or https, got: {scheme}"
        )));
    }

    if url.host_str().is_none() {
        return Err(ClientIdParseError::InvalidOrigin(format!(
            "missing host in origin: {value}"
        )));
    }

    Ok(())
}

fn validate_dns_name(value: &str) -> Result<(), ClientIdParseError> {
    if value.is_empty() {
        return Err(ClientIdParseError::InvalidDnsName(
            "DNS name cannot be empty".to_string(),
        ));
    }

    if value.len() > 253 {
        return Err(ClientIdParseError::InvalidDnsName(format!(
            "DNS name too long: {} characters (max 253)",
            value.len()
        )));
    }

    if value.starts_with('-') || value.starts_with('.') {
        return Err(ClientIdParseError::InvalidDnsName(format!(
            "DNS name cannot start with '-' or '.': {value}"
        )));
    }
    if value.ends_with('-') || value.ends_with('.') {
        return Err(ClientIdParseError::InvalidDnsName(format!(
            "DNS name cannot end with '-' or '.': {value}"
        )));
    }

    for label in value.split('.') {
        if label.is_empty() {
            return Err(ClientIdParseError::InvalidDnsName(format!(
                "DNS name has empty label: {value}"
            )));
        }

        if !label
            .chars()
            .next()
            .map(|c| c.is_ascii_alphanumeric())
            .unwrap_or(false)
        {
            return Err(ClientIdParseError::InvalidDnsName(format!(
                "DNS label must start with alphanumeric: {label}"
            )));
        }
        if !label
            .chars()
            .last()
            .map(|c| c.is_ascii_alphanumeric())
            .unwrap_or(false)
        {
            return Err(ClientIdParseError::InvalidDnsName(format!(
                "DNS label must end with alphanumeric: {label}"
            )));
        }

        for c in label.chars() {
            if !c.is_ascii_alphanumeric() && c != '-' {
                return Err(ClientIdParseError::InvalidDnsName(format!(
                    "DNS label contains invalid character '{c}': {value}"
                )));
            }
        }

        if label.len() > 63 {
            return Err(ClientIdParseError::InvalidDnsName(format!(
                "DNS label too long: {label} (max 63 characters)"
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_id_prefix_as_str() {
        assert_eq!(ClientIdPrefix::RedirectUri.as_str(), "redirect_uri:");
        assert_eq!(
            ClientIdPrefix::OpenidFederation.as_str(),
            "openid_federation:"
        );
        assert_eq!(
            ClientIdPrefix::DecentralizedIdentifier.as_str(),
            "decentralized_identifier:"
        );
        assert_eq!(
            ClientIdPrefix::VerifierAttestation.as_str(),
            "verifier_attestation:"
        );
        assert_eq!(ClientIdPrefix::X509SanDns.as_str(), "x509_san_dns:");
        assert_eq!(ClientIdPrefix::X509Hash.as_str(), "x509_hash:");
        assert_eq!(ClientIdPrefix::Origin.as_str(), "origin:");
    }

    #[test]
    fn test_all_prefixes() {
        let prefixes = ClientIdPrefix::all();
        assert_eq!(prefixes.len(), 7);
        assert!(prefixes.contains(&ClientIdPrefix::RedirectUri));
        assert!(prefixes.contains(&ClientIdPrefix::OpenidFederation));
        assert!(prefixes.contains(&ClientIdPrefix::DecentralizedIdentifier));
        assert!(prefixes.contains(&ClientIdPrefix::VerifierAttestation));
        assert!(prefixes.contains(&ClientIdPrefix::X509SanDns));
        assert!(prefixes.contains(&ClientIdPrefix::X509Hash));
        assert!(prefixes.contains(&ClientIdPrefix::Origin));
    }

    #[test]
    fn test_parse_redirect_uri_valid() {
        let parsed = ParsedClientId::parse("redirect_uri:https://client.example.org/cb").unwrap();
        assert_eq!(parsed.prefix(), Some(ClientIdPrefix::RedirectUri));
        assert_eq!(parsed.value(), "https://client.example.org/cb");
        assert!(parsed.is_redirect_uri());
        assert!(!parsed.is_pre_registered());
    }

    #[test]
    fn test_parse_redirect_uri_empty() {
        let result = ParsedClientId::parse("redirect_uri:");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_openid_federation() {
        let parsed =
            ParsedClientId::parse("openid_federation:https://federation-verifier.example.com")
                .unwrap();
        assert_eq!(parsed.prefix(), Some(ClientIdPrefix::OpenidFederation));
        assert_eq!(parsed.value(), "https://federation-verifier.example.com");
        assert!(parsed.is_openid_federation());
    }

    #[test]
    fn test_parse_decentralized_identifier() {
        let parsed = ParsedClientId::parse("decentralized_identifier:did:example:123").unwrap();
        assert_eq!(
            parsed.prefix(),
            Some(ClientIdPrefix::DecentralizedIdentifier)
        );
        assert_eq!(parsed.value(), "did:example:123");
        assert!(parsed.is_decentralized_identifier());
    }

    #[test]
    fn test_parse_verifier_attestation() {
        let jwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature";
        let parsed = ParsedClientId::parse(format!("verifier_attestation:{jwt}")).unwrap();
        assert_eq!(parsed.prefix(), Some(ClientIdPrefix::VerifierAttestation));
        assert_eq!(parsed.value(), jwt);
        assert!(parsed.is_verifier_attestation());
    }

    #[test]
    fn test_parse_x509_san_dns_valid() {
        let parsed = ParsedClientId::parse("x509_san_dns:client.example.org").unwrap();
        assert_eq!(parsed.prefix(), Some(ClientIdPrefix::X509SanDns));
        assert_eq!(parsed.value(), "client.example.org");
        assert!(parsed.is_x509_san_dns());
    }

    #[test]
    fn test_parse_x509_san_dns_invalid() {
        let result = ParsedClientId::parse("x509_san_dns:-invalid.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_x509_hash() {
        let hash = "Uvo3HtuIxuhC92rShpgqcT3YXwrqRxWEviRiA0OZszk";
        let parsed = ParsedClientId::parse(format!("x509_hash:{hash}")).unwrap();
        assert_eq!(parsed.prefix(), Some(ClientIdPrefix::X509Hash));
        assert_eq!(parsed.value(), hash);
        assert!(parsed.is_x509_hash());
    }

    #[test]
    fn test_parse_origin_valid() {
        let parsed = ParsedClientId::parse("origin:https://verifier.example.com").unwrap();
        assert_eq!(parsed.prefix(), Some(ClientIdPrefix::Origin));
        assert_eq!(parsed.value(), "https://verifier.example.com");
        assert!(parsed.is_origin());
    }

    #[test]
    fn test_parse_origin_invalid_scheme() {
        let result = ParsedClientId::parse("origin:ftp://example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_pre_registered() {
        let parsed = ParsedClientId::parse("my-client-123").unwrap();
        assert_eq!(parsed.prefix(), None);
        assert_eq!(parsed.value(), "my-client-123");
        assert!(parsed.is_pre_registered());
    }

    #[test]
    fn test_parse_unknown_prefix_falls_back() {
        let parsed = ParsedClientId::parse("unknown-prefix:value").unwrap();
        assert_eq!(parsed.prefix(), None);
        assert_eq!(parsed.value(), "unknown-prefix:value");
        assert!(parsed.is_pre_registered());
    }

    #[test]
    fn test_display() {
        let parsed = ParsedClientId::parse("redirect_uri:https://client.example.org/cb").unwrap();
        assert_eq!(
            format!("{parsed}"),
            "redirect_uri:https://client.example.org/cb"
        );
    }

    #[test]
    fn test_from_str() {
        let parsed: ParsedClientId = "x509_san_dns:client.example.org".parse().unwrap();
        assert_eq!(parsed.value(), "client.example.org");
    }

    #[test]
    fn test_serialize() {
        let parsed = ParsedClientId::parse("openid_federation:https://example.com").unwrap();
        let json = serde_json::to_string(&parsed).unwrap();
        assert_eq!(json, r#""openid_federation:https://example.com""#);
    }

    #[test]
    fn test_deserialize() {
        let parsed: ParsedClientId = serde_json::from_str(r#""x509_hash:abc123""#).unwrap();
        assert_eq!(parsed.value(), "abc123");
    }

    #[test]
    fn test_deserialize_invalid() {
        let result: Result<ParsedClientId, _> = serde_json::from_str(r#""x509_san_dns:-invalid""#);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_dns_name_valid() {
        assert!(validate_dns_name("example.com").is_ok());
        assert!(validate_dns_name("sub.example.com").is_ok());
        assert!(validate_dns_name("my-host.example.org").is_ok());
    }

    #[test]
    fn test_validate_dns_name_invalid() {
        assert!(validate_dns_name("").is_err());
        assert!(validate_dns_name("-example.com").is_err());
        assert!(validate_dns_name("example-.com").is_err());
        assert!(validate_dns_name("example.com-").is_err());
        assert!(validate_dns_name("example..com").is_err());
        assert!(validate_dns_name("example_.com").is_err());
    }

    #[test]
    fn test_validate_origin_valid() {
        assert!(validate_origin("https://example.com").is_ok());
        assert!(validate_origin("http://localhost").is_ok());
        assert!(validate_origin("https://example.com:8080").is_ok());
    }

    #[test]
    fn test_validate_origin_invalid() {
        assert!(validate_origin("not-a-url").is_err());
        assert!(validate_origin("ftp://example.com").is_err());
        assert!(validate_origin("https://").is_err());
    }

    #[test]
    fn test_equality_and_hashing() {
        let parsed1 = ParsedClientId::parse("redirect_uri:https://example.com").unwrap();
        let parsed2 = ParsedClientId::parse("redirect_uri:https://example.com").unwrap();
        let parsed3 = ParsedClientId::parse("redirect_uri:https://other.com").unwrap();

        assert_eq!(parsed1, parsed2);
        assert_ne!(parsed1, parsed3);

        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(parsed1.clone());
        assert!(set.contains(&parsed2));
        assert!(!set.contains(&parsed3));
    }
}
