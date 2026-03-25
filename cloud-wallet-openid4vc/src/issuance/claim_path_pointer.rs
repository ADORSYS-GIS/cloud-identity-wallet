//! Claims Path Pointer type as defined in [OpenID4VCI Appendix C].
//!
//! [OpenID4VCI Appendix C]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-C

use serde::{Deserialize, Serialize, de::Deserializer};

/// A single element of a claims path pointer.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ClaimPathElement {
    String(String),
    Index(u64),
    Null,
}

impl From<String> for ClaimPathElement {
    fn from(s: String) -> Self {
        Self::String(s)
    }
}

impl From<&str> for ClaimPathElement {
    fn from(s: &str) -> Self {
        Self::String(s.to_string())
    }
}

impl From<usize> for ClaimPathElement {
    fn from(i: usize) -> Self {
        Self::Index(i as u64)
    }
}

impl From<u64> for ClaimPathElement {
    fn from(i: u64) -> Self {
        Self::Index(i)
    }
}

impl std::fmt::Display for ClaimPathElement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::String(s) => write!(f, "\"{s}\""),
            Self::Index(i) => write!(f, "{i}"),
            Self::Null => write!(f, "null"),
        }
    }
}

/// A claims path pointer into a Verifiable Credential.
///
/// Non-empty array of path elements. For ISO mdoc, first element is namespace,
/// second is data element identifier.
///
/// # Examples
///
/// ```
/// # use cloud_wallet_openid4vc::issuance::claim_path_pointer::{ClaimPathPointer, ClaimPathElement};
/// // Path to claim within a JSON credential
/// let path = ClaimPathPointer::new(vec![
///     ClaimPathElement::from("credentialSubject"),
///     ClaimPathElement::from("given_name"),
/// ]);
///
/// // Path with array index
/// let path = ClaimPathPointer::new(vec![
///     ClaimPathElement::from("addresses"),
///     ClaimPathElement::from(0u64),
///     ClaimPathElement::from("street"),
/// ]);
///
/// // Path selecting all array elements (null selects all)
/// let path = ClaimPathPointer::new(vec![
///     ClaimPathElement::from("phone_numbers"),
///     ClaimPathElement::Null,
/// ]);
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct ClaimPathPointer(Vec<ClaimPathElement>);

impl<'de> Deserialize<'de> for ClaimPathPointer {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec: Vec<ClaimPathElement> = Vec::deserialize(deserializer)?;
        if vec.is_empty() {
            return Err(serde::de::Error::custom(
                "claims path pointer must be non-empty",
            ));
        }
        Ok(Self(vec))
    }
}

impl ClaimPathPointer {
    /// Creates a new claims path pointer.
    ///
    /// # Panics
    ///
    /// Panics if the path is empty.
    pub fn new(elements: Vec<ClaimPathElement>) -> Self {
        assert!(
            !elements.is_empty(),
            "claims path pointer must be non-empty"
        );
        Self(elements)
    }

    pub fn elements(&self) -> &[ClaimPathElement] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &ClaimPathElement> {
        self.0.iter()
    }

    /// Convenience method for the common case where all elements are string keys.
    pub fn from_strings<I, S>(strings: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let elements: Vec<ClaimPathElement> = strings
            .into_iter()
            .map(|s| ClaimPathElement::String(s.into()))
            .collect();
        Self::new(elements)
    }
}

impl std::fmt::Display for ClaimPathPointer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[")?;
        for (i, element) in self.0.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{element}")?;
        }
        write!(f, "]")
    }
}

impl From<Vec<ClaimPathElement>> for ClaimPathPointer {
    fn from(elements: Vec<ClaimPathElement>) -> Self {
        Self::new(elements)
    }
}

impl std::ops::Deref for ClaimPathPointer {
    type Target = [ClaimPathElement];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_elements() {
        let path = ClaimPathPointer::from_strings(["credentialSubject", "given_name"]);
        assert_eq!(path.len(), 2);
        assert_eq!(
            path.elements()[0],
            ClaimPathElement::from("credentialSubject")
        );
    }

    #[test]
    fn test_mixed_elements() {
        let path = ClaimPathPointer::new(vec![
            ClaimPathElement::from("addresses"),
            ClaimPathElement::from(0u64),
            ClaimPathElement::Null,
        ]);
        assert_eq!(path.len(), 3);
    }

    #[test]
    fn test_serde() {
        let path = ClaimPathPointer::new(vec![
            ClaimPathElement::from("credentialSubject"),
            ClaimPathElement::from("given_name"),
        ]);
        let json = serde_json::to_string(&path).unwrap();
        assert_eq!(json, r#"["credentialSubject","given_name"]"#);

        let parsed: ClaimPathPointer = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, path);
    }

    #[test]
    fn test_serde_with_null() {
        let json = r#"["phone_numbers",null]"#;
        let path: ClaimPathPointer = serde_json::from_str(json).unwrap();
        assert_eq!(path.len(), 2);
        assert_eq!(path.elements()[1], ClaimPathElement::Null);
    }

    #[test]
    fn test_serde_with_index() {
        let json = r#"["addresses",0,"street"]"#;
        let path: ClaimPathPointer = serde_json::from_str(json).unwrap();
        assert_eq!(path.elements()[1], ClaimPathElement::from(0u64));
    }

    #[test]
    fn test_serde_empty_rejected() {
        let json = r#"[]"#;
        let result: Result<ClaimPathPointer, _> = serde_json::from_str(json);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string()
                .contains("claims path pointer must be non-empty")
        );
    }

    #[test]
    #[should_panic(expected = "claims path pointer must be non-empty")]
    fn test_empty_path_panics() {
        let _ = ClaimPathPointer::new(vec![]);
    }

    /// Test case from OpenID4VCI spec Appendix C.3
    /// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-C
    #[test]
    fn test_spec_examples() {
        // ["name"]: The claim name with the value Arthur Dent is selected.
        let path: ClaimPathPointer = serde_json::from_str(r#"["name"]"#).unwrap();
        assert_eq!(path.elements().len(), 1);
        assert_eq!(
            path.elements()[0],
            ClaimPathElement::String("name".to_string())
        );

        // ["address"]: The claim address with its sub-claims as the value is selected.
        let path: ClaimPathPointer = serde_json::from_str(r#"["address"]"#).unwrap();
        assert_eq!(
            path.elements()[0],
            ClaimPathElement::String("address".to_string())
        );

        // ["address", "street_address"]: The claim street_address with the value 42 Market Street is selected.
        let path: ClaimPathPointer =
            serde_json::from_str(r#"["address","street_address"]"#).unwrap();
        assert_eq!(
            path.elements()[0],
            ClaimPathElement::String("address".to_string())
        );
        assert_eq!(
            path.elements()[1],
            ClaimPathElement::String("street_address".to_string())
        );

        // ["degrees", null, "type"]: All type claims in the degrees array are selected.
        let path: ClaimPathPointer = serde_json::from_str(r#"["degrees",null,"type"]"#).unwrap();
        assert_eq!(
            path.elements()[0],
            ClaimPathElement::String("degrees".to_string())
        );
        assert_eq!(path.elements()[1], ClaimPathElement::Null);
        assert_eq!(
            path.elements()[2],
            ClaimPathElement::String("type".to_string())
        );

        // ["nationalities", 1]: The second nationality is selected.
        let path: ClaimPathPointer = serde_json::from_str(r#"["nationalities",1]"#).unwrap();
        assert_eq!(
            path.elements()[0],
            ClaimPathElement::String("nationalities".to_string())
        );
        assert_eq!(path.elements()[1], ClaimPathElement::Index(1));
    }
}
