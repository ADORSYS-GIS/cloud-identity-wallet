//! Claims Path Pointer type as defined in [OpenID4VCI Appendix C].
//!
//! [OpenID4VCI Appendix C]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-C

use serde::{Deserialize, Serialize};

/// A single component of a claims path pointer.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PathComponent {
    String(String),
    Index(usize),
    /// Selects all elements of the currently selected array(s).
    #[serde(deserialize_with = "deserialize_null")]
    All,
}

/// Custom deserializer to accept any null value as `PathComponent::All`.
fn deserialize_null<'de, D>(deserializer: D) -> Result<(), D::Error>
where
    D: serde::Deserializer<'de>,
{
    let _ = <() as serde::Deserialize>::deserialize(deserializer)?;
    Ok(())
}

impl From<String> for PathComponent {
    fn from(s: String) -> Self {
        Self::String(s)
    }
}

impl From<&str> for PathComponent {
    fn from(s: &str) -> Self {
        Self::String(s.to_string())
    }
}

impl From<usize> for PathComponent {
    fn from(i: usize) -> Self {
        Self::Index(i)
    }
}

impl std::fmt::Display for PathComponent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::String(s) => write!(f, "\"{}\"", s),
            Self::Index(i) => write!(f, "{}", i),
            Self::All => write!(f, "null"),
        }
    }
}

/// A claims path pointer into a Verifiable Credential.
///
/// Non-empty array of path components. For ISO mdoc, first component is namespace,
/// second is data element identifier.
///
/// # Examples
///
/// ```
/// # use cloud_wallet_openid4vc::issuance::claim_path_pointer::{ClaimPathPointer, PathComponent};
/// // Path to claim within a JSON credential
/// let path = ClaimPathPointer::new(vec![
///     PathComponent::from("credentialSubject"),
///     PathComponent::from("given_name"),
/// ]);
///
/// // Path with array index
/// let path = ClaimPathPointer::new(vec![
///     PathComponent::from("addresses"),
///     PathComponent::from(0),
///     PathComponent::from("street"),
/// ]);
///
/// // Path selecting all array elements
/// let path = ClaimPathPointer::new(vec![
///     PathComponent::from("phone_numbers"),
///     PathComponent::All,
/// ]);
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ClaimPathPointer(Vec<PathComponent>);

impl ClaimPathPointer {
    /// Creates a new claims path pointer.
    ///
    /// # Panics
    ///
    /// Panics if the path is empty.
    pub fn new(components: Vec<PathComponent>) -> Self {
        assert!(
            !components.is_empty(),
            "claims path pointer must be non-empty"
        );
        Self(components)
    }

    pub fn components(&self) -> &[PathComponent] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &PathComponent> {
        self.0.iter()
    }

    /// Convenience method for the common case where all components are string keys.
    pub fn from_strings<I, S>(strings: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let components: Vec<PathComponent> = strings
            .into_iter()
            .map(|s| PathComponent::String(s.into()))
            .collect();
        Self::new(components)
    }
}

impl std::fmt::Display for ClaimPathPointer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[")?;
        for (i, component) in self.0.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", component)?;
        }
        write!(f, "]")
    }
}

impl From<Vec<PathComponent>> for ClaimPathPointer {
    fn from(components: Vec<PathComponent>) -> Self {
        Self::new(components)
    }
}

impl std::ops::Deref for ClaimPathPointer {
    type Target = [PathComponent];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_components() {
        let path = ClaimPathPointer::from_strings(["credentialSubject", "given_name"]);
        assert_eq!(path.len(), 2);
        assert_eq!(
            path.components()[0],
            PathComponent::from("credentialSubject")
        );
    }

    #[test]
    fn test_mixed_components() {
        let path = ClaimPathPointer::new(vec![
            PathComponent::from("addresses"),
            PathComponent::from(0),
            PathComponent::All,
        ]);
        assert_eq!(path.len(), 3);
    }

    #[test]
    fn test_serde() {
        let path = ClaimPathPointer::new(vec![
            PathComponent::from("credentialSubject"),
            PathComponent::from("given_name"),
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
        assert_eq!(path.components()[1], PathComponent::All);
    }

    #[test]
    fn test_serde_with_index() {
        let json = r#"["addresses",0,"street"]"#;
        let path: ClaimPathPointer = serde_json::from_str(json).unwrap();
        assert_eq!(path.components()[1], PathComponent::from(0));
    }

    #[test]
    #[should_panic(expected = "claims path pointer must be non-empty")]
    fn test_empty_path_panics() {
        let _ = ClaimPathPointer::new(vec![]);
    }
}
