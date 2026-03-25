//! Claims Path Pointer type as defined in [OpenID4VCI Appendix C].
//!
//! [OpenID4VCI Appendix C]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-C

use crate::errors::EmptyClaimPathError;
use serde::{Deserialize, Serialize, de::Deserializer};
use serde_json::Value;

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
    /// Attempts to create a new claims path pointer.
    ///
    /// Returns an error if the path is empty.
    pub fn try_new(elements: Vec<ClaimPathElement>) -> Result<Self, EmptyClaimPathError> {
        if elements.is_empty() {
            return Err(EmptyClaimPathError);
        }
        Ok(Self(elements))
    }

    /// Creates a new claims path pointer.
    ///
    /// # Panics
    ///
    /// Panics if the path is empty. Use [`try_new`](Self::try_new) for a
    /// fallible version that returns a `Result`.
    pub fn new(elements: Vec<ClaimPathElement>) -> Self {
        Self::try_new(elements).expect("claims path pointer must be non-empty")
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

    /// Selects claims from a JSON value using this path pointer.
    ///
    /// Returns a vector of selected values according to the OpenID4VCI spec:
    /// - String elements navigate into object properties
    /// - Index elements select array elements by position
    /// - Null elements select ALL elements in an array
    ///
    /// # Examples
    ///
    /// ```
    /// # use cloud_wallet_openid4vc::issuance::claim_path_pointer::ClaimPathPointer;
    /// # use serde_json::json;
    /// let credential = json!({
    ///     "name": "Arthur Dent",
    ///     "nationalities": ["British", "Betelgeusian"]
    /// });
    ///
    /// // Select single claim
    /// let path: ClaimPathPointer = serde_json::from_str(r#"["name"]"#).unwrap();
    /// let selected = path.select(&credential);
    /// assert_eq!(selected.len(), 1);
    /// assert_eq!(selected[0], json!("Arthur Dent"));
    ///
    /// // Select array element by index
    /// let path: ClaimPathPointer = serde_json::from_str(r#"["nationalities", 1]"#).unwrap();
    /// let selected = path.select(&credential);
    /// assert_eq!(selected[0], json!("Betelgeusian"));
    /// ```
    pub fn select(&self, value: &Value) -> Vec<Value> {
        let mut results = vec![value.clone()];

        for element in &self.0 {
            results = results
                .into_iter()
                .flat_map(|v| self.select_one(&v, element))
                .collect();
        }

        results
    }

    /// Applies a single path element to a value, returning matching values.
    fn select_one(&self, value: &Value, element: &ClaimPathElement) -> Vec<Value> {
        match (value, element) {
            (Value::Object(obj), ClaimPathElement::String(key)) => {
                obj.get(key).cloned().into_iter().collect()
            }
            (Value::Array(arr), ClaimPathElement::Index(idx)) => {
                arr.get(*idx as usize).cloned().into_iter().collect()
            }
            (Value::Array(arr), ClaimPathElement::Null) => arr.clone(),
            _ => vec![],
        }
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
    use serde_json::json;

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
    fn test_empty_path_returns_error() {
        let result = ClaimPathPointer::try_new(vec![]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.to_string(), "claims path pointer must be non-empty");
    }

    /// Test case from OpenID4VCI spec Appendix C.3
    /// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-C
    ///
    /// Uses the full example credential from the spec and tests that claim path
    /// pointers correctly select the expected values.
    #[test]
    fn test_spec_examples_with_full_payload() {
        // Full example credential from OpenID4VCI spec Appendix C.3
        let credential = json!({
            "name": "Arthur Dent",
            "address": {
                "street_address": "42 Market Street",
                "locality": "Milliways",
                "postal_code": "12345"
            },
            "degrees": [
                {
                    "type": "Bachelor of Science",
                    "university": "University of Betelgeuse"
                },
                {
                    "type": "Master of Science",
                    "university": "University of Betelgeuse"
                }
            ],
            "nationalities": ["British", "Betelgeusian"]
        });

        // ["name"]: The claim name with the value Arthur Dent is selected.
        let path: ClaimPathPointer = serde_json::from_str(r#"["name"]"#).unwrap();
        let selected = path.select(&credential);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0], json!("Arthur Dent"));

        // ["address"]: The claim address with its sub-claims as the value is selected.
        let path: ClaimPathPointer = serde_json::from_str(r#"["address"]"#).unwrap();
        let selected = path.select(&credential);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0]["street_address"], json!("42 Market Street"));
        assert_eq!(selected[0]["locality"], json!("Milliways"));

        // ["address", "street_address"]: The claim street_address with the value 42 Market Street is selected.
        let path: ClaimPathPointer =
            serde_json::from_str(r#"["address","street_address"]"#).unwrap();
        let selected = path.select(&credential);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0], json!("42 Market Street"));

        // ["degrees", null, "type"]: All type claims in the degrees array are selected.
        let path: ClaimPathPointer = serde_json::from_str(r#"["degrees",null,"type"]"#).unwrap();
        let selected = path.select(&credential);
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0], json!("Bachelor of Science"));
        assert_eq!(selected[1], json!("Master of Science"));

        // ["nationalities", 1]: The second nationality is selected.
        let path: ClaimPathPointer = serde_json::from_str(r#"["nationalities",1]"#).unwrap();
        let selected = path.select(&credential);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0], json!("Betelgeusian"));
    }
}
