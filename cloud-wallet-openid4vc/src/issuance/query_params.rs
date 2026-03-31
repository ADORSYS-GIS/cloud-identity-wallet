use percent_encoding::percent_decode_str;

use crate::errors::{Error, ErrorKind};

/// A parsed, duplicate-free set of query parameters.
#[derive(Debug)]
pub struct QueryParams {
    pairs: Vec<(String, String)>,
}

impl QueryParams {
    /// Parses a raw query string, **rejecting** duplicate occurrences of any
    /// key listed in `recognized`.
    ///
    /// Percent-encoding and `+`-as-space are decoded for every key and value.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::InvalidAuthorizationResponse`] if a key that
    /// appears in `recognized` is present more than once.
    pub fn parse(query: &str, recognized: &[&str]) -> Result<Self, Error> {
        let pairs: Vec<(String, String)> = query
            .split('&')
            .filter_map(|pair| {
                let mut parts = pair.splitn(2, '=');
                let key = parts.next()?.trim();
                let value = parts.next().unwrap_or("");

                if key.is_empty() {
                    return None;
                }

                Some((decode_form_value(key), decode_form_value(value)))
            })
            .collect();

        // Reject duplicate recognized parameters.
        for key in recognized {
            let count = pairs.iter().filter(|(k, _)| k == key).count();
            if count > 1 {
                return Err(Error::message(
                    ErrorKind::InvalidAuthorizationResponse,
                    format!("duplicate '{key}' parameter in authorization response"),
                ));
            }
        }

        Ok(Self { pairs })
    }

    /// Returns the value for `key`, or `None` if absent.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.pairs
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// Decodes a single `application/x-www-form-urlencoded` value.
///
/// Replaces `+` with a space, then applies percent-decoding.
fn decode_form_value(s: &str) -> String {
    let plus_decoded = s.replace('+', " ");
    percent_decode_str(&plus_decoded)
        .decode_utf8_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECOGNIZED: &[&str] = &["code", "state"];

    #[test]
    fn parses_simple_pair() {
        let params = QueryParams::parse("code=abc123", RECOGNIZED).unwrap();
        assert_eq!(params.get("code"), Some("abc123"));
        assert_eq!(params.get("state"), None);
    }

    #[test]
    fn parses_multiple_pairs() {
        let params = QueryParams::parse("code=abc&state=xyz", RECOGNIZED).unwrap();
        assert_eq!(params.get("code"), Some("abc"));
        assert_eq!(params.get("state"), Some("xyz"));
    }

    #[test]
    fn decodes_percent_encoding() {
        let params = QueryParams::parse("state=state%3Dvalue%26other%3Ddata", RECOGNIZED).unwrap();
        assert_eq!(params.get("state"), Some("state=value&other=data"));
    }

    #[test]
    fn decodes_plus_as_space() {
        let params = QueryParams::parse("state=hello+world", RECOGNIZED).unwrap();
        assert_eq!(params.get("state"), Some("hello world"));
    }

    #[test]
    fn rejects_duplicate_recognized_key() {
        let err = QueryParams::parse("code=a&code=b", RECOGNIZED).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidAuthorizationResponse);
        assert!(err.to_string().contains("duplicate 'code'"));
    }

    #[test]
    fn allows_duplicate_unrecognized_key() {
        // Unrecognized keys are not subject to duplicate detection.
        let params = QueryParams::parse("code=abc&extra=1&extra=2", RECOGNIZED).unwrap();
        assert_eq!(params.get("code"), Some("abc"));
    }

    #[test]
    fn ignores_empty_key_segments() {
        let params = QueryParams::parse("&code=abc&&", RECOGNIZED).unwrap();
        assert_eq!(params.get("code"), Some("abc"));
    }
}
