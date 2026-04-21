/// Returns `true` when `b` falls within the allowed character set for
/// `error_description` values across OpenID4VCI error responses:
///
/// (0x7F) — the same restriction defined in [RFC 6750 §3] and reused by
/// [OpenID4VCI §8.3.1.2].
///
/// [RFC 6750 §3]: https://www.rfc-editor.org/rfc/rfc6750#section-3
/// [OpenID4VCI §8.3.1.2]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-request-errors
pub(crate) fn is_allowed_ascii_byte(b: u8) -> bool {
    matches!(b, 0x20..=0x21 | 0x23..=0x5B | 0x5D..=0x7E)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exhaustive_range_matches_spec() {
        for b in 0x00..=0xFFu16 {
            let b = b as u8;
            let expected = matches!(b, 0x20..=0x21 | 0x23..=0x5B | 0x5D..=0x7E);

            assert_eq!(is_allowed_ascii_byte(b), expected, "byte {b:#04x} mismatch");
        }
    }
}
