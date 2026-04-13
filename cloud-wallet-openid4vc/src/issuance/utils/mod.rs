pub mod pkce;

/// Returns `true` when `b` falls within the allowed character set for
/// `error_description` values across OpenID4VCI error responses:
///
/// `%x20-21 / %x23-5B / %x5D-7E` i.e Printable ASCII excluding double-quote and backslash
///
/// This is printable ASCII *excluding* `"` (0x22), `\` (0x5C), and DEL
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
    fn space_is_allowed() {
        assert!(is_allowed_ascii_byte(b' '));
    }

    #[test]
    fn exclamation_mark_is_allowed() {
        assert!(is_allowed_ascii_byte(b'!'));
    }

    #[test]
    fn hash_is_allowed() {
        assert!(is_allowed_ascii_byte(b'#'));
    }

    #[test]
    fn tilde_upper_boundary_is_allowed() {
        assert!(is_allowed_ascii_byte(b'~'));
    }

    #[test]
    fn alphanumeric_characters_are_allowed() {
        for b in b'A'..=b'Z' {
            assert!(
                is_allowed_ascii_byte(b),
                "uppercase {b:#04x} should be allowed"
            );
        }
        for b in b'a'..=b'z' {
            assert!(
                is_allowed_ascii_byte(b),
                "lowercase {b:#04x} should be allowed"
            );
        }
        for b in b'0'..=b'9' {
            assert!(is_allowed_ascii_byte(b), "digit {b:#04x} should be allowed");
        }
    }

    #[test]
    fn right_bracket_just_past_backslash_is_allowed() {
        assert!(is_allowed_ascii_byte(b']'));
    }

    #[test]
    fn double_quote_is_rejected() {
        assert!(!is_allowed_ascii_byte(b'"'));
    }

    #[test]
    fn backslash_is_rejected() {
        assert!(!is_allowed_ascii_byte(b'\\'));
    }

    #[test]
    fn del_is_rejected() {
        assert!(!is_allowed_ascii_byte(0x7F));
    }

    #[test]
    fn null_byte_is_rejected() {
        assert!(!is_allowed_ascii_byte(0x00));
    }

    #[test]
    fn control_characters_are_rejected() {
        for b in 0x00..0x20u8 {
            assert!(
                !is_allowed_ascii_byte(b),
                "control char {b:#04x} should be rejected"
            );
        }
    }

    #[test]
    fn high_bytes_above_tilde_are_rejected() {
        for b in 0x7F..=0xFFu8 {
            assert!(
                !is_allowed_ascii_byte(b),
                "byte {b:#04x} should be rejected"
            );
        }
    }

    #[test]
    fn exhaustive_range_matches_spec() {
        for b in 0x00..=0xFFu16 {
            let b = b as u8;
            let expected = matches!(b, 0x20..=0x21 | 0x23..=0x5B | 0x5D..=0x7E);
<<<<<<< HEAD:cloud-wallet-openid4vc/src/issuance/utils/mod.rs
=======

>>>>>>> ce01eb7 (fix fmt and typo issue):cloud-wallet-openid4vc/src/issuance/utils.rs
            assert_eq!(is_allowed_ascii_byte(b), expected, "byte {b:#04x} mismatch");
        }
    }
}
