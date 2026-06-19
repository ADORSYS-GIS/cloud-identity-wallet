//! Compact JWE serialization helpers (RFC 7516 §7.1).
//!
//! All functions in this module are `pub(crate)` — they are implementation
//! details shared between `encrypt` and `decrypt`.

use base64ct::{Base64UrlUnpadded, Encoding};

use crate::ecdh::{EcdhCurve, EcdhPublicKey};
use crate::error::{Error, ErrorKind, Result};
use crate::jwk::{self, B64, Key, OkpCurve};
use crate::utils::error_msg;

use super::header::JweHeader;

/// Serialize `header` to JSON and base64url-encode it.
///
/// The returned string is:
/// - The first segment of the compact JWE token.
/// - The AAD value for AES-GCM content encryption (used as raw ASCII bytes).
///
/// Must be called **after** all header fields (including `epk`) are populated.
pub(crate) fn serialize_header(header: &JweHeader) -> Result<String> {
    let json =
        serde_json::to_string(header).map_err(|e| Error::new(ErrorKind::Serialization, e))?;
    Ok(Base64UrlUnpadded::encode_string(json.as_bytes()))
}

/// Split a compact JWE token into its five base64url segments.
///
/// Returns `ErrorKind::Serialization` if the token does not contain exactly
/// four '.' separators.
pub(crate) fn parse_compact(token: &str) -> Result<[&str; 5]> {
    let parts: Vec<&str> = token.splitn(6, '.').collect();
    if parts.len() != 5 {
        return Err(error_msg(
            ErrorKind::Serialization,
            format!(
                "compact JWE must have 5 dot-separated parts, found {}",
                parts.len()
            ),
        ));
    }
    Ok([parts[0], parts[1], parts[2], parts[3], parts[4]])
}

/// Base64url-encode `bytes` without padding (RFC 4648 §5).
pub(crate) fn b64url_encode(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

/// Base64url-decode a string, returning `ErrorKind::Serialization` on failure.
pub(crate) fn b64url_decode(s: &str) -> Result<Vec<u8>> {
    Base64UrlUnpadded::decode_vec(s)
        .map_err(|e| error_msg(ErrorKind::Serialization, format!("base64url decode: {e}")))
}

/// Convert raw ephemeral public key bytes to a JWK for inclusion in the `epk` header field.
///
/// Encoding:
/// - P-256 / P-384 / P-521: `04 || x || y` split into x and y coordinates →
///   `jwk::Key::Ec { crv, x, y }`
/// - X25519: raw 32-byte scalar → `jwk::Key::Okp { crv: X25519, x }`
///
/// The curve determines the coordinate size; coordinate lengths are validated.
pub(crate) fn epk_bytes_to_jwk(curve: EcdhCurve, pub_bytes: &[u8]) -> Result<jwk::Jwk> {
    let key = match curve {
        EcdhCurve::X25519 => {
            if pub_bytes.len() != 32 {
                return Err(error_msg(
                    ErrorKind::KeyParsing,
                    format!(
                        "X25519 public key must be 32 bytes, got {}",
                        pub_bytes.len()
                    ),
                ));
            }
            Key::Okp(jwk::Okp {
                crv: OkpCurve::X25519,
                x: B64::new(pub_bytes),
                d: None,
            })
        }
        curve => {
            // NIST curves: pub_bytes = 04 || x || y
            let coord_size = nist_coord_size(curve)?;
            let expected_len = 1 + 2 * coord_size;
            if pub_bytes.len() != expected_len || pub_bytes[0] != 0x04 {
                return Err(error_msg(
                    ErrorKind::KeyParsing,
                    format!(
                        "{curve:?} public key must be {expected_len} bytes with 0x04 prefix, \
                         got {} bytes",
                        pub_bytes.len()
                    ),
                ));
            }
            let x = B64::new(&pub_bytes[1..1 + coord_size]);
            let y = B64::new(&pub_bytes[1 + coord_size..]);
            Key::Ec(jwk::Ec {
                crv: ecdh_curve_to_jwk_curve(curve)?,
                x,
                y,
                d: None,
            })
        }
    };
    Ok(jwk::Jwk {
        key,
        prm: jwk::Parameters::default(),
    })
}

/// Convert an `epk` JWK from the JWE header to an [`EcdhPublicKey`].
///
/// Returns the detected curve alongside the key so the caller can check it
/// matches the recipient's static key curve before performing agreement.
///
/// # Errors
/// [`ErrorKind::KeyParsing`] for unsupported key types (Ed25519, Ed448, X448,
/// RSA, symmetric), invalid coordinate lengths, or missing uncompressed-point
/// tag for NIST curves.
pub(crate) fn epk_jwk_to_ecdh_pub(epk: &jwk::Jwk) -> Result<(EcdhCurve, EcdhPublicKey)> {
    match &epk.key {
        Key::Okp(okp) => {
            if okp.d.is_some() {
                return Err(error_msg(
                    ErrorKind::KeyParsing,
                    "epk MUST NOT contain private key material (RFC 7516 §4.6.1.1)",
                ));
            }
            match okp.crv {
                OkpCurve::X25519 => {
                    let x: &[u8] = &okp.x;
                    let curve = EcdhCurve::X25519;
                    let pub_key = EcdhPublicKey::from_bytes(curve, x)?;
                    Ok((curve, pub_key))
                }
                _ => Err(error_msg(
                    ErrorKind::KeyParsing,
                    format!(
                        "OKP curve {:?} is not supported for ECDH-ES epk; only X25519 is",
                        okp.crv
                    ),
                )),
            }
        }
        Key::Ec(ec) => {
            if ec.d.is_some() {
                return Err(error_msg(
                    ErrorKind::KeyParsing,
                    "epk MUST NOT contain private key material (RFC 7516 §4.6.1.1)",
                ));
            }
            let curve = jwk_curve_to_ecdh_curve(ec.crv)?;
            let coord_size = nist_coord_size(curve)?;

            if ec.x.len() != coord_size || ec.y.len() != coord_size {
                return Err(error_msg(
                    ErrorKind::KeyParsing,
                    format!(
                        "{curve:?} epk coordinates must be {coord_size} bytes each, \
                         got x={} y={}",
                        ec.x.len(),
                        ec.y.len()
                    ),
                ));
            }

            // Reconstruct uncompressed SEC1 point: 04 || x || y
            let mut point = vec![0u8; 1 + 2 * coord_size];
            point[0] = 0x04;
            point[1..1 + coord_size].copy_from_slice(&ec.x);
            point[1 + coord_size..].copy_from_slice(&ec.y);

            let pub_key = EcdhPublicKey::from_bytes(curve, &point)?;
            Ok((curve, pub_key))
        }
        _ => Err(error_msg(
            ErrorKind::KeyParsing,
            "epk must be an EC or OKP key; RSA and symmetric keys are not supported",
        )),
    }
}

fn nist_coord_size(curve: EcdhCurve) -> Result<usize> {
    match curve {
        EcdhCurve::P256 => Ok(32),
        EcdhCurve::P384 => Ok(48),
        EcdhCurve::P521 => Ok(66),
        EcdhCurve::X25519 => Err(error_msg(
            ErrorKind::KeyParsing,
            "X25519 does not use NIST-style coordinates",
        )),
    }
}

fn ecdh_curve_to_jwk_curve(curve: EcdhCurve) -> Result<jwk::Curve> {
    match curve {
        EcdhCurve::P256 => Ok(jwk::Curve::P256),
        EcdhCurve::P384 => Ok(jwk::Curve::P384),
        EcdhCurve::P521 => Ok(jwk::Curve::P521),
        EcdhCurve::X25519 => Err(error_msg(
            ErrorKind::KeyParsing,
            "X25519 is OKP, not EC; use epk_bytes_to_jwk for dispatch",
        )),
    }
}

fn jwk_curve_to_ecdh_curve(curve: jwk::Curve) -> Result<EcdhCurve> {
    match curve {
        jwk::Curve::P256 => Ok(EcdhCurve::P256),
        jwk::Curve::P384 => Ok(EcdhCurve::P384),
        jwk::Curve::P521 => Ok(EcdhCurve::P521),
        jwk::Curve::P256K1 => Err(error_msg(
            ErrorKind::UnsupportedAlgorithm,
            "secp256k1 is not supported for ECDH-ES",
        )),
    }
}
