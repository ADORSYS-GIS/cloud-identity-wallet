use super::*;
use crate::formats::mdoc::revocation::RevocationPolicy;

/// ISO 18013-5 Document Signer Certificate EKU OID (arc 1.0.18013.5.1.2).
/// Encoded as relative OID component integers for rcgen `ExtendedKeyUsagePurpose::Other`.
const DSC_EKU_OID: &[u64] = &[1, 0, 18013, 5, 1, 2];

/// The `validityInfo.signed` (and `validFrom`) timestamp used in `minimal_mso_cbor()`.
///
/// Must fall within the default DSC validity window used by `build_chain_params`
/// (`2023-12-01` – `2024-12-31`).  Change both together if the fixture dates ever move.
const MINIMAL_MSO_SIGNED: &str = "2024-01-01T00:00:00Z";

/// Builds an IACA root CA cert and a DSC cert signed by that IACA, returning
/// `(iaca_der, dsc_der, dsc_signing_key)` where `dsc_signing_key` is backed by
/// `aws-lc-rs` so that signatures produced by it can be verified by
/// `cloud_wallet_crypto::ecdsa::VerifyingKey`.
///
/// The `include_dsc_eku` flag controls whether the DSC carries the mandatory
/// ISO 18013-5 EKU OID; set it to `false` to exercise the missing-EKU path.
fn build_chain(include_dsc_eku: bool) -> (Vec<u8>, Vec<u8>, cloud_wallet_crypto::ecdsa::KeyPair) {
    build_chain_params(include_dsc_eku, None, None, None, None, None)
}

/// Parameterised version of [`build_chain`] for tests that need specific DSC validity
/// dates, per-country-code attributes, or stateOrProvinceName attributes.
///
/// - `dsc_validity`: `(not_before, not_after)` for the DSC; defaults to a 396-day window
///   (`2023-12-01` to `2024-12-31`) that covers the `minimal_mso_cbor()` `signed` timestamp.
/// - `iaca_country`: `CountryName` for the IACA subject DN (e.g. `"DE"`).
/// - `dsc_country`: `CountryName` for the DSC subject DN (e.g. `"FR"`).
/// - `iaca_state`: `stateOrProvinceName` for the IACA subject DN (e.g. `"California"`).
/// - `dsc_state`: `stateOrProvinceName` for the DSC subject DN (e.g. `"NewYork"`).
fn build_chain_params(
    include_dsc_eku: bool,
    dsc_validity: Option<(time::OffsetDateTime, time::OffsetDateTime)>,
    iaca_country: Option<&str>,
    dsc_country: Option<&str>,
    iaca_state: Option<&str>,
    dsc_state: Option<&str>,
) -> (Vec<u8>, Vec<u8>, cloud_wallet_crypto::ecdsa::KeyPair) {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyUsagePurpose,
    };
    let iaca_key = rcgen::KeyPair::generate().expect("rcgen key generation must succeed");
    let mut iaca_params =
        CertificateParams::new(vec!["IACA Root".to_string()]).expect("iaca params");
    iaca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    if let Some(c) = iaca_country {
        iaca_params.distinguished_name.push(DnType::CountryName, c);
    }
    if let Some(s) = iaca_state {
        iaca_params
            .distinguished_name
            .push(DnType::StateOrProvinceName, s);
    }
    let iaca_cert = iaca_params
        .self_signed(&iaca_key)
        .expect("self-signed IACA cert must succeed");
    let iaca_der: Vec<u8> = iaca_cert.der().to_vec();
    let iaca_issuer = Issuer::new(iaca_params, iaca_key);

    let dsc_aws_key =
        cloud_wallet_crypto::ecdsa::KeyPair::generate(cloud_wallet_crypto::ecdsa::Curve::P256)
            .expect("aws-lc-rs DSC key generation must succeed");

    let dsc_pkcs8 = dsc_aws_key.to_pkcs8_der();
    let dsc_rcgen_key = rcgen::KeyPair::from_der_and_sign_algo(
        &rustls_pki_types::PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(
            dsc_pkcs8,
        )),
        &rcgen::PKCS_ECDSA_P256_SHA256,
    )
    .expect("loading aws-lc-rs key into rcgen must succeed");

    // Default DSC validity: 396-day window that covers MINIMAL_MSO_SIGNED ("2024-01-01").
    // If MINIMAL_MSO_SIGNED changes, update these dates to keep the signed timestamp in-window.
    let (not_before, not_after) = dsc_validity.unwrap_or_else(|| {
        (
            OffsetDateTime::parse("2023-12-01T00:00:00Z", &Rfc3339).expect("fixed date must parse"),
            OffsetDateTime::parse("2024-12-31T23:59:59Z", &Rfc3339).expect("fixed date must parse"),
        )
    });

    let mut dsc_params = CertificateParams::new(vec!["DSC".to_string()]).expect("dsc params");
    dsc_params.is_ca = IsCa::NoCa;
    dsc_params.not_before = not_before;
    dsc_params.not_after = not_after;
    if include_dsc_eku {
        dsc_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::Other(DSC_EKU_OID.to_vec())];
    }
    if let Some(c) = dsc_country {
        dsc_params.distinguished_name.push(DnType::CountryName, c);
    }
    if let Some(s) = dsc_state {
        dsc_params
            .distinguished_name
            .push(DnType::StateOrProvinceName, s);
    }
    dsc_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let dsc_cert = dsc_params
        .signed_by(&dsc_rcgen_key, &iaca_issuer)
        .expect("DSC signing by IACA must succeed");
    let dsc_der: Vec<u8> = dsc_cert.der().to_vec();

    (iaca_der, dsc_der, dsc_aws_key)
}

/// Constructs the COSE Sig_Structure (RFC 9052 §4.4) and signs it with
/// `signing_key`, then assembles a raw `IssuerSigned` CBOR payload suitable
/// for `ParsedMdoc::parse`.
///
/// The unprotected header carries `x5chain` (label 33) as an array of two
/// DER-encoded certs: `[dsc_der, iaca_der]`.
///
/// If `tamper` is `true` the COSE signature bytes are altered after signing so
/// that signature verification fails while the payload structure remains valid.
fn build_issuer_signed_with_issuer_auth(
    mso_bytes: Vec<u8>,
    dsc_der: Vec<u8>,
    signing_key: &cloud_wallet_crypto::ecdsa::KeyPair,
    tamper: bool,
) -> String {
    // {1: -7} (ES256): a1 01 26
    let issuer_auth = signed_cose1(
        mso_bytes,
        vec![0xa1, 0x01, 0x26],
        Value::Array(vec![Value::Bytes(dsc_der)]),
        |tbs| {
            signing_key
                .sign_sha256(tbs)
                .expect("COSE signing must succeed")
                .to_vec()
        },
        tamper,
    );
    issuer_signed_b64(default_name_spaces(), issuer_auth)
}

/// Builds an `issuerAuth` signed with ESP256 (-9), the RFC 9864 fully-specified
/// P-256+SHA-256 identifier that replaces the polymorphic ES256 (-7).
fn build_issuer_signed_esp256(
    mso_bytes: Vec<u8>,
    dsc_der: Vec<u8>,
    signing_key: &cloud_wallet_crypto::ecdsa::KeyPair,
) -> String {
    // {1: -9} (ESP256): a1 01 28
    let issuer_auth = signed_cose1(
        mso_bytes,
        vec![0xa1, 0x01, 0x28],
        Value::Array(vec![Value::Bytes(dsc_der)]),
        |tbs| {
            signing_key
                .sign_sha256(tbs)
                .expect("ESP256 COSE signing must succeed")
                .to_vec()
        },
        false,
    );
    issuer_signed_b64(default_name_spaces(), issuer_auth)
}

/// Returns the MSO payload bytes as they appear inside the COSE_Sign1 `payload` field:
/// `Tag(24, bstr(mso_cbor))` per ISO 18013-5 §9.1.2 MobileSecurityObjectBytes.
fn minimal_mso_cbor() -> Vec<u8> {
    let validity_info = Value::Map(vec![
        (
            Value::Text("signed".into()),
            Value::Tag(0, Box::new(Value::Text(MINIMAL_MSO_SIGNED.into()))),
        ),
        (
            Value::Text("validFrom".into()),
            Value::Tag(0, Box::new(Value::Text(MINIMAL_MSO_SIGNED.into()))),
        ),
        (
            Value::Text("validUntil".into()),
            Value::Tag(0, Box::new(Value::Text("9998-01-01T00:00:00Z".into()))),
        ),
    ]);

    let mso = Value::Map(vec![
        (Value::Text("version".into()), Value::Text("1.0".into())),
        (
            Value::Text("digestAlgorithm".into()),
            Value::Text("SHA-256".into()),
        ),
        // valueDigests must have at least one namespace with at least one digest (32 bytes for SHA-256).
        (
            Value::Text("valueDigests".into()),
            Value::Map(vec![(
                Value::Text("org.iso.18013.5.1".into()),
                Value::Map(vec![(
                    Value::Integer(0.into()),
                    Value::Bytes(vec![0u8; 32]),
                )]),
            )]),
        ),
        // deviceKeyInfo must contain a deviceKey entry.
        (
            Value::Text("deviceKeyInfo".into()),
            Value::Map(vec![(
                Value::Text("deviceKey".into()),
                // Minimal COSE_Key: {1: 2, -1: 1} (kty=EC2, crv=P-256)
                Value::Map(vec![
                    (Value::Integer(1.into()), Value::Integer(2.into())),
                    (
                        Value::Integer(ciborium::value::Integer::from(-1i64)),
                        Value::Integer(1.into()),
                    ),
                ]),
            )]),
        ),
        (
            Value::Text("docType".into()),
            Value::Text("org.iso.18013.5.1.mDL".into()),
        ),
        (Value::Text("validityInfo".into()), validity_info),
    ]);

    cbor(&Value::Tag(24, Box::new(Value::Bytes(cbor(&mso)))))
}

/// Builds an IACA root and DSC cert chain for a given ECDSA curve and signing algorithm.
///
/// Both the IACA (self-signed P-256 CA) and DSC use the same validity window as the
/// default in [`build_chain_params`] so they cover [`MINIMAL_MSO_SIGNED`].
///
/// This is the shared implementation used by [`build_chain_p384`] and [`build_chain_p521`].
fn build_chain_ecdsa(
    curve: cloud_wallet_crypto::ecdsa::Curve,
    sign_algo: &'static rcgen::SignatureAlgorithm,
) -> (Vec<u8>, Vec<u8>, cloud_wallet_crypto::ecdsa::KeyPair) {
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyUsagePurpose,
    };

    let iaca_key = rcgen::KeyPair::generate().expect("rcgen key generation must succeed");
    let mut iaca_params =
        CertificateParams::new(vec!["IACA Root".to_string()]).expect("iaca params");
    iaca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let iaca_cert = iaca_params
        .self_signed(&iaca_key)
        .expect("self-signed IACA cert must succeed");
    let iaca_der: Vec<u8> = iaca_cert.der().to_vec();
    let iaca_issuer = Issuer::new(iaca_params, iaca_key);

    let dsc_aws_key = cloud_wallet_crypto::ecdsa::KeyPair::generate(curve)
        .expect("aws-lc-rs DSC key generation must succeed");

    let dsc_pkcs8 = dsc_aws_key.to_pkcs8_der();
    let dsc_rcgen_key = rcgen::KeyPair::from_der_and_sign_algo(
        &rustls_pki_types::PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(
            dsc_pkcs8,
        )),
        sign_algo,
    )
    .expect("loading DSC key into rcgen must succeed");

    let not_before =
        OffsetDateTime::parse("2023-12-01T00:00:00Z", &Rfc3339).expect("fixed date must parse");
    let not_after =
        OffsetDateTime::parse("2024-12-31T23:59:59Z", &Rfc3339).expect("fixed date must parse");

    let mut dsc_params = CertificateParams::new(vec!["DSC".to_string()]).expect("dsc params");
    dsc_params.is_ca = IsCa::NoCa;
    dsc_params.not_before = not_before;
    dsc_params.not_after = not_after;
    dsc_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::Other(DSC_EKU_OID.to_vec())];
    dsc_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let dsc_cert = dsc_params
        .signed_by(&dsc_rcgen_key, &iaca_issuer)
        .expect("DSC signing by IACA must succeed");
    let dsc_der: Vec<u8> = dsc_cert.der().to_vec();

    (iaca_der, dsc_der, dsc_aws_key)
}

fn build_chain_p521() -> (Vec<u8>, Vec<u8>, cloud_wallet_crypto::ecdsa::KeyPair) {
    build_chain_ecdsa(
        cloud_wallet_crypto::ecdsa::Curve::P521,
        &rcgen::PKCS_ECDSA_P521_SHA512,
    )
}

/// Like [`build_issuer_signed_with_issuer_auth`] but uses the ES512 algorithm (-36).
///
/// Protected header encodes `{1: -36}` and the payload is signed with SHA-512.
fn build_issuer_signed_with_issuer_auth_es512(
    mso_bytes: Vec<u8>,
    dsc_der: Vec<u8>,
    signing_key: &cloud_wallet_crypto::ecdsa::KeyPair,
) -> String {
    // {1: -36} (ES512): a1 01 38 23
    let issuer_auth = signed_cose1(
        mso_bytes,
        vec![0xa1, 0x01, 0x38, 0x23],
        Value::Array(vec![Value::Bytes(dsc_der)]),
        |tbs| {
            signing_key
                .sign_sha512(tbs)
                .expect("ES512 COSE signing must succeed")
                .to_vec()
        },
        false,
    );
    issuer_signed_b64(default_name_spaces(), issuer_auth)
}

/// Builds a chain where the DSC has a Key Usage extension but the `digitalSignature`
/// bit is NOT set (only `ContentCommitment`), exercising the key-usage rejection path.
fn build_chain_dsc_wrong_key_usage() -> (Vec<u8>, Vec<u8>, cloud_wallet_crypto::ecdsa::KeyPair) {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyUsagePurpose,
    };

    let iaca_key = rcgen::KeyPair::generate().expect("rcgen key generation must succeed");
    let mut iaca_params =
        CertificateParams::new(vec!["IACA Root".to_string()]).expect("iaca params");
    iaca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let iaca_cert = iaca_params
        .self_signed(&iaca_key)
        .expect("self-signed IACA cert must succeed");
    let iaca_der: Vec<u8> = iaca_cert.der().to_vec();
    let iaca_issuer = Issuer::new(iaca_params, iaca_key);

    let dsc_aws_key =
        cloud_wallet_crypto::ecdsa::KeyPair::generate(cloud_wallet_crypto::ecdsa::Curve::P256)
            .expect("aws-lc-rs DSC key generation must succeed");

    let dsc_pkcs8 = dsc_aws_key.to_pkcs8_der();
    let dsc_rcgen_key = rcgen::KeyPair::from_der_and_sign_algo(
        &rustls_pki_types::PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(
            dsc_pkcs8,
        )),
        &rcgen::PKCS_ECDSA_P256_SHA256,
    )
    .expect("loading key into rcgen must succeed");

    let not_before =
        OffsetDateTime::parse("2023-12-01T00:00:00Z", &Rfc3339).expect("fixed date must parse");
    let not_after =
        OffsetDateTime::parse("2024-12-31T23:59:59Z", &Rfc3339).expect("fixed date must parse");

    let mut dsc_params =
        CertificateParams::new(vec!["DSC Wrong KU".to_string()]).expect("dsc params");
    dsc_params.is_ca = IsCa::NoCa;
    dsc_params.not_before = not_before;
    dsc_params.not_after = not_after;
    dsc_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::Other(DSC_EKU_OID.to_vec())];
    // Key Usage extension IS present, but digitalSignature bit is NOT set.
    dsc_params.key_usages = vec![KeyUsagePurpose::ContentCommitment];
    dsc_params
        .distinguished_name
        .push(DnType::CommonName, "DSC Wrong KU");
    let dsc_cert = dsc_params
        .signed_by(&dsc_rcgen_key, &iaca_issuer)
        .expect("DSC signing must succeed");
    let dsc_der: Vec<u8> = dsc_cert.der().to_vec();

    (iaca_der, dsc_der, dsc_aws_key)
}

/// Builds an `IssuerSigned` where the x5chain unprotected header value is a
/// single `bstr` rather than `[bstr]`.  Per RFC 9360 §2 both forms are valid.
fn build_issuer_signed_single_bstr_x5chain(
    mso_bytes: Vec<u8>,
    dsc_der: Vec<u8>,
    signing_key: &cloud_wallet_crypto::ecdsa::KeyPair,
) -> String {
    // {1: -7} (ES256): a1 01 26 — single bstr x5chain (no array wrapper)
    let issuer_auth = signed_cose1(
        mso_bytes,
        vec![0xa1, 0x01, 0x26],
        Value::Bytes(dsc_der),
        |tbs| {
            signing_key
                .sign_sha256(tbs)
                .expect("COSE signing must succeed")
                .to_vec()
        },
        false,
    );
    issuer_signed_b64(default_name_spaces(), issuer_auth)
}

/// Builds an `IssuerSigned` with a multi-cert x5chain `[dsc, …]` (leaf-first).
///
/// The protected header is fixed to ES256; the signature covers `mso_bytes`
/// using `signing_key`.
fn build_issuer_signed_with_chain_x5chain(
    mso_bytes: Vec<u8>,
    cert_chain: Vec<Vec<u8>>,
    signing_key: &cloud_wallet_crypto::ecdsa::KeyPair,
) -> String {
    let x5chain = Value::Array(cert_chain.into_iter().map(Value::Bytes).collect());
    let issuer_auth = signed_cose1(
        mso_bytes,
        vec![0xa1, 0x01, 0x26],
        x5chain,
        |tbs| {
            signing_key
                .sign_sha256(tbs)
                .expect("COSE signing must succeed")
                .to_vec()
        },
        false,
    );
    issuer_signed_b64(default_name_spaces(), issuer_auth)
}

/// Builds an `IssuerSigned` with an arbitrary raw protected-header CBOR blob and
/// a dummy (zero-filled) COSE signature.  Intended for tests that verify errors
/// that fire before signature verification (e.g. unsupported algorithm).
fn build_issuer_signed_with_custom_alg(
    mso_bytes: Vec<u8>,
    dsc_der: Vec<u8>,
    protected_header_bytes: Vec<u8>,
) -> String {
    let issuer_auth = signed_cose1(
        mso_bytes,
        protected_header_bytes,
        Value::Array(vec![Value::Bytes(dsc_der)]),
        |_| vec![0u8; 64], // dummy sig — error fires before verification
        false,
    );
    issuer_signed_b64(default_name_spaces(), issuer_auth)
}

/// Builds a three-tier certificate chain: IACA root → Intermediate CA → DSC.
///
/// Returns `(iaca_der, intermediate_der, dsc_der, dsc_signing_key)`.
fn build_three_cert_chain() -> (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    cloud_wallet_crypto::ecdsa::KeyPair,
) {
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyUsagePurpose,
    };

    // IACA root (self-signed CA)
    let iaca_key = rcgen::KeyPair::generate().expect("IACA key generation must succeed");
    let mut iaca_params =
        CertificateParams::new(vec!["Three-tier IACA Root".to_string()]).expect("iaca params");
    iaca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let iaca_cert = iaca_params
        .self_signed(&iaca_key)
        .expect("IACA self-sign must succeed");
    let iaca_der: Vec<u8> = iaca_cert.der().to_vec();
    let iaca_issuer = Issuer::new(iaca_params, iaca_key);

    // Intermediate CA (signed by IACA root)
    let int_key = rcgen::KeyPair::generate().expect("Intermediate CA key generation must succeed");
    let mut int_params =
        CertificateParams::new(vec!["Three-tier Intermediate CA".to_string()]).expect("int params");
    int_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let int_cert = int_params
        .signed_by(&int_key, &iaca_issuer)
        .expect("Intermediate CA signing must succeed");
    let int_der: Vec<u8> = int_cert.der().to_vec();
    let int_issuer = Issuer::new(int_params, int_key);

    // DSC (signed by Intermediate CA)
    let dsc_aws_key =
        cloud_wallet_crypto::ecdsa::KeyPair::generate(cloud_wallet_crypto::ecdsa::Curve::P256)
            .expect("aws-lc-rs DSC key generation must succeed");

    let dsc_pkcs8 = dsc_aws_key.to_pkcs8_der();
    let dsc_rcgen_key = rcgen::KeyPair::from_der_and_sign_algo(
        &rustls_pki_types::PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(
            dsc_pkcs8,
        )),
        &rcgen::PKCS_ECDSA_P256_SHA256,
    )
    .expect("loading aws-lc-rs key into rcgen must succeed");

    let not_before =
        OffsetDateTime::parse("2023-12-01T00:00:00Z", &Rfc3339).expect("fixed date must parse");
    let not_after =
        OffsetDateTime::parse("2024-12-31T23:59:59Z", &Rfc3339).expect("fixed date must parse");

    let mut dsc_params =
        CertificateParams::new(vec!["Three-tier DSC".to_string()]).expect("dsc params");
    dsc_params.is_ca = IsCa::NoCa;
    dsc_params.not_before = not_before;
    dsc_params.not_after = not_after;
    dsc_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::Other(DSC_EKU_OID.to_vec())];
    dsc_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let dsc_cert = dsc_params
        .signed_by(&dsc_rcgen_key, &int_issuer)
        .expect("DSC signing by Intermediate CA must succeed");
    let dsc_der: Vec<u8> = dsc_cert.der().to_vec();

    (iaca_der, int_der, dsc_der, dsc_aws_key)
}

/// Constructs a minimal X.509 certificate with an Ed448 public key (OID `1.3.101.113`)
/// in the SubjectPublicKeyInfo, signed by the provided P-256 IACA key.
///
/// `rcgen 0.13` does not support Ed448 key generation, so the certificate is built from
/// raw DER.  The public key payload is all-zeros (57 bytes) — sufficient for the Ed448
/// OID check in `verify_issuer_signature`, which fires before any key-payload check.
///
/// Hand-assembled DER because rcgen 0.13 cannot generate Ed448 keys, and Ed448 is a
/// Table 22 curve we must recognize-and-reject. This is the only way to produce an
/// Ed448 DSC to exercise the OID-rejection path. Do not "simplify" with rcgen — it
/// cannot do this.
fn build_ed448_dsc_manual(
    iaca_cert_der: &[u8],
    iaca_key: &cloud_wallet_crypto::ecdsa::KeyPair,
) -> Vec<u8> {
    use x509_parser::prelude::{FromDer as _, X509Certificate};

    // Extract the IACA subject DER bytes — these become the DSC issuer field.
    let (_, iaca_x509) =
        X509Certificate::from_der(iaca_cert_der).expect("IACA cert must be parseable");
    let issuer_raw = iaca_x509.tbs_certificate.subject.as_raw().to_vec();

    fn len_bytes(n: usize) -> Vec<u8> {
        if n < 128 {
            vec![n as u8]
        } else if n < 256 {
            vec![0x81, n as u8]
        } else {
            vec![0x82, (n >> 8) as u8, (n & 0xff) as u8]
        }
    }
    fn tlv(tag: u8, body: Vec<u8>) -> Vec<u8> {
        let mut v = vec![tag];
        v.extend(len_bytes(body.len()));
        v.extend(body);
        v
    }
    fn seq(body: Vec<u8>) -> Vec<u8> {
        tlv(0x30, body)
    }
    fn set(body: Vec<u8>) -> Vec<u8> {
        tlv(0x31, body)
    }
    fn ctx_explicit(n: u8, body: Vec<u8>) -> Vec<u8> {
        tlv(0xa0 | n, body)
    }
    fn oid(components: &[u64]) -> Vec<u8> {
        fn base128(mut n: u64) -> Vec<u8> {
            if n == 0 {
                return vec![0];
            }
            let mut b = Vec::new();
            while n > 0 {
                b.push((n & 0x7f) as u8);
                n >>= 7;
            }
            b.reverse();
            for i in 0..b.len() - 1 {
                b[i] |= 0x80;
            }
            b
        }
        let mut bytes = base128(components[0] * 40 + components[1]);
        for &c in &components[2..] {
            bytes.extend(base128(c));
        }
        tlv(0x06, bytes)
    }
    fn integer_pos(b: Vec<u8>) -> Vec<u8> {
        let mut content = b;
        if content.first().is_some_and(|&x| x & 0x80 != 0) {
            content.insert(0, 0);
        }
        tlv(0x02, content)
    }
    fn bit_str(data: Vec<u8>) -> Vec<u8> {
        let mut c = vec![0x00]; // 0 unused bits
        c.extend(data);
        tlv(0x03, c)
    }
    fn octet_str(b: Vec<u8>) -> Vec<u8> {
        tlv(0x04, b)
    }
    fn bool_true() -> Vec<u8> {
        vec![0x01, 0x01, 0xff]
    }
    fn utc_time(s: &'static str) -> Vec<u8> {
        tlv(0x17, s.as_bytes().to_vec())
    }

    let version = ctx_explicit(0, integer_pos(vec![0x02])); // [0] INTEGER 2 → v3
    let serial = integer_pos(vec![0x01]); // serialNumber = 1
    let sig_alg_id = seq(oid(&[1, 2, 840, 10045, 4, 3, 2])); // ecdsa-with-SHA256
    let validity = seq({
        let mut b = utc_time("231201000000Z");
        b.extend(utc_time("241231235959Z"));
        b
    });
    let subject = seq(set(seq({
        let mut b = oid(&[2, 5, 4, 3]); // id-at-commonName
        b.extend(tlv(0x0c, b"Ed448DSC".to_vec())); // UTF8String
        b
    })));
    let spki = seq({
        let mut b = seq(oid(&[1, 3, 101, 113])); // id-Ed448, no params
        b.extend(bit_str(vec![0u8; 57])); // fake 57-byte public key
        b
    });
    // extendedKeyUsage (2.5.29.37), critical — ISO 18013-5 EKU
    let eku_ext = seq({
        let mut b = oid(&[2, 5, 29, 37]);
        b.extend(bool_true());
        // ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
        b.extend(octet_str(seq(oid(&[1, 0, 18013, 5, 1, 2]))));
        b
    });
    // keyUsage (2.5.29.15), critical, digitalSignature bit set
    let ku_ext = seq({
        let mut b = oid(&[2, 5, 29, 15]);
        b.extend(bool_true());
        b.extend(octet_str(tlv(0x03, vec![0x07, 0x80]))); // BIT STRING: 7 unused, bit 0
        b
    });
    let extensions = ctx_explicit(
        3,
        seq({
            let mut b = eku_ext;
            b.extend(ku_ext);
            b
        }),
    );
    let tbs = seq({
        let mut b = version;
        b.extend(serial);
        b.extend(sig_alg_id.clone());
        b.extend(issuer_raw);
        b.extend(validity);
        b.extend(subject);
        b.extend(spki);
        b.extend(extensions);
        b
    });

    // Sign TBSCertificate with the IACA's P-256 key (ASN.1 DER encoding for X.509).
    let mut sig_buf = [0u8; 80]; // P-256 ASN.1 ECDSA signature is at most ~72 bytes
    let sig = iaca_key
        .sign_sha256_asn1(&tbs, &mut sig_buf)
        .expect("ECDSA-P256 signing of TBSCertificate must succeed");

    // Assemble full Certificate = SEQUENCE { TBSCertificate, AlgorithmIdentifier, BIT STRING }
    seq({
        let mut b = tbs;
        b.extend(sig_alg_id);
        b.extend(bit_str(sig.to_vec()));
        b
    })
}

/// Builds a P-256 IACA root and a minimal Ed448 DSC signed by that root.
///
/// `rcgen 0.13` does not support Ed448 key generation; the DSC is assembled from raw
/// DER via [`build_ed448_dsc_manual`].  The DSC's SPKI holds OID `1.3.101.113`
/// (id-Ed448) with a fake public key — sufficient to exercise the OID rejection check.
fn build_ed448_dsc_chain() -> (Vec<u8>, Vec<u8>) {
    use rcgen::{BasicConstraints, CertificateParams, IsCa};

    // Use cloud_wallet_crypto key so we can sign the TBSCertificate for the DSC.
    let iaca_aws_key =
        cloud_wallet_crypto::ecdsa::KeyPair::generate(cloud_wallet_crypto::ecdsa::Curve::P256)
            .expect("P-256 IACA key generation must succeed");

    let iaca_pkcs8 = iaca_aws_key.to_pkcs8_der();
    let iaca_rcgen_key = rcgen::KeyPair::from_der_and_sign_algo(
        &rustls_pki_types::PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(
            iaca_pkcs8,
        )),
        &rcgen::PKCS_ECDSA_P256_SHA256,
    )
    .expect("loading P-256 key into rcgen must succeed");

    let mut iaca_params =
        CertificateParams::new(vec!["Ed448 Test IACA".to_string()]).expect("iaca params");
    iaca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let iaca_cert = iaca_params
        .self_signed(&iaca_rcgen_key)
        .expect("IACA self-sign must succeed");
    let iaca_der: Vec<u8> = iaca_cert.der().to_vec();

    let dsc_der = build_ed448_dsc_manual(&iaca_der, &iaca_aws_key);

    (iaca_der, dsc_der)
}

fn build_chain_p384() -> (Vec<u8>, Vec<u8>, cloud_wallet_crypto::ecdsa::KeyPair) {
    build_chain_ecdsa(
        cloud_wallet_crypto::ecdsa::Curve::P384,
        &rcgen::PKCS_ECDSA_P384_SHA384,
    )
}

/// Like [`build_issuer_signed_with_issuer_auth`] but uses the ES384 algorithm (-35).
///
/// Protected header encodes `{1: -35}` and the payload is signed with SHA-384.
fn build_issuer_signed_es384(
    mso_bytes: Vec<u8>,
    dsc_der: Vec<u8>,
    signing_key: &cloud_wallet_crypto::ecdsa::KeyPair,
) -> String {
    // {1: -35} (ES384): a1 01 38 22
    let issuer_auth = signed_cose1(
        mso_bytes,
        vec![0xa1, 0x01, 0x38, 0x22],
        Value::Array(vec![Value::Bytes(dsc_der)]),
        |tbs| {
            signing_key
                .sign_sha384(tbs)
                .expect("ES384 COSE signing must succeed")
                .to_vec()
        },
        false,
    );
    issuer_signed_b64(default_name_spaces(), issuer_auth)
}

/// Builds an IACA root (P-256) and a DSC backed by an Ed25519 key.
///
/// Returns `(iaca_der, dsc_der, dsc_signing_key)`.
fn build_chain_ed25519() -> (Vec<u8>, Vec<u8>, cloud_wallet_crypto::ed25519::KeyPair) {
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyUsagePurpose,
    };

    let iaca_key = rcgen::KeyPair::generate().expect("rcgen key generation must succeed");
    let mut iaca_params =
        CertificateParams::new(vec!["IACA Root Ed25519".to_string()]).expect("iaca params");
    iaca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let iaca_cert = iaca_params
        .self_signed(&iaca_key)
        .expect("self-signed IACA cert must succeed");
    let iaca_der: Vec<u8> = iaca_cert.der().to_vec();
    let iaca_issuer = Issuer::new(iaca_params, iaca_key);

    let dsc_aws_key = cloud_wallet_crypto::ed25519::KeyPair::generate()
        .expect("aws-lc-rs Ed25519 key generation must succeed");

    let mut pkcs8_buf = [0u8; 128];
    let dsc_pkcs8 = dsc_aws_key
        .to_pkcs8_der(&mut pkcs8_buf)
        .expect("Ed25519 PKCS#8 export must succeed");
    let dsc_rcgen_key = rcgen::KeyPair::from_der_and_sign_algo(
        &rustls_pki_types::PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(
            dsc_pkcs8.to_vec(),
        )),
        &rcgen::PKCS_ED25519,
    )
    .expect("loading Ed25519 key into rcgen must succeed");

    let not_before =
        OffsetDateTime::parse("2023-12-01T00:00:00Z", &Rfc3339).expect("fixed date must parse");
    let not_after =
        OffsetDateTime::parse("2024-12-31T23:59:59Z", &Rfc3339).expect("fixed date must parse");

    let mut dsc_params =
        CertificateParams::new(vec!["DSC Ed25519".to_string()]).expect("dsc params");
    dsc_params.is_ca = IsCa::NoCa;
    dsc_params.not_before = not_before;
    dsc_params.not_after = not_after;
    dsc_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::Other(DSC_EKU_OID.to_vec())];
    dsc_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let dsc_cert = dsc_params
        .signed_by(&dsc_rcgen_key, &iaca_issuer)
        .expect("DSC Ed25519 signing by IACA must succeed");
    let dsc_der: Vec<u8> = dsc_cert.der().to_vec();

    (iaca_der, dsc_der, dsc_aws_key)
}

/// Like [`build_issuer_signed_with_issuer_auth`] but uses the EdDSA algorithm (-8)
/// with an Ed25519 signing key.
///
/// Protected header encodes `{1: -8}` and the TBS is signed directly by `signing_key`.
fn build_issuer_signed_ed25519(
    mso_bytes: Vec<u8>,
    dsc_der: Vec<u8>,
    signing_key: &cloud_wallet_crypto::ed25519::KeyPair,
) -> String {
    // {1: -8} (EdDSA): a1 01 27
    let issuer_auth = signed_cose1(
        mso_bytes,
        vec![0xa1, 0x01, 0x27],
        Value::Array(vec![Value::Bytes(dsc_der)]),
        |tbs| signing_key.sign(tbs).to_vec(),
        false,
    );
    issuer_signed_b64(default_name_spaces(), issuer_auth)
}

/// Builds a fresh `ParsedMdoc` and overwrites its `device_key` with `cose_key`,
/// keeping the rest of the document valid and within its validity window.
fn parsed_with_device_key(cose_key: Value) -> ParsedMdoc {
    let mut parsed = ParsedMdoc::parse(&build_issuer_signed(
        "2020-01-01T00:00:00Z",
        "9998-01-01T00:00:00Z",
    ))
    .expect("base mdoc must parse");
    parsed.device_key = cbor(&cose_key);
    parsed
}

// ── Verifier tests ───────────────────────────────────────────────────────────

#[tokio::test]
async fn verify_issuer_signature_accepts_valid_chain() {
    let (iaca_der, dsc_der, signing_key) = build_chain(true);
    let mso_bytes = minimal_mso_cbor();
    let raw = build_issuer_signed_with_issuer_auth(mso_bytes, dsc_der.clone(), &signing_key, false);
    let mdoc = ParsedMdoc::parse(&raw).expect("valid issuer-signed mdoc must parse");
    let trust_store = StaticTrustStore::new(vec![iaca_der]);

    let result = verify_issuer_signature(
        &mdoc,
        "org.iso.18013.5.1.mDL",
        &trust_store,
        RevocationPolicy::Skip,
        OffsetDateTime::now_utc(),
    )
    .await;

    assert!(
        result.is_ok(),
        "valid COSE_Sign1 with trusted chain must be accepted, got: {result:?}"
    );
    let info = result.unwrap();
    assert_eq!(
        info.cert_chain[0], dsc_der,
        "cert_chain[0] must be the DSC leaf certificate"
    );
}

#[tokio::test]
async fn verify_issuer_signature_accepts_valid_esp256() {
    let (iaca_der, dsc_der, signing_key) = build_chain(true);
    let mso_bytes = minimal_mso_cbor();
    let raw = build_issuer_signed_esp256(mso_bytes, dsc_der.clone(), &signing_key);
    let mdoc = ParsedMdoc::parse(&raw).expect("valid ESP256 issuer-signed mdoc must parse");
    let trust_store = StaticTrustStore::new(vec![iaca_der]);

    let result = verify_issuer_signature(
        &mdoc,
        "org.iso.18013.5.1.mDL",
        &trust_store,
        RevocationPolicy::Skip,
        OffsetDateTime::now_utc(),
    )
    .await;

    assert!(
        result.is_ok(),
        "valid ESP256 (-9, RFC 9864 fully-specified) COSE_Sign1 with trusted chain must be \
         accepted, got: {result:?}"
    );
    let info = result.unwrap();
    assert_eq!(
        info.cert_chain[0], dsc_der,
        "cert_chain[0] must be the DSC leaf certificate"
    );
}

#[tokio::test]
async fn verify_issuer_signature_rejects_tampered_payload() {
    // covers different content than what the verifier sees.
    let (iaca_der, dsc_der, signing_key) = build_chain(true);
    let mso_bytes = minimal_mso_cbor();
    let raw = build_issuer_signed_with_issuer_auth(mso_bytes, dsc_der, &signing_key, true);
    let mdoc =
        ParsedMdoc::parse(&raw).expect("tampered mdoc must still parse (parser is not a verifier)");
    let trust_store = StaticTrustStore::new(vec![iaca_der]);

    let err = verify_issuer_signature(
        &mdoc,
        "org.iso.18013.5.1.mDL",
        &trust_store,
        RevocationPolicy::Skip,
        OffsetDateTime::now_utc(),
    )
    .await
    .expect_err("tampered payload must be rejected");

    assert!(
        matches!(err, MdocError::InvalidIssuerSignature),
        "expected InvalidIssuerSignature, got: {err:?}"
    );
}

#[tokio::test]
async fn verify_issuer_signature_rejects_untrusted_root() {
    let (_, dsc_der, signing_key) = build_chain(true);
    let mso_bytes = minimal_mso_cbor();
    let raw = build_issuer_signed_with_issuer_auth(mso_bytes, dsc_der, &signing_key, false);
    let mdoc = ParsedMdoc::parse(&raw).expect("valid mdoc must parse");

    let (unrelated_iaca_der, _, _) = build_chain(true);
    let trust_store = StaticTrustStore::new(vec![unrelated_iaca_der]);

    let err = verify_issuer_signature(
        &mdoc,
        "org.iso.18013.5.1.mDL",
        &trust_store,
        RevocationPolicy::Skip,
        OffsetDateTime::now_utc(),
    )
    .await
    .expect_err("chain not anchored to trusted root must be rejected");

    assert!(
        matches!(err, MdocError::InvalidCertificateChain { .. }),
        "expected InvalidCertificateChain, got: {err:?}"
    );
}

#[tokio::test]
async fn verify_issuer_signature_rejects_missing_eku() {
    let (iaca_der, dsc_der, signing_key) = build_chain(false); // no EKU
    let mso_bytes = minimal_mso_cbor();
    let raw = build_issuer_signed_with_issuer_auth(mso_bytes, dsc_der, &signing_key, false);
    let mdoc = ParsedMdoc::parse(&raw).expect("valid mdoc must parse");
    let trust_store = StaticTrustStore::new(vec![iaca_der]);

    let err = verify_issuer_signature(
        &mdoc,
        "org.iso.18013.5.1.mDL",
        &trust_store,
        RevocationPolicy::Skip,
        OffsetDateTime::now_utc(),
    )
    .await
    .expect_err("DSC without ISO 18013-5 EKU must be rejected");

    assert!(
        matches!(err, MdocError::MissingDocSignerEku),
        "expected MissingDocSignerEku, got: {err:?}"
    );
}

#[tokio::test]
async fn verify_issuer_signature_rejects_missing_x5chain() {
    let (iaca_der, _dsc_der, signing_key) = build_chain(true);
    let mso_bytes = minimal_mso_cbor();

    let protected_header_bytes: Vec<u8> = vec![0xa1, 0x01, 0x26];
    let tbs = cbor(&Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected_header_bytes.clone()),
        Value::Bytes(vec![]),
        Value::Bytes(mso_bytes.clone()),
    ]));
    let sig_bytes = signing_key.sign_sha256(&tbs).expect("signing must succeed");

    let cose_sign1 = Value::Tag(
        18,
        Box::new(Value::Array(vec![
            Value::Bytes(protected_header_bytes),
            Value::Map(vec![]), // empty unprotected header
            Value::Bytes(mso_bytes),
            Value::Bytes(sig_bytes.to_vec()),
        ])),
    );
    let item = Value::Map(vec![
        (Value::Text("digestID".into()), Value::Integer(0u64.into())),
        (Value::Text("random".into()), Value::Bytes(vec![0u8; 16])),
        (
            Value::Text("elementIdentifier".into()),
            Value::Text("family_name".into()),
        ),
        (
            Value::Text("elementValue".into()),
            Value::Text("Doe".into()),
        ),
    ]);
    let item_tag24 = Value::Tag(24, Box::new(Value::Bytes(cbor(&item))));
    let issuer_signed = Value::Map(vec![
        (
            Value::Text("nameSpaces".into()),
            Value::Map(vec![(
                Value::Text("org.iso.18013.5.1".into()),
                Value::Array(vec![item_tag24]),
            )]),
        ),
        (Value::Text("issuerAuth".into()), cose_sign1),
    ]);
    let raw = Base64UrlUnpadded::encode_string(&cbor(&issuer_signed));
    let mdoc = ParsedMdoc::parse(&raw).expect("mdoc without x5chain must still parse");
    let trust_store = StaticTrustStore::new(vec![iaca_der]);

    let err = verify_issuer_signature(
        &mdoc,
        "org.iso.18013.5.1.mDL",
        &trust_store,
        RevocationPolicy::Skip,
        OffsetDateTime::now_utc(),
    )
    .await
    .expect_err("missing x5chain must be rejected");

    assert!(
        matches!(err, MdocError::MissingX5Chain),
        "expected MissingX5Chain, got: {err:?}"
    );
}

#[tokio::test]
async fn verify_issuer_signature_rejects_doctype_mismatch() {
    let (iaca_der, dsc_der, signing_key) = build_chain(true);
    let mso_bytes = minimal_mso_cbor();
    let raw = build_issuer_signed_with_issuer_auth(mso_bytes, dsc_der, &signing_key, false);
    let mdoc = ParsedMdoc::parse(&raw).expect("valid mdoc must parse");
    let trust_store = StaticTrustStore::new(vec![iaca_der]);

    let err = verify_issuer_signature(
        &mdoc,
        "com.example.other.doctype",
        &trust_store,
        RevocationPolicy::Skip,
        OffsetDateTime::now_utc(),
    )
    .await
    .expect_err("docType mismatch must be rejected");

    assert!(
        matches!(err, MdocError::DocTypeMismatch { .. }),
        "expected DocTypeMismatch, got: {err:?}"
    );
}

#[tokio::test]
async fn verify_issuer_signature_rejects_signed_outside_dsc_validity() {
    // signed timestamp is "2024-01-01T00:00:00Z" — before the DSC notBefore.
    let (iaca_der, dsc_der, signing_key) = build_chain_params(
        true,
        Some((
            OffsetDateTime::parse("2025-01-01T00:00:00Z", &Rfc3339).expect("date must parse"),
            OffsetDateTime::parse("2025-12-31T23:59:59Z", &Rfc3339).expect("date must parse"),
        )),
        None,
        None,
        None,
        None,
    );
    let mso_bytes = minimal_mso_cbor(); // signed = "2024-01-01T00:00:00Z"
    let raw = build_issuer_signed_with_issuer_auth(mso_bytes, dsc_der, &signing_key, false);
    let mdoc = ParsedMdoc::parse(&raw).expect("valid mdoc must parse");
    let trust_store = StaticTrustStore::new(vec![iaca_der]);

    let err = verify_issuer_signature(
        &mdoc,
        "org.iso.18013.5.1.mDL",
        &trust_store,
        RevocationPolicy::Skip,
        OffsetDateTime::now_utc(),
    )
    .await
    .expect_err("MSO signed before DSC notBefore must be rejected");

    assert!(
        matches!(err, MdocError::SignedOutsideDscValidity { .. }),
        "expected SignedOutsideDscValidity, got: {err:?}"
    );
}

#[tokio::test]
async fn verify_issuer_signature_rejects_country_mismatch() {
    let (iaca_der, dsc_der, signing_key) =
        build_chain_params(true, None, Some("DE"), Some("FR"), None, None);
    let mso_bytes = minimal_mso_cbor();
    let raw = build_issuer_signed_with_issuer_auth(mso_bytes, dsc_der, &signing_key, false);
    let mdoc = ParsedMdoc::parse(&raw).expect("valid mdoc must parse");
    let trust_store = StaticTrustStore::new(vec![iaca_der]);

    let err = verify_issuer_signature(
        &mdoc,
        "org.iso.18013.5.1.mDL",
        &trust_store,
        RevocationPolicy::Skip,
        OffsetDateTime::now_utc(),
    )
    .await
    .expect_err("DSC/IACA country mismatch must be rejected");

    assert!(
        matches!(err, MdocError::CountryMismatch { .. }),
        "expected CountryMismatch, got: {err:?}"
    );
}

#[tokio::test]
async fn verify_issuer_signature_rejects_dsc_validity_too_long() {
    // MSO signed="2024-01-01T00:00:00Z" = DSC notBefore (would be within-window if allowed).
    let (iaca_der, dsc_der, signing_key) = build_chain_params(
        true,
        Some((
            OffsetDateTime::parse("2024-01-01T00:00:00Z", &Rfc3339).expect("date must parse"),
            OffsetDateTime::parse("2025-04-04T00:00:00Z", &Rfc3339).expect("date must parse"),
        )),
        None,
        None,
        None,
        None,
    );
    let mso_bytes = minimal_mso_cbor(); // signed = "2024-01-01T00:00:00Z"
    let raw = build_issuer_signed_with_issuer_auth(mso_bytes, dsc_der, &signing_key, false);
    let mdoc = ParsedMdoc::parse(&raw).expect("valid mdoc must parse");
    let trust_store = StaticTrustStore::new(vec![iaca_der]);

    let err = verify_issuer_signature(
        &mdoc,
        "org.iso.18013.5.1.mDL",
        &trust_store,
        RevocationPolicy::Skip,
        OffsetDateTime::now_utc(),
    )
    .await
    .expect_err("DSC with 459-day validity must be rejected");

    assert!(
        matches!(err, MdocError::InvalidCertificateChain { .. }),
        "expected InvalidCertificateChain (457-day limit exceeded), got: {err:?}"
    );
}

#[tokio::test]
async fn verify_issuer_signature_accepts_valid_es512() {
    let (iaca_der, dsc_der, signing_key) = build_chain_p521();
    let mso_bytes = minimal_mso_cbor();
    let raw = build_issuer_signed_with_issuer_auth_es512(mso_bytes, dsc_der.clone(), &signing_key);
    let mdoc = ParsedMdoc::parse(&raw).expect("valid ES512 issuer-signed mdoc must parse");
    let trust_store = StaticTrustStore::new(vec![iaca_der]);

    let result = verify_issuer_signature(
        &mdoc,
        "org.iso.18013.5.1.mDL",
        &trust_store,
        RevocationPolicy::Skip,
        OffsetDateTime::now_utc(),
    )
    .await;

    assert!(
        result.is_ok(),
        "valid ES512 COSE_Sign1 with trusted chain must be accepted, got: {result:?}"
    );
    let info = result.unwrap();
    assert_eq!(
        info.cert_chain[0], dsc_der,
        "cert_chain[0] must be the DSC leaf certificate"
    );
}

#[tokio::test]
async fn verify_issuer_signature_rejects_state_mismatch() {
    let (iaca_der, dsc_der, signing_key) =
        build_chain_params(true, None, None, None, Some("California"), Some("NewYork"));
    let mso_bytes = minimal_mso_cbor();
    let raw = build_issuer_signed_with_issuer_auth(mso_bytes, dsc_der, &signing_key, false);
    let mdoc = ParsedMdoc::parse(&raw).expect("valid mdoc must parse");
    let trust_store = StaticTrustStore::new(vec![iaca_der]);

    let err = verify_issuer_signature(
        &mdoc,
        "org.iso.18013.5.1.mDL",
        &trust_store,
        RevocationPolicy::Skip,
        OffsetDateTime::now_utc(),
    )
    .await
    .expect_err("DSC/IACA state mismatch must be rejected");

    assert!(
        matches!(err, MdocError::StateMismatch { .. }),
        "expected StateMismatch, got: {err:?}"
    );
}

#[tokio::test]
async fn verify_issuer_signature_rejects_missing_key_usage() {
    // the digitalSignature bit required by ISO 18013-5 Annex B Table B.3 is absent.
    let (iaca_der, dsc_der, signing_key) = build_chain_dsc_wrong_key_usage();
    let mso_bytes = minimal_mso_cbor();
    let raw = build_issuer_signed_with_issuer_auth(mso_bytes, dsc_der, &signing_key, false);
    let mdoc = ParsedMdoc::parse(&raw).expect("valid mdoc must parse");
    let trust_store = StaticTrustStore::new(vec![iaca_der]);

    let err = verify_issuer_signature(
        &mdoc,
        "org.iso.18013.5.1.mDL",
        &trust_store,
        RevocationPolicy::Skip,
        OffsetDateTime::now_utc(),
    )
    .await
    .expect_err("DSC without digitalSignature key usage must be rejected");

    assert!(
        matches!(err, MdocError::MissingDigitalSignatureKeyUsage),
        "expected MissingDigitalSignatureKeyUsage, got: {err:?}"
    );
}

#[tokio::test]
async fn verify_issuer_signature_rejects_signed_after_dsc_expiry() {
    // 457-day limit).  The minimal_mso_cbor() fixture has signed = "2024-01-01",
    // which is after notAfter (2023-06-30), so check_signed_within_dsc_validity
    // must reject the credential.
    let (iaca_der, dsc_der, signing_key) = build_chain_params(
        true,
        Some((
            OffsetDateTime::parse("2023-01-01T00:00:00Z", &Rfc3339).expect("fixed date must parse"),
            OffsetDateTime::parse("2023-06-30T23:59:59Z", &Rfc3339).expect("fixed date must parse"),
        )),
        None,
        None,
        None,
        None,
    );
    let mso_bytes = minimal_mso_cbor(); // signed = "2024-01-01" — after notAfter
    let raw = build_issuer_signed_with_issuer_auth(mso_bytes, dsc_der, &signing_key, false);
    let mdoc = ParsedMdoc::parse(&raw).expect("valid mdoc must parse");
    let trust_store = StaticTrustStore::new(vec![iaca_der]);

    let err = verify_issuer_signature(
        &mdoc,
        "org.iso.18013.5.1.mDL",
        &trust_store,
        RevocationPolicy::Skip,
        OffsetDateTime::now_utc(),
    )
    .await
    .expect_err("MSO signed after DSC notAfter must be rejected");

    assert!(
        matches!(err, MdocError::SignedOutsideDscValidity { .. }),
        "expected SignedOutsideDscValidity, got: {err:?}"
    );
}

#[tokio::test]
async fn verify_issuer_signature_accepts_single_bstr_x5chain() {
    // RFC 9360 §2 permits x5chain to be either a single bstr or an array of
    // bstr.  Both forms must be accepted.
    let (iaca_der, dsc_der, signing_key) = build_chain(true);
    let mso_bytes = minimal_mso_cbor();
    let raw = build_issuer_signed_single_bstr_x5chain(mso_bytes, dsc_der, &signing_key);
    let mdoc = ParsedMdoc::parse(&raw).expect("valid mdoc must parse");
    let trust_store = StaticTrustStore::new(vec![iaca_der]);

    let result = verify_issuer_signature(
        &mdoc,
        "org.iso.18013.5.1.mDL",
        &trust_store,
        RevocationPolicy::Skip,
        OffsetDateTime::now_utc(),
    )
    .await;

    assert!(
        result.is_ok(),
        "credential with single-bstr x5chain must be accepted: {result:?}"
    );
}

#[tokio::test]
async fn verify_issuer_signature_accepts_intermediate_ca_chain() {
    // x5chain = [dsc_der, int_der] (leaf first; IACA root not included per
    // ISO 18013-5 Annex B §B.1).  validate_cert_chain must walk the full path.
    let (iaca_der, int_der, dsc_der, signing_key) = build_three_cert_chain();
    let mso_bytes = minimal_mso_cbor();
    let raw =
        build_issuer_signed_with_chain_x5chain(mso_bytes, vec![dsc_der, int_der], &signing_key);
    let mdoc = ParsedMdoc::parse(&raw).expect("valid mdoc must parse");
    let trust_store = StaticTrustStore::new(vec![iaca_der]);

    let result = verify_issuer_signature(
        &mdoc,
        "org.iso.18013.5.1.mDL",
        &trust_store,
        RevocationPolicy::Skip,
        OffsetDateTime::now_utc(),
    )
    .await;

    assert!(
        result.is_ok(),
        "three-cert chain with valid intermediate must be accepted: {result:?}"
    );
}

#[tokio::test]
async fn verify_issuer_signature_rejects_tampered_intermediate() {
    // Replace the real intermediate with a fresh IACA root (different key).
    // chain[0].verify_signature(chain[1].public_key()) will fail because the
    // DSC was signed by the real intermediate, not by the replacement.
    let (iaca_der, _int_der, dsc_der, signing_key) = build_three_cert_chain();

    // A fresh IACA cert has a different key — use it as the "wrong intermediate".
    let (wrong_cert_der, _, _) = build_chain(true);

    let mso_bytes = minimal_mso_cbor();
    let raw = build_issuer_signed_with_chain_x5chain(
        mso_bytes,
        vec![dsc_der, wrong_cert_der],
        &signing_key,
    );
    let mdoc = ParsedMdoc::parse(&raw).expect("mdoc must still parse structurally");
    let trust_store = StaticTrustStore::new(vec![iaca_der]);

    let err = verify_issuer_signature(
        &mdoc,
        "org.iso.18013.5.1.mDL",
        &trust_store,
        RevocationPolicy::Skip,
        OffsetDateTime::now_utc(),
    )
    .await
    .expect_err("chain with wrong intermediate must be rejected");

    assert!(
        matches!(err, MdocError::InvalidCertificateChain { .. }),
        "expected InvalidCertificateChain, got: {err:?}"
    );
}

#[tokio::test]
async fn verify_issuer_signature_rejects_empty_trust_store() {
    // An empty trust store cannot anchor any chain.
    let (_iaca_der, dsc_der, signing_key) = build_chain(true);
    let mso_bytes = minimal_mso_cbor();
    let raw = build_issuer_signed_with_issuer_auth(mso_bytes, dsc_der, &signing_key, false);
    let mdoc = ParsedMdoc::parse(&raw).expect("valid mdoc must parse");
    let trust_store = StaticTrustStore::new(vec![]);

    let err = verify_issuer_signature(
        &mdoc,
        "org.iso.18013.5.1.mDL",
        &trust_store,
        RevocationPolicy::Skip,
        OffsetDateTime::now_utc(),
    )
    .await
    .expect_err("empty trust store must reject all chains");

    assert!(
        matches!(err, MdocError::InvalidCertificateChain { .. }),
        "expected InvalidCertificateChain, got: {err:?}"
    );
}

#[tokio::test]
async fn verify_issuer_signature_rejects_brainpool_algorithms() {
    // ISO 18013-5 Table 22 names three Brainpool curves; all are currently rejected as
    // UnsupportedAlgorithm. Each iteration uses a fresh chain so cert generation is
    // isolated per case. When aws-lc-rs adds Brainpool support, split this back into
    // per-curve tests with real signatures.
    //
    // CBOR protected header encoding:
    //   {1: -38} = a1 01 38 25   (Brainpool P-256r1)
    //   {1: -47} = a1 01 38 2e   (Brainpool P-384r1)
    //   {1: -48} = a1 01 38 2f   (Brainpool P-512r1)
    for (header, expected_alg) in [
        (vec![0xa1u8, 0x01, 0x38, 0x25], -38i64), // Brainpool P-256r1
        (vec![0xa1u8, 0x01, 0x38, 0x2e], -47i64), // Brainpool P-384r1
        (vec![0xa1u8, 0x01, 0x38, 0x2f], -48i64), // Brainpool P-512r1
    ] {
        let (iaca_der, dsc_der, _) = build_chain(true);
        let raw = build_issuer_signed_with_custom_alg(minimal_mso_cbor(), dsc_der, header);
        let mdoc = ParsedMdoc::parse(&raw).expect("mdoc with Brainpool alg must parse");
        let trust_store = StaticTrustStore::new(vec![iaca_der]);

        let err = verify_issuer_signature(
            &mdoc,
            "org.iso.18013.5.1.mDL",
            &trust_store,
            RevocationPolicy::Skip,
            OffsetDateTime::now_utc(),
        )
        .await
        .expect_err("Brainpool must be rejected as unsupported");

        assert!(
            matches!(err, MdocError::UnsupportedAlgorithm { alg } if alg == expected_alg),
            "expected UnsupportedAlgorithm {{ alg: {expected_alg} }}, got: {err:?}"
        );
    }
}

#[tokio::test]
async fn verify_issuer_signature_rejects_iaca_root_in_x5chain() {
    // ISO 18013-5 Annex B §B.1: the IACA root must NOT appear in x5chain.
    // Placing it as the second entry causes validate_cert_chain to find the
    // trusted root inside the chain and reject the credential.
    let (iaca_der, dsc_der, signing_key) = build_chain(true);
    let mso_bytes = minimal_mso_cbor();
    // chain = [dsc_der, iaca_der] — IACA root is present as the second entry.
    let raw = build_issuer_signed_with_chain_x5chain(
        mso_bytes,
        vec![dsc_der, iaca_der.clone()],
        &signing_key,
    );
    let mdoc = ParsedMdoc::parse(&raw).expect("mdoc with IACA root in chain must still parse");
    let trust_store = StaticTrustStore::new(vec![iaca_der]);

    let err = verify_issuer_signature(
        &mdoc,
        "org.iso.18013.5.1.mDL",
        &trust_store,
        RevocationPolicy::Skip,
        OffsetDateTime::now_utc(),
    )
    .await
    .expect_err("IACA root present in x5chain must be rejected");

    assert!(
        matches!(err, MdocError::InvalidCertificateChain { .. }),
        "expected InvalidCertificateChain, got: {err:?}"
    );
}

#[tokio::test]
async fn verify_issuer_signature_rejects_ed448_algorithm() {
    // Ed448 (OID 1.3.101.113) is not supported even when the COSE alg field is
    // EdDSA (-8). The check fires after chain validation but before the crypto
    // backend, so a dummy signature is sufficient to reach the rejection.
    let (iaca_der, dsc_der) = build_ed448_dsc_chain();
    let mso_bytes = minimal_mso_cbor();
    // {1: -8} (EdDSA) protected header: a1 01 27
    let raw = build_issuer_signed_with_custom_alg(mso_bytes, dsc_der, vec![0xa1, 0x01, 0x27]);
    let mdoc = ParsedMdoc::parse(&raw).expect("mdoc with Ed448 DSC must still parse");
    let trust_store = StaticTrustStore::new(vec![iaca_der]);

    let err = verify_issuer_signature(
        &mdoc,
        "org.iso.18013.5.1.mDL",
        &trust_store,
        RevocationPolicy::Skip,
        OffsetDateTime::now_utc(),
    )
    .await
    .expect_err("Ed448 DSC must be rejected");

    assert!(
        matches!(err, MdocError::UnsupportedAlgorithm { alg: -8 }),
        "expected UnsupportedAlgorithm {{ alg: -8 }}, got: {err:?}"
    );
}

#[tokio::test]
async fn verify_issuer_signature_accepts_valid_es384() {
    let (iaca_der, dsc_der, signing_key) = build_chain_p384();
    let mso_bytes = minimal_mso_cbor();
    let raw = build_issuer_signed_es384(mso_bytes, dsc_der.clone(), &signing_key);
    let mdoc = ParsedMdoc::parse(&raw).expect("valid ES384 issuer-signed mdoc must parse");
    let trust_store = StaticTrustStore::new(vec![iaca_der]);

    let result = verify_issuer_signature(
        &mdoc,
        "org.iso.18013.5.1.mDL",
        &trust_store,
        RevocationPolicy::Skip,
        OffsetDateTime::now_utc(),
    )
    .await;

    assert!(
        result.is_ok(),
        "valid ES384 COSE_Sign1 with trusted chain must be accepted, got: {result:?}"
    );
    let info = result.unwrap();
    assert_eq!(
        info.cert_chain[0], dsc_der,
        "cert_chain[0] must be the DSC leaf certificate"
    );
}

#[tokio::test]
async fn verify_issuer_signature_accepts_valid_ed25519() {
    let (iaca_der, dsc_der, signing_key) = build_chain_ed25519();
    let mso_bytes = minimal_mso_cbor();
    let raw = build_issuer_signed_ed25519(mso_bytes, dsc_der.clone(), &signing_key);
    let mdoc = ParsedMdoc::parse(&raw).expect("valid Ed25519 issuer-signed mdoc must parse");
    let trust_store = StaticTrustStore::new(vec![iaca_der]);

    let result = verify_issuer_signature(
        &mdoc,
        "org.iso.18013.5.1.mDL",
        &trust_store,
        RevocationPolicy::Skip,
        OffsetDateTime::now_utc(),
    )
    .await;

    assert!(
        result.is_ok(),
        "valid EdDSA/Ed25519 COSE_Sign1 with trusted chain must be accepted, got: {result:?}"
    );
    let info = result.unwrap();
    assert_eq!(
        info.cert_chain[0], dsc_der,
        "cert_chain[0] must be the DSC leaf certificate"
    );
}

#[tokio::test]
async fn tbs_data_preserves_original_protected_header_bytes() {
    let (iaca_der, dsc_der, signing_key) = build_chain(true);
    let mso_bytes = minimal_mso_cbor();

    // {1: -7} (ES256), CBOR-encoded: a1 01 26 — these are the exact bytes the parser
    // will store as CoseSign1::protected::original_data.
    let protected_header_bytes: Vec<u8> = vec![0xa1, 0x01, 0x26];

    // RFC 9052 §4.4 Sig_Structure: ["Signature1", protected_bstr, external_aad, payload]
    let expected_tbs = cbor(&Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected_header_bytes.clone()),
        Value::Bytes(vec![]), // external AAD = b""
        Value::Bytes(mso_bytes.clone()),
    ]));

    let sig_bytes = signing_key
        .sign_sha256(&expected_tbs)
        .expect("signing must succeed in tests");

    let unprotected_map = Value::Map(vec![(
        Value::Integer(33.into()),
        Value::Array(vec![Value::Bytes(dsc_der)]),
    )]);
    let cose_sign1_val = Value::Tag(
        18,
        Box::new(Value::Array(vec![
            Value::Bytes(protected_header_bytes),
            unprotected_map,
            Value::Bytes(mso_bytes),
            Value::Bytes(sig_bytes.to_vec()),
        ])),
    );
    let item = Value::Map(vec![
        (Value::Text("digestID".into()), Value::Integer(0u64.into())),
        (Value::Text("random".into()), Value::Bytes(vec![0u8; 16])),
        (
            Value::Text("elementIdentifier".into()),
            Value::Text("family_name".into()),
        ),
        (
            Value::Text("elementValue".into()),
            Value::Text("Doe".into()),
        ),
    ]);
    let item_tag24 = Value::Tag(24, Box::new(Value::Bytes(cbor(&item))));
    let issuer_signed = Value::Map(vec![
        (
            Value::Text("nameSpaces".into()),
            Value::Map(vec![(
                Value::Text("org.iso.18013.5.1".into()),
                Value::Array(vec![item_tag24]),
            )]),
        ),
        (Value::Text("issuerAuth".into()), cose_sign1_val),
    ]);
    let raw = Base64UrlUnpadded::encode_string(&cbor(&issuer_signed));
    let mdoc = ParsedMdoc::parse(&raw).expect("valid mdoc must parse");

    let actual_tbs = mdoc.cose_sign1.tbs_data(b"");

    assert_eq!(
        actual_tbs, expected_tbs,
        "tbs_data() must return the same byte sequence as the manually-constructed Sig_Structure"
    );

    // End-to-end confirmation: the signature was created over `expected_tbs`; if
    // tbs_data() had re-encoded the header, verification would fail with InvalidIssuerSignature.
    let trust_store = StaticTrustStore::new(vec![iaca_der]);
    let result = verify_issuer_signature(
        &mdoc,
        "org.iso.18013.5.1.mDL",
        &trust_store,
        RevocationPolicy::Skip,
        OffsetDateTime::now_utc(),
    )
    .await;
    assert!(
        result.is_ok(),
        "signature over original protected-header bytes must verify: {result:?}"
    );
}

// ── Device key binding tests ─────────────────────────────────────────────────

#[test]
fn verify_device_key_binding_passes_matching_p256_key() {
    let x_bytes = vec![1u8; 32];
    let y_bytes = vec![2u8; 32];
    let cose_key = Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Integer(2i64.into())),
        (Value::Integer((-1i64).into()), Value::Integer(1i64.into())),
        (
            Value::Integer((-2i64).into()),
            Value::Bytes(x_bytes.clone()),
        ),
        (
            Value::Integer((-3i64).into()),
            Value::Bytes(y_bytes.clone()),
        ),
    ]);
    let parsed = parsed_with_device_key(cose_key);
    let holder_binding_public_jwk = Jwk {
        key: Key::Ec(Ec {
            crv: Curve::P256,
            x: B64::new(x_bytes),
            y: B64::new(y_bytes),
            d: None,
        }),
        prm: Parameters::default(),
    };

    let result = verify_device_key_binding(&parsed, &holder_binding_public_jwk);

    assert!(
        result.is_ok(),
        "matching P-256 keys must pass, got: {result:?}"
    );
}

#[test]
fn verify_device_key_binding_rejects_mismatched_x_coordinate() {
    let cose_key = Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Integer(2i64.into())),
        (Value::Integer((-1i64).into()), Value::Integer(1i64.into())),
        (Value::Integer((-2i64).into()), Value::Bytes(vec![1u8; 32])),
        (Value::Integer((-3i64).into()), Value::Bytes(vec![2u8; 32])),
    ]);
    let parsed = parsed_with_device_key(cose_key);
    let holder_binding_public_jwk = Jwk {
        key: Key::Ec(Ec {
            crv: Curve::P256,
            x: B64::new(vec![9u8; 32]),
            y: B64::new(vec![2u8; 32]),
            d: None,
        }),
        prm: Parameters::default(),
    };

    let err = verify_device_key_binding(&parsed, &holder_binding_public_jwk)
        .expect_err("mismatched x must be rejected");

    assert!(
        matches!(err, MdocError::DeviceKeyMismatch),
        "expected DeviceKeyMismatch, got: {err:?}"
    );
}

#[test]
fn verify_device_key_binding_rejects_mismatched_y_coordinate() {
    let cose_key = Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Integer(2i64.into())),
        (Value::Integer((-1i64).into()), Value::Integer(1i64.into())),
        (Value::Integer((-2i64).into()), Value::Bytes(vec![1u8; 32])),
        (Value::Integer((-3i64).into()), Value::Bytes(vec![2u8; 32])),
    ]);
    let parsed = parsed_with_device_key(cose_key);
    let holder_binding_public_jwk = Jwk {
        key: Key::Ec(Ec {
            crv: Curve::P256,
            x: B64::new(vec![1u8; 32]),
            y: B64::new(vec![9u8; 32]),
            d: None,
        }),
        prm: Parameters::default(),
    };

    let err = verify_device_key_binding(&parsed, &holder_binding_public_jwk)
        .expect_err("mismatched y must be rejected");

    assert!(
        matches!(err, MdocError::DeviceKeyMismatch),
        "expected DeviceKeyMismatch, got: {err:?}"
    );
}

#[test]
fn verify_device_key_binding_rejects_curve_mismatch() {
    let cose_key = Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Integer(2i64.into())),
        (Value::Integer((-1i64).into()), Value::Integer(2i64.into())), // P-384
        (Value::Integer((-2i64).into()), Value::Bytes(vec![1u8; 48])),
        (Value::Integer((-3i64).into()), Value::Bytes(vec![2u8; 48])),
    ]);
    let parsed = parsed_with_device_key(cose_key);
    // JWK claims P-256 — curve mismatch.
    let holder_binding_public_jwk = Jwk {
        key: Key::Ec(Ec {
            crv: Curve::P256,
            x: B64::new(vec![1u8; 32]),
            y: B64::new(vec![2u8; 32]),
            d: None,
        }),
        prm: Parameters::default(),
    };

    let err = verify_device_key_binding(&parsed, &holder_binding_public_jwk)
        .expect_err("curve mismatch must be rejected");

    assert!(
        matches!(err, MdocError::CurveMismatch { .. }),
        "expected CurveMismatch, got: {err:?}"
    );
}

#[test]
fn verify_device_key_binding_rejects_malformed_cose_key() {
    let mut parsed = ParsedMdoc::parse(&build_issuer_signed(
        "2020-01-01T00:00:00Z",
        "9998-01-01T00:00:00Z",
    ))
    .expect("base mdoc must parse");
    parsed.device_key = vec![0xffu8]; // 0xff is not valid initial CBOR
    let holder_binding_public_jwk = Jwk {
        key: Key::Ec(Ec {
            crv: Curve::P256,
            x: B64::new(vec![0u8; 32]),
            y: B64::new(vec![0u8; 32]),
            d: None,
        }),
        prm: Parameters::default(),
    };

    let err = verify_device_key_binding(&parsed, &holder_binding_public_jwk)
        .expect_err("malformed COSE_Key bytes must be rejected");

    assert!(
        matches!(err, MdocError::MalformedDeviceKey { .. }),
        "expected MalformedDeviceKey, got: {err:?}"
    );
}

#[test]
fn verify_device_key_binding_rejects_incompatible_jwk_type() {
    let cose_key = Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Integer(2i64.into())),
        (Value::Integer((-1i64).into()), Value::Integer(1i64.into())),
        (Value::Integer((-2i64).into()), Value::Bytes(vec![1u8; 32])),
        (Value::Integer((-3i64).into()), Value::Bytes(vec![2u8; 32])),
    ]);
    let parsed = parsed_with_device_key(cose_key);
    let holder_binding_public_jwk = Jwk {
        key: Key::Okp(Okp {
            crv: OkpCurve::X25519,
            x: B64::new(vec![1u8; 32]),
            d: None,
        }),
        prm: Parameters::default(),
    };

    let err = verify_device_key_binding(&parsed, &holder_binding_public_jwk)
        .expect_err("EC2 COSE_Key against non-EC proof JWK must be rejected");

    assert!(
        matches!(err, MdocError::UnsupportedDeviceKeyType { .. }),
        "expected UnsupportedDeviceKeyType, got: {err:?}"
    );
}

#[test]
fn verify_device_key_binding_rejects_unknown_curve() {
    let cose_key = Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Integer(2i64.into())),
        (Value::Integer((-1i64).into()), Value::Integer(99i64.into())), // unknown crv
        (Value::Integer((-2i64).into()), Value::Bytes(vec![1u8; 32])),
        (Value::Integer((-3i64).into()), Value::Bytes(vec![2u8; 32])),
    ]);
    let parsed = parsed_with_device_key(cose_key);
    let holder_binding_public_jwk = Jwk {
        key: Key::Ec(Ec {
            crv: Curve::P256,
            x: B64::new(vec![1u8; 32]),
            y: B64::new(vec![2u8; 32]),
            d: None,
        }),
        prm: Parameters::default(),
    };

    let err = verify_device_key_binding(&parsed, &holder_binding_public_jwk)
        .expect_err("unknown COSE_Key curve must be rejected");

    assert!(
        matches!(err, MdocError::UnsupportedDeviceKeyType { .. }),
        "expected UnsupportedDeviceKeyType, got: {err:?}"
    );
}

#[test]
fn verify_device_key_binding_passes_matching_ed25519_key() {
    let x_bytes = vec![5u8; 32];
    let cose_key = Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Integer(1i64.into())), // kty=OKP
        (Value::Integer((-1i64).into()), Value::Integer(6i64.into())), // crv=Ed25519
        (
            Value::Integer((-2i64).into()),
            Value::Bytes(x_bytes.clone()),
        ),
    ]);
    let parsed = parsed_with_device_key(cose_key);
    let holder_binding_public_jwk = Jwk {
        key: Key::Okp(Okp {
            crv: OkpCurve::Ed25519,
            x: B64::new(x_bytes),
            d: None,
        }),
        prm: Parameters::default(),
    };

    let result = verify_device_key_binding(&parsed, &holder_binding_public_jwk);

    assert!(
        result.is_ok(),
        "matching Ed25519 keys must pass, got: {result:?}"
    );
}

#[test]
fn verify_device_key_binding_rejects_mismatched_ed25519_x() {
    let cose_key = Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Integer(1i64.into())),
        (Value::Integer((-1i64).into()), Value::Integer(6i64.into())),
        (Value::Integer((-2i64).into()), Value::Bytes(vec![5u8; 32])),
    ]);
    let parsed = parsed_with_device_key(cose_key);
    let holder_binding_public_jwk = Jwk {
        key: Key::Okp(Okp {
            crv: OkpCurve::Ed25519,
            x: B64::new(vec![9u8; 32]),
            d: None,
        }),
        prm: Parameters::default(),
    };

    let err = verify_device_key_binding(&parsed, &holder_binding_public_jwk)
        .expect_err("mismatched Ed25519 x must be rejected");

    assert!(
        matches!(err, MdocError::DeviceKeyMismatch),
        "expected DeviceKeyMismatch, got: {err:?}"
    );
}

#[test]
fn verify_device_key_binding_rejects_compressed_ec2_y() {
    // but comparing a compressed COSE y against an uncompressed JWK y requires EC
    // decompression which is not implemented. Reject explicitly.
    let cose_key = Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Integer(2i64.into())), // kty=EC2
        (Value::Integer((-1i64).into()), Value::Integer(1i64.into())), // crv=P-256
        (Value::Integer((-2i64).into()), Value::Bytes(vec![1u8; 32])),
        (Value::Integer((-3i64).into()), Value::Bool(true)), // compressed y
    ]);
    let parsed = parsed_with_device_key(cose_key);
    let holder_binding_public_jwk = Jwk {
        key: Key::Ec(Ec {
            crv: Curve::P256,
            x: B64::new(vec![1u8; 32]),
            y: B64::new(vec![2u8; 32]),
            d: None,
        }),
        prm: Parameters::default(),
    };

    let err = verify_device_key_binding(&parsed, &holder_binding_public_jwk)
        .expect_err("compressed y (bool) must be rejected");

    assert!(
        matches!(err, MdocError::UnsupportedDeviceKeyType { .. }),
        "expected UnsupportedDeviceKeyType, got: {err:?}"
    );
}

#[test]
fn verify_device_key_binding_passes_matching_p384_key() {
    let x_bytes = vec![7u8; 48];
    let y_bytes = vec![8u8; 48];
    let cose_key = Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Integer(2i64.into())), // kty=EC2
        (Value::Integer((-1i64).into()), Value::Integer(2i64.into())), // crv=P-384
        (
            Value::Integer((-2i64).into()),
            Value::Bytes(x_bytes.clone()),
        ),
        (
            Value::Integer((-3i64).into()),
            Value::Bytes(y_bytes.clone()),
        ),
    ]);
    let parsed = parsed_with_device_key(cose_key);
    let holder_binding_public_jwk = Jwk {
        key: Key::Ec(Ec {
            crv: Curve::P384,
            x: B64::new(x_bytes),
            y: B64::new(y_bytes),
            d: None,
        }),
        prm: Parameters::default(),
    };

    let result = verify_device_key_binding(&parsed, &holder_binding_public_jwk);

    assert!(
        result.is_ok(),
        "matching P-384 keys must pass, got: {result:?}"
    );
}

#[test]
fn verify_device_key_binding_rejects_okp_x25519_cose_crv() {
    let cose_key = Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Integer(1i64.into())), // kty=OKP
        (Value::Integer((-1i64).into()), Value::Integer(4i64.into())), // crv=X25519
        (Value::Integer((-2i64).into()), Value::Bytes(vec![5u8; 32])),
    ]);
    let parsed = parsed_with_device_key(cose_key);
    let holder_binding_public_jwk = Jwk {
        key: Key::Okp(Okp {
            crv: OkpCurve::Ed25519,
            x: B64::new(vec![5u8; 32]),
            d: None,
        }),
        prm: Parameters::default(),
    };

    let err = verify_device_key_binding(&parsed, &holder_binding_public_jwk)
        .expect_err("OKP X25519 COSE crv must be rejected");

    assert!(
        matches!(err, MdocError::UnsupportedDeviceKeyType { .. }),
        "expected UnsupportedDeviceKeyType, got: {err:?}"
    );
}

#[test]
fn verify_device_key_binding_passes_matching_p521_key() {
    let x_bytes = vec![3u8; 66];
    let y_bytes = vec![4u8; 66];
    let cose_key = Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Integer(2i64.into())), // kty=EC2
        (Value::Integer((-1i64).into()), Value::Integer(3i64.into())), // crv=P-521
        (
            Value::Integer((-2i64).into()),
            Value::Bytes(x_bytes.clone()),
        ),
        (
            Value::Integer((-3i64).into()),
            Value::Bytes(y_bytes.clone()),
        ),
    ]);
    let parsed = parsed_with_device_key(cose_key);
    let holder_binding_public_jwk = Jwk {
        key: Key::Ec(Ec {
            crv: Curve::P521,
            x: B64::new(x_bytes),
            y: B64::new(y_bytes),
            d: None,
        }),
        prm: Parameters::default(),
    };

    let result = verify_device_key_binding(&parsed, &holder_binding_public_jwk);

    assert!(
        result.is_ok(),
        "matching P-521 keys must pass, got: {result:?}"
    );
}

#[test]
fn verify_device_key_binding_rejects_duplicate_cose_key_label() {
    // RFC 7049 §3.1 forbids duplicate map keys; accepting them could enable
    // split-key constructions where the first x matches but the second does not.
    let cose_key = Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Integer(2i64.into())), // kty=EC2
        (Value::Integer((-1i64).into()), Value::Integer(1i64.into())), // crv=P-256
        (Value::Integer((-2i64).into()), Value::Bytes(vec![1u8; 32])), // x (first)
        (Value::Integer((-2i64).into()), Value::Bytes(vec![9u8; 32])), // x (duplicate)
        (Value::Integer((-3i64).into()), Value::Bytes(vec![2u8; 32])),
    ]);
    let parsed = parsed_with_device_key(cose_key);
    let holder_binding_public_jwk = Jwk {
        key: Key::Ec(Ec {
            crv: Curve::P256,
            x: B64::new(vec![1u8; 32]),
            y: B64::new(vec![2u8; 32]),
            d: None,
        }),
        prm: Parameters::default(),
    };

    let err = verify_device_key_binding(&parsed, &holder_binding_public_jwk)
        .expect_err("duplicate COSE_Key label must be rejected");

    assert!(
        matches!(err, MdocError::MalformedDeviceKey { .. }),
        "expected MalformedDeviceKey, got: {err:?}"
    );
}

#[test]
fn verify_device_key_binding_rejects_ec2_coordinate_wrong_length() {
    // The coordinate-length gate must catch this before ct_eq is called; if it did not,
    // subtle::ConstantTimeEq would short-circuit on the length difference (non-constant-time).
    let cose_key = Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Integer(2i64.into())), // kty=EC2
        (Value::Integer((-1i64).into()), Value::Integer(1i64.into())), // crv=P-256
        (Value::Integer((-2i64).into()), Value::Bytes(vec![1u8; 31])), // x: 31 bytes (wrong)
        (Value::Integer((-3i64).into()), Value::Bytes(vec![2u8; 32])),
    ]);
    let parsed = parsed_with_device_key(cose_key);
    let holder_binding_public_jwk = Jwk {
        key: Key::Ec(Ec {
            crv: Curve::P256,
            x: B64::new(vec![1u8; 32]),
            y: B64::new(vec![2u8; 32]),
            d: None,
        }),
        prm: Parameters::default(),
    };

    let err = verify_device_key_binding(&parsed, &holder_binding_public_jwk)
        .expect_err("EC2 coordinate with wrong length must be rejected");

    assert!(
        matches!(err, MdocError::MalformedDeviceKey { .. }),
        "expected MalformedDeviceKey, got: {err:?}"
    );
}

#[test]
fn verify_device_key_binding_rejects_ed25519_x_wrong_length() {
    // The length gate must catch this before ct_eq; subtle does not guarantee constant-time
    // comparison for unequal-length slices.
    let cose_key = Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Integer(1i64.into())), // kty=OKP
        (Value::Integer((-1i64).into()), Value::Integer(6i64.into())), // crv=Ed25519
        (Value::Integer((-2i64).into()), Value::Bytes(vec![5u8; 31])), // x: 31 bytes (wrong)
    ]);
    let parsed = parsed_with_device_key(cose_key);
    let holder_binding_public_jwk = Jwk {
        key: Key::Okp(Okp {
            crv: OkpCurve::Ed25519,
            x: B64::new(vec![5u8; 32]),
            d: None,
        }),
        prm: Parameters::default(),
    };

    let err = verify_device_key_binding(&parsed, &holder_binding_public_jwk)
        .expect_err("Ed25519 x with wrong length must be rejected");

    assert!(
        matches!(err, MdocError::MalformedDeviceKey { .. }),
        "expected MalformedDeviceKey, got: {err:?}"
    );
}
