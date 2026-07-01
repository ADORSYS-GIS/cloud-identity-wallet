use color_eyre::eyre::{WrapErr as _, eyre};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject as _;
#[cfg(feature = "sqlx")]
use std::borrow::Cow;
#[cfg(feature = "sqlx")]
use std::fmt::Write;
use std::path::Path;
#[cfg(feature = "sqlx")]
use std::sync::OnceLock;

#[cfg(feature = "sqlx")]
use sqlx::{AnyPool, ConnectOptions};
use x509_parser::prelude::{FromDer, X509Certificate};

use rustls_pki_types::TrustAnchor;

/// Loaded and validated root trust store shared by issuance and presentation engines.
///
/// All certificates in this store have been validated at startup:
/// - Self-signed (issuer == subject)
/// - Basic-constraints CA = true
///
/// The same underlying certificate bytes feed both:
/// - **IACA roots** — raw DER bytes for [`cloud_wallet_openid4vc::formats::mdoc::StaticTrustStore`] (mdoc issuerAuth verification)
/// - **X5C trust anchors** — parsed [`TrustAnchor`] values for SD-JWT VC x5c chain verification
#[derive(Debug, Clone)]
pub struct RootTrustStore {
    pub iaca_roots: Vec<Vec<u8>>,
    pub x5c_trust_anchors: Vec<TrustAnchor<'static>>,
}

/// An SQL database driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(feature = "sqlx")]
pub enum Driver {
    Postgres,
    MySql,
    Sqlite,
}
#[cfg(feature = "sqlx")]
impl Driver {
    /// Create a new driver from a pool.
    pub fn from_pool(pool: &AnyPool) -> Self {
        let url = pool.connect_options().to_url_lossy();
        let url = url.as_str();
        if url.starts_with("postgres://") || url.starts_with("postgresql://") {
            Self::Postgres
        } else if url.starts_with("mysql://") || url.starts_with("mariadb://") {
            Self::MySql
        } else {
            Self::Sqlite
        }
    }

    #[inline]
    pub fn is_postgres(&self) -> bool {
        matches!(self, Self::Postgres)
    }

    /// Write a bind placeholder into `buf`.
    /// Postgres uses `$N`; MySQL and SQLite use `?`.
    #[inline]
    pub fn write_placeholder(&self, buf: &mut String, index: usize) {
        if self.is_postgres() {
            buf.push('$');
            write!(buf, "{index}").unwrap();
        } else {
            buf.push('?');
        }
    }
}

/// Query wrapper that handles driver-specific placeholder rewriting.
///
/// Postgres uses `$N` placeholders; MySQL and SQLite use `?`.
/// This wrapper automatically rewrites queries to the target driver's format.
#[cfg(feature = "sqlx")]
pub struct Query {
    raw: &'static str,
    rewritten: OnceLock<String>,
}

#[cfg(feature = "sqlx")]
impl Query {
    /// Create a new query wrapper from a raw SQL string.
    pub const fn new(raw: &'static str) -> Self {
        Self {
            raw,
            rewritten: OnceLock::new(),
        }
    }

    /// Get the query string for the given driver.
    ///
    /// The query is computed once and cached.
    pub fn for_driver(&self, driver: &Driver) -> &str {
        match driver {
            Driver::Postgres => self.raw,
            Driver::MySql | Driver::Sqlite => self
                .rewritten
                .get_or_init(|| rewrite_to_positional(self.raw).into_owned()),
        }
    }
}

/// Rewrite a query from `$N` placeholders to `?` placeholders.
#[cfg(feature = "sqlx")]
fn rewrite_to_positional(sql: &str) -> Cow<'_, str> {
    let bytes = sql.as_bytes();
    let mut result = String::with_capacity(sql.len());
    let mut last = 0usize;
    let mut index = 0usize;

    while index < bytes.len() {
        if bytes[index] == b'$' {
            let start_digits = index + 1;
            let mut end_digits = start_digits;
            while end_digits < bytes.len() && bytes[end_digits].is_ascii_digit() {
                end_digits += 1;
            }

            if end_digits > start_digits {
                result.push_str(&sql[last..index]);
                result.push('?');
                index = end_digits;
                last = index;
                continue;
            }
        }
        index += 1;
    }
    result.push_str(&sql[last..]);
    Cow::Owned(result)
}

/// Loads and validates all X.509 root certificates from a truststore directory.
///
/// Each file in `dir` may be DER-encoded or PEM-encoded (possibly containing
/// multiple certificates). Every parsed certificate must be a well-formed X.509
/// root CA (self-signed, basic-constraints CA=true); otherwise a hard startup
/// error is returned.
///
/// If `dir` is `None`, logs a `WARN` and returns an empty store (all mdoc/x5c
/// verifications will fail closed). If `dir` is `Some(path)` but the directory
/// does not exist, returns a hard error (misconfigured path). If `dir` is
/// `Some(path)` and the directory exists but is empty, logs a `WARN`.
pub fn load_root_truststore(dir: Option<&Path>) -> color_eyre::Result<RootTrustStore> {
    let Some(dir) = dir.filter(|d| !d.as_os_str().is_empty()) else {
        tracing::warn!(
            "root truststore directory not configured; \
             all mdoc/x5c verifications will fail closed"
        );
        return Ok(RootTrustStore {
            iaca_roots: Vec::new(),
            x5c_trust_anchors: Vec::new(),
        });
    };

    load_root_truststore_from_dir(dir)
}

fn load_root_truststore_from_dir(dir: &Path) -> color_eyre::Result<RootTrustStore> {
    if !dir.exists() {
        return Err(eyre!(
            "root truststore directory '{}' does not exist; \
             verify APP_OID4VC__ROOT_TRUSTSTORE_DIR is correct",
            dir.display()
        ));
    }

    let entries = std::fs::read_dir(dir)
        .wrap_err_with(|| format!("failed to read truststore directory '{}'", dir.display()))?;

    let mut iaca_roots = Vec::new();
    let mut x5c_trust_anchors = Vec::new();

    for entry in entries {
        let entry = entry.wrap_err("failed to read directory entry")?;
        let path = entry.path();

        if !path.is_file() {
            continue;
        }

        let bytes = std::fs::read(&path)
            .wrap_err_with(|| format!("failed to read certificate file '{}'", path.display()))?;

        let certs = if bytes.starts_with(b"-----BEGIN") {
            let mut parsed = Vec::new();
            for cert in CertificateDer::pem_slice_iter(&bytes) {
                let cert = cert.wrap_err_with(|| {
                    format!("malformed PEM in certificate file '{}'", path.display())
                })?;
                parsed.push(cert.as_ref().to_vec());
            }
            if parsed.is_empty() {
                return Err(eyre!(
                    "certificate file '{}' is PEM-formatted but contains no certificates",
                    path.display()
                ));
            }
            parsed
        } else {
            vec![bytes]
        };

        for (idx, der_bytes) in certs.iter().enumerate() {
            let label = if certs.len() > 1 {
                format!("certificate #{} in '{}'", idx + 1, path.display())
            } else {
                format!("certificate in '{}'", path.display())
            };

            // Validate using x509_parser first: must be a self-signed root CA.
            let (_rest, parsed) = X509Certificate::from_der(der_bytes)
                .wrap_err_with(|| format!("{label}: failed to parse X.509 certificate"))?;

            if parsed.issuer() != parsed.subject() {
                return Err(eyre!(
                    "{label}: certificate subject '{}' does not match \
                     issuer '{}'; only self-signed root CAs are accepted",
                    parsed.subject(),
                    parsed.issuer()
                ));
            }

            if !parsed.is_ca() {
                return Err(eyre!(
                    "{label}: certificate subject '{}' has basic-constraints \
                     CA=false; only root CAs are accepted",
                    parsed.subject()
                ));
            }

            let cert_der = CertificateDer::from(der_bytes.as_slice());

            match webpki::anchor_from_trusted_cert(&cert_der) {
                Ok(anchor) => {
                    let trust_anchor: TrustAnchor<'static> = anchor.to_owned();
                    iaca_roots.push(der_bytes.clone());
                    x5c_trust_anchors.push(trust_anchor);
                }
                Err(err) => {
                    return Err(eyre!(
                        "{label}: validated as root CA but failed to create trust anchor: {err}"
                    ));
                }
            }
        }
    }

    if iaca_roots.is_empty() {
        tracing::warn!(
            path = %dir.display(),
            "root truststore directory is empty; \
             all mdoc/x5c verifications will fail closed"
        );
    } else {
        tracing::info!(
            count = iaca_roots.len(),
            path = %dir.display(),
            "loaded root truststore certificates"
        );
    }

    Ok(RootTrustStore {
        iaca_roots,
        x5c_trust_anchors,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[cfg(feature = "sqlx")]
    #[test]
    fn rewrites_postgres_bindings_to_question_marks() {
        let sql = "SELECT * FROM credentials WHERE id = $1 AND tenant_id = $2";
        assert_eq!(
            rewrite_to_positional(sql).as_ref(),
            "SELECT * FROM credentials WHERE id = ? AND tenant_id = ?"
        );
    }

    // --- Root truststore tests ---

    fn self_signed_ca_cert() -> (Vec<u8>, String) {
        let mut params =
            rcgen::CertificateParams::new(vec!["test-ca.local".to_string()]).expect("cert params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate().expect("key generation");
        let cert = params.self_signed(&key).expect("self-signed CA cert");
        (cert.der().to_vec(), cert.pem())
    }

    fn end_entity_cert() -> Vec<u8> {
        let mut ca_params =
            rcgen::CertificateParams::new(vec!["test-ca.local".to_string()]).expect("cert params");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().expect("key generation");
        let _ca_cert = ca_params.self_signed(&ca_key).expect("self-signed CA cert");
        let ca_issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);

        let mut ee_params = rcgen::CertificateParams::new(vec!["end-entity.local".to_string()])
            .expect("cert params");
        ee_params.is_ca = rcgen::IsCa::NoCa;
        let ee_key = rcgen::KeyPair::generate().expect("key generation");
        let ee_cert = ee_params
            .signed_by(&ee_key, &ca_issuer)
            .expect("end-entity cert");
        ee_cert.der().to_vec()
    }

    #[test]
    fn loads_truststore_from_dir_with_der_and_pem() {
        let (der, pem) = self_signed_ca_cert();

        // DER file
        let dir = tempfile::tempdir().unwrap();
        let der_path = dir.path().join("root.der");
        std::fs::write(&der_path, &der).unwrap();
        let store = load_root_truststore(Some(dir.path())).unwrap();
        assert_eq!(store.iaca_roots.len(), 1);
        assert_eq!(store.x5c_trust_anchors.len(), 1);
        assert_eq!(store.iaca_roots[0], der);

        // PEM file
        let dir2 = tempfile::tempdir().unwrap();
        let pem_path = dir2.path().join("root.pem");
        std::fs::write(&pem_path, pem.as_bytes()).unwrap();
        let store2 = load_root_truststore(Some(dir2.path())).unwrap();
        assert_eq!(store2.iaca_roots.len(), 1);
        assert_eq!(store2.x5c_trust_anchors.len(), 1);
        assert_eq!(store2.iaca_roots[0], der);
    }

    #[test]
    fn loads_pem_bundle_from_dir() {
        let (der1, pem1) = self_signed_ca_cert();
        let (der2, pem2) = self_signed_ca_cert();

        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("roots.pem");
        std::fs::write(&bundle_path, format!("{pem1}{pem2}").as_bytes()).unwrap();
        let store = load_root_truststore(Some(dir.path())).unwrap();
        assert_eq!(store.iaca_roots.len(), 2);
        assert!(store.iaca_roots.contains(&der1));
        assert!(store.iaca_roots.contains(&der2));
        assert_eq!(store.x5c_trust_anchors.len(), 2);
    }

    #[test]
    fn rejects_non_self_signed_certificate() {
        let ee_der = end_entity_cert();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("end_entity.der");
        std::fs::write(&path, &ee_der).unwrap();

        let result = load_root_truststore(Some(dir.path()));
        assert!(
            result.is_err(),
            "non-self-signed cert should be rejected, but got Ok with {} iaca roots",
            result.unwrap().iaca_roots.len()
        );
    }

    #[test]
    fn returns_empty_on_none_dir() {
        let store = load_root_truststore(None::<&Path>).unwrap();
        assert!(store.iaca_roots.is_empty());
        assert!(store.x5c_trust_anchors.is_empty());
    }

    #[test]
    fn errors_on_nonexistent_dir() {
        let dir = PathBuf::from("/nonexistent/truststore/path");
        let result = load_root_truststore(Some(dir.as_path()));
        assert!(
            result.is_err(),
            "nonexistent configured truststore dir should be a hard error"
        );
    }

    #[test]
    fn errors_on_malformed_pem() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.pem");
        std::fs::write(
            &path,
            b"-----BEGIN CERTIFICATE-----\nnot-valid-base64!!!\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let result = load_root_truststore(Some(dir.path()));
        assert!(result.is_err());
    }

    #[test]
    fn errors_on_pem_without_certs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.pem");
        std::fs::write(
            &path,
            b"-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n",
        )
        .unwrap();
        let result = load_root_truststore(Some(dir.path()));
        assert!(result.is_err());
    }
}
