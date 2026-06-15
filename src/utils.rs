use color_eyre::eyre::{WrapErr as _, eyre};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject as _;
use std::borrow::Cow;
use std::fmt::Write;
use std::sync::OnceLock;

use sqlx::{AnyPool, ConnectOptions};

/// An SQL database driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Driver {
    Postgres,
    MySql,
    Sqlite,
}

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
pub struct Query {
    raw: &'static str,
    rewritten: OnceLock<String>,
}

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

/// Loads IACA root certificates from the given file paths.
///
/// Each path may point to either a DER-encoded certificate or a PEM file containing
/// one or more certificates.  Format is detected by checking whether the file starts
/// with the ASCII bytes `-----BEGIN`.
///
/// DER files are accepted without structural validation; a malformed DER file
/// produces an `InvalidCertificateChain` error at the first credential
/// verification, not at startup.  PEM files are validated only insofar as they
/// must contain at least one parseable `CERTIFICATE` block.
///
/// # Errors
///
/// Returns an error if any path cannot be read, if a PEM file is malformed, or if a
/// PEM file contains no `CERTIFICATE` blocks.
pub(crate) fn load_iaca_roots(paths: &[String]) -> color_eyre::Result<Vec<Vec<u8>>> {
    let mut roots = Vec::new();
    for path in paths {
        let bytes = std::fs::read(path)
            .wrap_err_with(|| format!("failed to read IACA root file '{path}'"))?;

        if bytes.starts_with(b"-----BEGIN") {
            let mut count = 0usize;
            for cert in CertificateDer::pem_slice_iter(&bytes) {
                let cert =
                    cert.wrap_err_with(|| format!("malformed PEM in IACA root file '{path}'"))?;
                roots.push(cert.as_ref().to_vec());
                count += 1;
            }
            if count == 0 {
                return Err(eyre!(
                    "IACA root file '{path}' is PEM-formatted but contains no certificates"
                ));
            }
        } else {
            roots.push(bytes);
        }
    }
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn rewrites_postgres_bindings_to_question_marks() {
        let sql = "SELECT * FROM credentials WHERE id = $1 AND tenant_id = $2";
        assert_eq!(
            rewrite_to_positional(sql).as_ref(),
            "SELECT * FROM credentials WHERE id = ? AND tenant_id = ?"
        );
    }

    // --- load_iaca_roots tests ---

    fn self_signed_cert() -> (Vec<u8>, String) {
        let params =
            rcgen::CertificateParams::new(vec!["test.local".to_string()]).expect("cert params");
        let key = rcgen::KeyPair::generate().expect("key generation");
        let cert = params.self_signed(&key).expect("self-signed cert");
        (cert.der().to_vec(), cert.pem())
    }

    #[test]
    fn loads_der_and_pem_to_same_bytes() {
        use cloud_wallet_openid4vc::formats::mdoc::{IacaTrustStore, StaticTrustStore};
        use std::io::Write as _;

        let (der, pem) = self_signed_cert();
        for (label, content) in [("DER", der.clone()), ("PEM", pem.into_bytes())] {
            let mut f = tempfile::NamedTempFile::new().unwrap();
            f.write_all(&content).unwrap();
            let roots = load_iaca_roots(&[f.path().to_string_lossy().into_owned()]).unwrap();
            assert_eq!(
                roots,
                vec![der.clone()],
                "{label} file should decode to the same DER"
            );
            let store = StaticTrustStore::new(roots);
            assert_eq!(
                store.trusted_roots(),
                std::slice::from_ref(&der),
                "{label} roots must reach the store"
            );
        }
    }

    #[test]
    fn pem_bundle_loads_all_certs() {
        let (der1, pem1) = self_signed_cert();
        let (der2, pem2) = self_signed_cert();
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(format!("{pem1}{pem2}").as_bytes()).unwrap();
        let roots = load_iaca_roots(&[f.path().to_string_lossy().into_owned()]).unwrap();
        assert_eq!(roots.len(), 2);
        assert!(roots.contains(&der1) && roots.contains(&der2));
    }

    #[test]
    fn errors_on_bad_input() {
        assert!(load_iaca_roots(&["/nonexistent/path/root.pem".into()]).is_err());

        let mut f1 = tempfile::NamedTempFile::new().unwrap();
        f1.write_all(
            b"-----BEGIN CERTIFICATE-----\nnot-valid-base64!!!\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        assert!(load_iaca_roots(&[f1.path().to_string_lossy().into_owned()]).is_err());

        let mut f2 = tempfile::NamedTempFile::new().unwrap();
        f2.write_all(b"-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n")
            .unwrap();
        assert!(load_iaca_roots(&[f2.path().to_string_lossy().into_owned()]).is_err());
    }
}
