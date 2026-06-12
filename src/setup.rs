use cloud_wallet_openid4vc::core::client::{Config as Oid4vciClientConfig, OidClient};
use cloud_wallet_openid4vc::formats::mdoc::StaticTrustStore;
use cloud_wallet_openid4vc::oid4vci::client::Oid4vciClient;

use crate::config::Config;
use crate::domain::models::issuance::IssuanceEngine;
use crate::domain::ports::TenantRepo;
use crate::domain::service::Service;
use crate::outbound::{
    MemoryCredentialRepo, MemoryEventPublisher, MemoryEventSubscriber, MemoryTaskQueue,
};
use crate::session::SessionStore;

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
fn load_iaca_roots(paths: &[String]) -> color_eyre::Result<Vec<Vec<u8>>> {
    use color_eyre::eyre::eyre;
    use rustls_pki_types::CertificateDer;
    use rustls_pki_types::pem::PemObject as _;

    let mut roots = Vec::new();
    for path in paths {
        let bytes = std::fs::read(path)
            .map_err(|e| eyre!("failed to read IACA root file '{path}': {e}"))?;

        if bytes.starts_with(b"-----BEGIN") {
            let mut count = 0usize;
            for cert in CertificateDer::pem_slice_iter(&bytes) {
                let cert =
                    cert.map_err(|e| eyre!("malformed PEM in IACA root file '{path}': {e}"))?;
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

/// Constructs an [`IssuanceEngine`] from configuration.
///
/// Loads IACA roots from [`crate::config::MdocConfig`].  Returns an error if any
/// configured root path is unreadable or is a PEM file with no certificates.
/// Logs a `WARN` at startup if no roots are loaded — the resulting store is
/// fail-closed and all mso_mdoc issuances will be rejected.
pub fn build_issuance_engine<S: SessionStore + Clone>(
    config: &Config,
    tenant_repo: impl TenantRepo,
    session_store: &S,
) -> color_eyre::Result<IssuanceEngine> {
    let client_config = Oid4vciClientConfig::new(
        config.oid4vci.client_id.clone(),
        config.oid4vci.redirect_uri.clone(),
    )
    .use_system_proxy(config.oid4vci.use_system_proxy)
    // TODO : remove this later on - only for local testing
    .accept_untrusted_hosts(true);

    let client = Oid4vciClient::new(OidClient::new(client_config)?);

    // TODO: Replace with production adapters (Redis, SQL)
    let task_queue = MemoryTaskQueue::new();
    let publisher = MemoryEventPublisher::new(128);
    let subscriber = MemoryEventSubscriber::new(&publisher);
    let credential_repo = MemoryCredentialRepo::new();
    let preferred_display_locales = config.oid4vci.preferred_display_locales.clone();

    let iaca_roots = load_iaca_roots(&config.mdoc.iaca_root_paths)?;
    if iaca_roots.is_empty() {
        tracing::warn!(
            "mdoc IACA trust store is empty: all mso_mdoc credential issuances will be rejected"
        );
    }

    let engine = IssuanceEngine::new(
        client,
        task_queue,
        publisher,
        subscriber,
        credential_repo,
        tenant_repo,
        session_store,
        preferred_display_locales,
    )
    .with_iaca_trust_store(StaticTrustStore::new(iaca_roots));
    Ok(engine)
}

/// Build a fully wired [`Service`] ready for use in the server.
pub fn build_service<S: SessionStore + Clone>(
    session_store: S,
    tenant_repo: impl TenantRepo + Clone,
    config: &Config,
) -> color_eyre::Result<Service<S>> {
    let engine = build_issuance_engine(config, tenant_repo.clone(), &session_store)?;
    Ok(Service::new(session_store, tenant_repo, engine))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cloud_wallet_openid4vc::formats::mdoc::IacaTrustStore;
    use std::io::Write;

    fn self_signed_cert() -> (Vec<u8>, String) {
        let params =
            rcgen::CertificateParams::new(vec!["test.local".to_string()]).expect("cert params");
        let key = rcgen::KeyPair::generate().expect("key generation");
        let cert = params.self_signed(&key).expect("self-signed cert");
        (cert.der().to_vec(), cert.pem())
    }

    #[test]
    fn loads_der_and_pem_to_same_bytes() {
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
            // loader→store link: the loaded bytes populate the trust store correctly
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
    fn errors_on_malformed_pem() {
        // invalid base64 inside a CERTIFICATE block
        let mut f1 = tempfile::NamedTempFile::new().unwrap();
        f1.write_all(
            b"-----BEGIN CERTIFICATE-----\nnot-valid-base64!!!\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        assert!(load_iaca_roots(&[f1.path().to_string_lossy().into_owned()]).is_err());

        // valid PEM syntax but no CERTIFICATE blocks (e.g. a private-key file)
        let mut f2 = tempfile::NamedTempFile::new().unwrap();
        f2.write_all(b"-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n")
            .unwrap();
        assert!(load_iaca_roots(&[f2.path().to_string_lossy().into_owned()]).is_err());
    }
}
