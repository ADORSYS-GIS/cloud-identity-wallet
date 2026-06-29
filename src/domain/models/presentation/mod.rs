mod consent;
mod error;
mod start;

use cloud_wallet_openid4vc::formats::mdoc::ParsedMdoc;
use cloud_wallet_openid4vc::oid4vci::client::ProofSigner;
pub use consent::*;
pub use error::{PresentationError, PresentationErrorCode};
pub use start::{StartPresentationRequest, StartPresentationResponse};

use std::sync::Arc;

use base64::Engine as _;
use base64ct::Encoding as _;
use cloud_wallet_openid4vc::errors::{Error as Oid4vcError, ErrorKind};
use cloud_wallet_openid4vc::oid4vp::authorization::DirectPostResponse;
use cloud_wallet_openid4vc::oid4vp::client::{Oid4vpClient, PresentationContext};
use cloud_wallet_openid4vc::oid4vp::client_id::ParsedClientId;
use cloud_wallet_openid4vc::oid4vp::dcql::TrustedAuthorityType;
use cloud_wallet_openid4vc::oid4vp::error::AuthorizationErrorCode;
use cloud_wallet_openid4vc::oid4vp::key_resolution::x509::X509Verifier;
use cloud_wallet_openid4vc::oid4vp::presentation::{PresentationFactory, SelectedCredential};
use cloud_wallet_openid4vc::oid4vp::request_object::VerifierKeyResolver;
use cloud_wallet_openid4vc::oid4vp::selection::{
    CredentialAuthority, CredentialCandidate, CredentialView, SelectionResult,
};
use cloud_wallet_openid4vc::oid4vp::transaction_data::TransactionData;
use rustls_pki_types::TrustAnchor;
use tracing::{debug, info, instrument};

use crate::domain::keys::tenant_crypto_signer;
use crate::domain::models::credential::{Credential, CredentialFormat};
use crate::domain::ports::{CredentialRepo, TenantRepo};

type Result<T> = std::result::Result<T, PresentationError>;

/// Composite key resolver that dispatches to the appropriate resolver based
/// on the client_id prefix.
///
/// Currently supports:
/// - `x509_san_dns:` and `x509_hash:` via [`X509Verifier`]
/// - `redirect_uri:` (unsigned requests — no key resolution needed, uses a
///   no-op path in the client)
///
/// Additional resolvers (`verifier_attestation:`, `decentralized_identifier:`,
/// `openid_federation:`) can be added here as they are implemented.
struct CompositeKeyResolver {
    x509: X509Verifier,
}

#[async_trait::async_trait]
impl VerifierKeyResolver for CompositeKeyResolver {
    async fn resolve_key(
        &self,
        client_id: &ParsedClientId,
        header: &jsonwebtoken::Header,
    ) -> cloud_wallet_openid4vc::errors::Result<jsonwebtoken::DecodingKey> {
        // Dispatch based on client_id prefix
        if client_id.is_x509_san_dns() || client_id.is_x509_hash() {
            return self.x509.resolve_key(client_id, header).await;
        }

        // For redirect_uri: prefix, unsigned requests are handled by the client
        // before reaching key resolution. If we get here, the request has a
        // signed Request Object with a prefix we don't yet support.
        Err(Oid4vcError::message(
            ErrorKind::InvalidPresentationRequest,
            format!(
                "unsupported client_id prefix for key resolution: {}",
                client_id.raw()
            ),
        ))
    }
}

/// The presentation engine.
///
/// Holds shared references to all internal services.
/// Designed to be cheaply cloneable (all fields are `Arc`).
pub struct PresentationEngine {
    pub client: Arc<Oid4vpClient>,
    pub credential_repo: Arc<dyn CredentialRepo>,
    pub tenant_repo: Arc<dyn TenantRepo>,
    key_resolver: Arc<dyn VerifierKeyResolver>,
}

impl Clone for PresentationEngine {
    fn clone(&self) -> Self {
        Self {
            client: Arc::clone(&self.client),
            credential_repo: Arc::clone(&self.credential_repo),
            tenant_repo: Arc::clone(&self.tenant_repo),
            key_resolver: Arc::clone(&self.key_resolver),
        }
    }
}

impl std::fmt::Debug for PresentationEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PresentationEngine")
            .field("client", &std::any::type_name::<Oid4vpClient>())
            .field(
                "credential_repo",
                &std::any::type_name::<dyn CredentialRepo>(),
            )
            .field("tenant_repo", &std::any::type_name::<dyn TenantRepo>())
            .finish_non_exhaustive()
    }
}

impl PresentationEngine {
    /// Creates a new presentation engine with all required dependencies.
    ///
    /// `x5c_trust_anchors` are pre-validated X.509 root trust anchors used for
    /// `x509_san_dns` / `x509_hash` verifier key resolution. They should be
    /// loaded once at startup via [`crate::utils::load_root_truststore`] and
    /// shared across engines.
    pub fn new<C, T>(
        client: Oid4vpClient,
        credential_repo: C,
        tenant_repo: T,
        x5c_trust_anchors: Arc<Vec<TrustAnchor<'static>>>,
    ) -> Self
    where
        C: CredentialRepo,
        T: TenantRepo,
    {
        let x509_verifier = X509Verifier::new(x5c_trust_anchors);
        let key_resolver = Arc::new(CompositeKeyResolver {
            x509: x509_verifier,
        });

        Self {
            client: Arc::new(client),
            credential_repo: Arc::new(credential_repo),
            tenant_repo: Arc::new(tenant_repo),
            key_resolver,
        }
    }

    /// Processes a raw OID4VP authorization request into a validated
    /// [`PresentationContext`].
    #[instrument(skip_all)]
    pub async fn process_request(&self, raw_request: &str) -> Result<PresentationContext> {
        debug!("processing OID4VP authorization request");
        let context = self
            .client
            .process_authz_request(raw_request, self.key_resolver.as_ref())
            .await?;
        info!(
            client_id = %context.client_id.value(),
            queries = context.dcql_query.credentials.len(),
            "authorization request validated"
        );
        Ok(context)
    }

    /// Ensures the requested DCQL credential formats intersect with this
    /// wallet's advertised VP format capabilities.
    pub fn ensure_supported_vp_formats(&self, ctx: &PresentationContext) -> Result<()> {
        let supported_formats = self
            .client
            .config()
            .wallet_metadata
            .as_ref()
            .map(|metadata| &metadata.vp_formats_supported);

        let supports_format = |format: &cloud_wallet_openid4vc::oid4vp::dcql::CredentialFormat| {
            supported_formats
                .map(|formats| {
                    formats
                        .keys()
                        .any(|supported_format| supported_format.to_string() == format.to_string())
                })
                .unwrap_or_else(|| {
                    matches!(
                        format,
                        cloud_wallet_openid4vc::oid4vp::dcql::CredentialFormat::DcSdJwt
                            | cloud_wallet_openid4vc::oid4vp::dcql::CredentialFormat::MsoMdoc
                            | cloud_wallet_openid4vc::oid4vp::dcql::CredentialFormat::JwtVcJson
                    )
                })
        };

        if ctx
            .dcql_query
            .credentials
            .iter()
            .any(|query| supports_format(&query.format))
        {
            return Ok(());
        }

        Err(PresentationError::new(
            PresentationErrorCode::VpFormatsNotSupported,
            "None of the requested VP formats are supported by this wallet",
        ))
    }

    /// Matches the wallet's credentials against the DCQL query in the context.
    pub fn match_credentials(
        &self,
        ctx: &PresentationContext,
        credentials: &[CredentialView],
    ) -> SelectionResult {
        self.client.match_credentials(ctx, credentials)
    }

    /// Builds and sends a VP Token response to the verifier.
    #[instrument(skip_all)]
    pub async fn submit_presentation(
        &self,
        ctx: &PresentationContext,
        selected: Vec<SelectedCredential>,
    ) -> Result<DirectPostResponse> {
        info!(
            client_id = %ctx.client_id.value(),
            credentials = selected.len(),
            "submitting VP token to verifier"
        );
        let response = self.client.create_response(ctx, selected).await?;
        Ok(response)
    }

    /// Sends an error response (e.g., `access_denied`) to the verifier.
    #[instrument(skip_all)]
    pub async fn reject_presentation(
        &self,
        ctx: &PresentationContext,
        error_code: AuthorizationErrorCode,
    ) -> Result<DirectPostResponse> {
        info!(
            client_id = %ctx.client_id.value(),
            error = %error_code,
            "sending error response to verifier"
        );
        let response = self.client.create_error_response(ctx, error_code).await?;
        Ok(response)
    }

    /// Loads the tenant's credentials and converts them to [`CredentialView`]
    /// for DCQL matching, together with a map of display metadata keyed by
    /// credential id.
    ///
    /// Credentials that fail format-specific decoding (e.g., malformed SD-JWT)
    /// are logged and skipped rather than failing the entire operation.
    pub async fn load_credential_views(
        &self,
        tenant_id: uuid::Uuid,
    ) -> Result<(
        Vec<CredentialView>,
        std::collections::HashMap<
            String,
            crate::domain::models::credential::CredentialDisplayMetadata,
        >,
    )> {
        use crate::domain::models::credential::CredentialFilter;

        let filter = CredentialFilter {
            tenant_id: Some(tenant_id),
            exclude_expired: true,
            ..Default::default()
        };

        // list() returns CredentialSummary, but we need raw_credential
        // payloads for DCQL claim matching.  Fetch each full credential
        // individually.
        let summaries = self.credential_repo.list(filter).await?;

        let mut views = Vec::with_capacity(summaries.len());
        let mut display_map = std::collections::HashMap::with_capacity(summaries.len());
        for summary in &summaries {
            match self.credential_repo.find_by_id(summary.id, tenant_id).await {
                Ok(cred) => match credential_to_view(&cred) {
                    Ok(view) => {
                        display_map.insert(view.id.clone(), summary.display.clone());
                        views.push(view);
                    }
                    Err(err) => {
                        tracing::warn!(
                            credential_id = %cred.id,
                            error = %err,
                            "skipping credential: failed to build CredentialView"
                        );
                    }
                },
                Err(err) => return Err(err.into()),
            }
        }
        debug!(count = views.len(), "loaded credential views for matching");
        Ok((views, display_map))
    }

    /// Builds a [`SelectedCredential`] from a raw credential payload and its
    /// format, using format-specific presentation factories.
    ///
    /// # Errors
    ///
    /// Returns [`PresentationErrorCode::InvalidRequest`] when selected credentials
    /// are not valid candidates, or [`PresentationErrorCode::InternalError`] when
    /// format-specific presentation creation fails.
    #[instrument(skip_all)]
    pub async fn build_selected_credential_from_raw(
        &self,
        ctx: &PresentationContext,
        query_id: &str,
        tenant_id: uuid::Uuid,
        credential: &Credential,
        dcql_result: &SelectionResult,
        transaction_data: &[TransactionData<'_>],
    ) -> Result<SelectedCredential> {
        // Ensure the selection is a valid candidate for the query.
        let mut credential_id_buf = uuid::Uuid::encode_buffer();
        let credential_id = credential
            .id
            .hyphenated()
            .encode_lower(&mut credential_id_buf);
        let candidate = dcql_result
            .candidates
            .get(query_id)
            .and_then(|candidates| {
                candidates
                    .iter()
                    .find(|candidate| candidate.credential_id == *credential_id)
            })
            .ok_or_else(|| {
                PresentationError::new(
                    PresentationErrorCode::InvalidRequest,
                    format!(
                        "credential {credential_id} is not a valid candidate for query {query_id}"
                    ),
                )
            })?;

        match credential.format {
            crate::domain::models::credential::CredentialFormat::SdJwtVc => {
                self.build_sd_jwt_presentation(
                    ctx,
                    query_id,
                    tenant_id,
                    credential,
                    candidate,
                    transaction_data,
                )
                .await
            }
            crate::domain::models::credential::CredentialFormat::Mdoc => {
                if !transaction_data.is_empty() {
                    tracing::warn!(
                        query_id = query_id,
                        count = transaction_data.len(),
                        "transaction data is not yet supported for mdoc presentations; \
                         hashes will not be bound to the device authentication"
                    );
                }
                self.build_mdoc_presentation(ctx, query_id, tenant_id, credential)
                    .await
            }
            other => Err(PresentationError::new(
                PresentationErrorCode::InvalidRequest,
                format!("Unsupported credential format: {other}"),
            )),
        }
    }

    /// Builds an SD-JWT VC presentation with selective disclosure.
    #[instrument(skip_all)]
    async fn build_sd_jwt_presentation(
        &self,
        ctx: &PresentationContext,
        query_id: &str,
        tenant_id: uuid::Uuid,
        credential: &Credential,
        candidate: &CredentialCandidate,
        transaction_data: &[TransactionData<'_>],
    ) -> Result<SelectedCredential> {
        use cloud_wallet_openid4vc::core::claim_path_pointer::ClaimPathPointer;
        use cloud_wallet_openid4vc::formats::sd_jwt::KEY_BINDING_JWT_TYP;
        use cloud_wallet_openid4vc::oid4vp::presentation::ProofError;
        use cloud_wallet_openid4vc::oid4vp::presentation::formats::sd_jwt::SdJwtPresentation;

        let matched_claim_paths: Vec<ClaimPathPointer> = candidate
            .matched_claims
            .iter()
            .map(|mc| mc.path.clone())
            .collect();

        let mut builder = SdJwtPresentation::builder(
            &credential.raw_credential,
            ctx.client_id.value(),
            &ctx.nonce,
        )
        .requested_claims(matched_claim_paths);

        let applicable_td: Vec<&TransactionData<'_>> = transaction_data
            .iter()
            .filter(|td| td.applies_to_credential(query_id))
            .collect();

        let mut td_hashes: Vec<String> = Vec::new();
        let mut td_alg: Option<String> = None;
        if !applicable_td.is_empty() {
            let all_algs: Vec<Vec<String>> = applicable_td
                .iter()
                .map(|td| td.hash_algorithms())
                .collect();
            let alg_set: Vec<String> = all_algs.first().cloned().unwrap_or_default()
                .into_iter()
                .filter(|alg| all_algs.iter().all(|algs| algs.contains(alg)))
                .collect();
            let alg = alg_set
                .first()
                .cloned()
                .unwrap_or_else(|| "sha-256".to_string());
            td_alg = Some(alg.clone());
            for td in &applicable_td {
                let hash = td.compute_hash(&alg).map_err(|e| {
                    PresentationError::new(
                        PresentationErrorCode::PresentationBuildFailed,
                        format!("Failed to compute transaction data hash: {e}"),
                    )
                })?;
                td_hashes.push(hash);
            }
        }

        if !td_hashes.is_empty() {
            builder = builder.transaction_data(td_hashes, td_alg);
        }

        if requires_holder_binding(ctx, query_id)? {
            let signer = tenant_crypto_signer(self.tenant_repo.as_ref(), tenant_id)
                .await
                .map_err(PresentationError::internal)?;
            let signer = Arc::new(signer);
            builder = builder.signer(move |claims| {
                sign_key_binding_jwt(&signer, claims, KEY_BINDING_JWT_TYP)
                    .map_err(|err| ProofError::SigningFailed(err.to_string()))
            });
        }

        let presentation = builder.build().create_presentation()?;
        Ok(SelectedCredential::new(query_id, presentation))
    }

    /// Builds an ISO mdoc `DeviceResponse` presentation, including a device
    /// signature bound to the OID4VP session transcript.
    #[instrument(skip_all)]
    async fn build_mdoc_presentation(
        &self,
        ctx: &PresentationContext,
        query_id: &str,
        tenant_id: uuid::Uuid,
        credential: &Credential,
    ) -> Result<SelectedCredential> {
        use ciborium::value::Value as CborValue;
        use cloud_wallet_openid4vc::oid4vci::client::ProofSigner;
        use cloud_wallet_openid4vc::oid4vp::presentation::ProofError;
        use cloud_wallet_openid4vc::oid4vp::presentation::formats::mdoc::{
            MdocPresentation, OpenID4VPHandover, SessionTranscript,
        };

        let Some(doctype) = credential.credential_types.first() else {
            return Err(PresentationError::internal_message(
                "mdoc credential is missing doc_type",
            ));
        };

        let response_uri = ctx
            .response_uri
            .as_ref()
            .map(|u| u.to_string())
            .unwrap_or_default();

        let handover =
            OpenID4VPHandover::new(ctx.client_id.value(), &response_uri, ctx.nonce.clone())
                .map_err(PresentationError::internal)?;
        let session_transcript = SessionTranscript::new(handover);

        let issuer_signed_bytes =
            base64ct::Base64UrlUnpadded::decode_vec(&credential.raw_credential)?;
        let issuer_signed: CborValue = ciborium::de::from_reader(issuer_signed_bytes.as_slice())?;

        let signer = tenant_crypto_signer(self.tenant_repo.as_ref(), tenant_id)
            .await
            .map_err(PresentationError::internal)?;
        let algorithm = match signer.algorithm() {
            cloud_wallet_openid4vc::oid4vci::client::Algorithm::ES256 => {
                coset::iana::Algorithm::ES256
            }
            cloud_wallet_openid4vc::oid4vci::client::Algorithm::ES384 => {
                coset::iana::Algorithm::ES384
            }
            _ => {
                return Err(PresentationError::internal_message(
                    "tenant key algorithm is incompatible with ISO mdoc DeviceSignature (ES256/ES384 required)",
                ));
            }
        };

        // The signer closure must be 'static. We wrap the CryptoSigner
        // refcounted so we can move it into the closure.
        let signer = std::sync::Arc::new(signer);
        let presentation = MdocPresentation::builder(doctype, session_transcript)
            .algorithm(algorithm)
            .issuer_signed(issuer_signed)
            .signer(move |tbs| {
                let signer = Arc::clone(&signer);
                // The CryptoSigner signs the full Sig_Structure bytes. For
                // ECDSA P-256/384 we return raw r||s signature bytes.
                signer
                    .sign_bytes(tbs)
                    .map_err(|e| ProofError::SigningFailed(e.to_string()))
            })
            .build()?;

        let presentation = presentation.create_presentation()?;
        Ok(SelectedCredential::new(query_id, presentation))
    }
}

fn requires_holder_binding(ctx: &PresentationContext, query_id: &str) -> Result<bool> {
    let Some(query) = ctx
        .dcql_query
        .credentials
        .iter()
        .find(|query| query.id == query_id)
    else {
        return Err(PresentationError::new(
            PresentationErrorCode::InvalidRequest,
            format!("credential query {query_id} does not exist in the DCQL request"),
        ));
    };

    Ok(query.require_cryptographic_holder_binding.unwrap_or(true))
}

fn sign_key_binding_jwt(
    signer: &cloud_wallet_openid4vc::oid4vci::client::CryptoSigner,
    claims: &cloud_wallet_openid4vc::formats::sd_jwt::KeyBindingClaims,
    typ: &'static str,
) -> std::result::Result<String, cloud_wallet_openid4vc::oid4vci::client::ClientError> {
    let header = cloud_wallet_openid4vc::oid4vci::client::ProofHeader {
        alg: signer.algorithm(),
        typ,
        kid: None,
        jwk: None,
        x5c: None,
        attestation: None,
        trust_chain: None,
    };
    signer.sign_jwt(&header, claims)
}

/// Converts a domain [`Credential`] to a [`CredentialView`] for DCQL matching.
///
/// Performs format-specific decoding to extract the claims JSON:
/// - **`dc+sd-jwt`**: Parses the SD-JWT and produces the fully disclosed payload.
/// - **`mso_mdoc`**: Decodes the base64url CBOR and extracts namespace/element pairs.
/// - Other formats: Unsupported.
fn credential_to_view(credential: &Credential) -> Result<CredentialView> {
    let dcql_format = credential.format.into();
    let decoded = decode_credential_for_matching(credential)?;
    let credential_type = credential.credential_types.first().cloned();

    Ok(CredentialView {
        id: credential.id.to_string(),
        format: dcql_format,
        vct: if matches!(credential.format, CredentialFormat::SdJwtVc) {
            credential_type.clone()
        } else {
            None
        },
        doctype: if matches!(credential.format, CredentialFormat::Mdoc) {
            credential_type.clone()
        } else {
            None
        },
        credential_types: credential.credential_types.clone(),
        claims: decoded.claims,
        issuer: Some(credential.issuer.clone()),
        trusted_authorities: decoded.trusted_authorities,
        holder_binding_supported: decoded.holder_binding_supported,
    })
}

struct DecodedCredential {
    claims: serde_json::Value,
    trusted_authorities: Vec<CredentialAuthority>,
    holder_binding_supported: bool,
}

/// Decodes credential claims from the raw credential payload.
///
/// Produces the JSON value needed for DCQL claim path matching.
fn decode_credential_for_matching(credential: &Credential) -> Result<DecodedCredential> {
    use cloud_wallet_openid4vc::formats::sd_jwt::SdJwt;

    match credential.format {
        CredentialFormat::SdJwtVc => {
            let sd_jwt = SdJwt::parse(&credential.raw_credential)?;
            let holder_binding_supported = sd_jwt.jwt().claims().cnf.is_some();
            let trusted_authorities = trusted_authorities_from_sd_jwt(&sd_jwt);
            let claims = sd_jwt.to_disclosed_payload()?;
            Ok(DecodedCredential {
                claims,
                trusted_authorities,
                holder_binding_supported,
            })
        }
        CredentialFormat::Mdoc => {
            let parsed = ParsedMdoc::parse(&credential.raw_credential)?;
            let trusted_authorities = trusted_authorities_from_mdoc(&parsed);
            let claims = extract_mdoc_claims(&parsed)?;
            Ok(DecodedCredential {
                claims,
                trusted_authorities,
                holder_binding_supported: true,
            })
        }
        CredentialFormat::JwtVcJson | CredentialFormat::JwtVcJsonLd => {
            let claims = decode_jwt_claims(&credential.raw_credential)?;
            Ok(DecodedCredential {
                claims,
                trusted_authorities: vec![],
                holder_binding_supported: true,
            })
        }
        other => Err(PresentationError::internal_message(format!(
            "unsupported credential format: {other}"
        ))),
    }
}

fn decode_jwt_claims(raw_credential: &str) -> Result<serde_json::Value> {
    let payload = raw_credential.split('.').nth(1).ok_or_else(|| {
        PresentationError::internal_message("JWT credential is missing a payload segment")
    })?;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|err| {
            PresentationError::internal_message(format!(
                "failed to decode JWT credential payload: {err}"
            ))
        })?;

    serde_json::from_slice(&payload).map_err(PresentationError::internal)
}

/// Extracts claims from an mdoc IssuerSigned CBOR value as a JSON object.
///
/// The result is keyed by namespace, each containing an object of
/// `elementIdentifier -> elementValue` pairs.
fn extract_mdoc_claims(parsed: &ParsedMdoc) -> Result<serde_json::Value> {
    let mut result = serde_json::Map::new();
    for (namespace, items) in &parsed.name_spaces {
        let mut ns_claims = serde_json::Map::with_capacity(items.len());
        for item in items {
            let value: ciborium::value::Value =
                ciborium::de::from_reader(item.element_value.as_slice())?;
            ns_claims.insert(item.element_identifier.clone(), cbor_to_json(&value)?);
        }
        result.insert(namespace.clone(), serde_json::Value::Object(ns_claims));
    }
    Ok(serde_json::Value::Object(result))
}

fn trusted_authorities_from_sd_jwt(
    sd_jwt: &cloud_wallet_openid4vc::formats::sd_jwt::SdJwt<'_>,
) -> Vec<CredentialAuthority> {
    let mut authorities = vec![];
    if let Some(x5c) = sd_jwt.jwt().header().x5c.as_deref() {
        extend_aki_authorities_from_x5c(&mut authorities, x5c.iter().map(String::as_str));
    }
    authorities
}

fn trusted_authorities_from_mdoc(parsed: &ParsedMdoc) -> Vec<CredentialAuthority> {
    use ciborium::value::Value as CborValue;
    use coset::Label;

    const X5CHAIN_LABEL: i64 = 33;

    let mut authorities = vec![];
    let Some(x5chain) = parsed
        .cose_sign1
        .unprotected
        .rest
        .iter()
        .find(|(label, _)| *label == Label::Int(X5CHAIN_LABEL))
        .map(|(_, value)| value)
    else {
        return authorities;
    };

    match x5chain {
        CborValue::Bytes(der) => push_aki_authority_from_der(&mut authorities, der),
        CborValue::Array(chain) => {
            for entry in chain {
                if let CborValue::Bytes(der) = entry {
                    push_aki_authority_from_der(&mut authorities, der);
                }
            }
        }
        _ => {}
    }
    authorities
}

fn extend_aki_authorities_from_x5c<'a>(
    authorities: &mut Vec<CredentialAuthority>,
    x5c: impl IntoIterator<Item = &'a str>,
) {
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    for encoded in x5c {
        let Ok(der) = STANDARD.decode(encoded) else {
            continue;
        };
        push_aki_authority_from_der(authorities, &der);
    }
}

fn push_aki_authority_from_der(authorities: &mut Vec<CredentialAuthority>, der: &[u8]) {
    use base64ct::Encoding as _;
    use x509_parser::extensions::ParsedExtension;
    use x509_parser::prelude::{FromDer as _, X509Certificate};

    let Ok((_, cert)) = X509Certificate::from_der(der) else {
        return;
    };

    for extension in cert.extensions() {
        let ParsedExtension::AuthorityKeyIdentifier(aki) = extension.parsed_extension() else {
            continue;
        };
        let Some(key_identifier) = &aki.key_identifier else {
            continue;
        };

        let value = base64ct::Base64UrlUnpadded::encode_string(key_identifier.0);
        if !authorities.iter().any(|authority| {
            authority.authority_type == TrustedAuthorityType::Aki && authority.value == value
        }) {
            authorities.push(CredentialAuthority {
                authority_type: TrustedAuthorityType::Aki,
                value,
            });
        }
    }
}

/// Best-effort conversion from CBOR to JSON for mdoc element values.
fn cbor_to_json(value: &ciborium::value::Value) -> Result<serde_json::Value> {
    use ciborium::value::Value as CborValue;

    match value {
        CborValue::Text(s) => Ok(serde_json::Value::String(s.clone())),
        CborValue::Integer(i) => {
            let n: i128 = (*i).into();
            Ok(serde_json::json!(n))
        }
        CborValue::Bool(b) => Ok(serde_json::Value::Bool(*b)),
        CborValue::Null => Ok(serde_json::Value::Null),
        CborValue::Float(f) => Ok(serde_json::json!(*f)),
        CborValue::Bytes(b) => {
            use base64ct::Encoding as _;
            Ok(serde_json::Value::String(
                base64ct::Base64UrlUnpadded::encode_string(b),
            ))
        }
        CborValue::Array(arr) => {
            let items: std::result::Result<Vec<_>, _> = arr.iter().map(cbor_to_json).collect();
            Ok(serde_json::Value::Array(items?))
        }
        CborValue::Map(map) => {
            let mut obj = serde_json::Map::new();
            for (k, v) in map {
                let key = match k {
                    CborValue::Text(s) => s.clone(),
                    _ => format!("{k:?}"),
                };
                obj.insert(key, cbor_to_json(v)?);
            }
            Ok(serde_json::Value::Object(obj))
        }
        // Tag values: unwrap the inner value
        CborValue::Tag(_, inner) => cbor_to_json(inner),
        _ => Ok(serde_json::Value::Null),
    }
}

impl From<CredentialFormat> for cloud_wallet_openid4vc::oid4vp::dcql::CredentialFormat {
    fn from(value: CredentialFormat) -> Self {
        use cloud_wallet_openid4vc::oid4vp::dcql::CredentialFormat as DcqlFormat;
        match value {
            CredentialFormat::SdJwtVc => DcqlFormat::DcSdJwt,
            CredentialFormat::Mdoc => DcqlFormat::MsoMdoc,
            CredentialFormat::JwtVcJson | CredentialFormat::JwtVcJsonLd => DcqlFormat::JwtVcJson,
            CredentialFormat::LdpVc => DcqlFormat::LdpVc,
        }
    }
}

impl From<cloud_wallet_openid4vc::oid4vp::presentation::ProofError> for PresentationError {
    fn from(err: cloud_wallet_openid4vc::oid4vp::presentation::ProofError) -> Self {
        Self::internal(err)
    }
}

impl From<base64ct::Error> for PresentationError {
    fn from(err: base64ct::Error) -> Self {
        Self::internal_message(format!("failed to decode mdoc base64url: {err}"))
    }
}

impl From<ciborium::de::Error<std::io::Error>> for PresentationError {
    fn from(err: ciborium::de::Error<std::io::Error>) -> Self {
        Self::internal_message(format!("failed to decode mdoc CBOR: {err}"))
    }
}

impl From<serde_json::Error> for PresentationError {
    fn from(err: serde_json::Error) -> Self {
        Self::internal(err)
    }
}

impl From<cloud_wallet_openid4vc::formats::sd_jwt::Error> for PresentationError {
    fn from(err: cloud_wallet_openid4vc::formats::sd_jwt::Error) -> Self {
        Self::internal(err)
    }
}

impl From<cloud_wallet_openid4vc::formats::mdoc::MdocError> for PresentationError {
    fn from(err: cloud_wallet_openid4vc::formats::mdoc::MdocError) -> Self {
        Self::internal(err)
    }
}

#[cfg(test)]
mod tests {
    use cloud_wallet_openid4vc::oauth::authorization::OAuthAuthorizationRequest;
    use cloud_wallet_openid4vc::oid4vp::authorization::{
        AuthorizationRequest, ResponseMode, ResponseType,
    };
    use cloud_wallet_openid4vc::oid4vp::client::PresentationContext;
    use cloud_wallet_openid4vc::oid4vp::client_id::ParsedClientId;
    use cloud_wallet_openid4vc::oid4vp::dcql::{
        CredentialFormat, CredentialMeta, CredentialQuery, DcqlQuery,
    };

    use super::*;

    fn presentation_context(require_holder_binding: Option<bool>) -> PresentationContext {
        let dcql_query = DcqlQuery {
            credentials: vec![CredentialQuery {
                id: "pid".to_string(),
                format: CredentialFormat::DcSdJwt,
                multiple: None,
                meta: CredentialMeta::SdJwt {
                    vct_values: vec!["https://example.com/vct".to_string()],
                },
                claims: None,
                claim_sets: None,
                trusted_authorities: None,
                require_cryptographic_holder_binding: require_holder_binding,
            }],
            credential_sets: None,
        };
        let client_id = ParsedClientId::parse("redirect_uri:https://verifier.example.com").unwrap();
        let response_uri = url::Url::parse("https://verifier.example.com/response").unwrap();

        PresentationContext {
            request: AuthorizationRequest {
                response_type: ResponseType::VpToken,
                nonce: "test-nonce".to_string(),
                response_mode: ResponseMode::DirectPost,
                oauth: OAuthAuthorizationRequest {
                    client_id: client_id.value().to_string(),
                    redirect_uri: None,
                    scope: None,
                    state: None,
                    nonce: None,
                    code_challenge: None,
                    code_challenge_method: None,
                },
                response_uri: Some(response_uri.clone()),
                request_uri: None,
                request_uri_method: None,
                dcql_query: Some(dcql_query.clone()),
                client_metadata: None,
                client_metadata_uri: None,
                request: None,
                transaction_data: None,
                verifier_info: None,
                expected_origins: None,
            },
            verifier_metadata: None,
            client_id,
            nonce: "test-nonce".to_string(),
            state: None,
            response_uri: Some(response_uri),
            response_mode: ResponseMode::DirectPost,
            dcql_query,
            transaction_data: vec![],
        }
    }

    #[test]
    fn holder_binding_defaults_to_required_when_query_omits_flag() {
        let ctx = presentation_context(None);

        assert!(requires_holder_binding(&ctx, "pid").unwrap());
    }

    #[test]
    fn holder_binding_honors_explicit_false() {
        let ctx = presentation_context(Some(false));

        assert!(!requires_holder_binding(&ctx, "pid").unwrap());
    }

    #[test]
    fn holder_binding_rejects_unknown_query_id() {
        let ctx = presentation_context(None);
        let err = requires_holder_binding(&ctx, "missing").unwrap_err();

        assert_eq!(err.error, PresentationErrorCode::InvalidRequest);
        assert_eq!(
            err.error_description.as_deref(),
            Some("credential query missing does not exist in the DCQL request")
        );
    }
}
