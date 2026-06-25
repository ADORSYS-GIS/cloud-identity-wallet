mod consent;
mod error;
mod start;

pub use consent::{
    ConsentOutcome, CredentialSelection, PresentationConsentRequest, PresentationConsentResponse,
};
pub use error::{PresentationError, PresentationErrorCode};
pub use start::{StartPresentationRequest, StartPresentationResponse};

use std::sync::Arc;

use base64ct::Encoding as _;
use cloud_wallet_openid4vc::oid4vp::client::{Oid4vpClient, PresentationContext};
use cloud_wallet_openid4vc::oid4vp::error::AuthorizationErrorCode;
use cloud_wallet_openid4vc::oid4vp::key_resolution::x509::X509Verifier;
use cloud_wallet_openid4vc::oid4vp::presentation::{PresentationFactory, SelectedCredential};
use cloud_wallet_openid4vc::oid4vp::request_object::VerifierKeyResolver;
use cloud_wallet_openid4vc::oid4vp::selection::{CredentialView, SelectionResult};
use rustls_pki_types::TrustAnchor;
use tracing::{debug, info, instrument};

use crate::domain::keys::tenant_crypto_signer;
use crate::domain::models::credential::CredentialDisplayMetadata;
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
        client_id: &cloud_wallet_openid4vc::oid4vp::client_id::ParsedClientId,
        header: &jsonwebtoken::Header,
    ) -> cloud_wallet_openid4vc::errors::Result<jsonwebtoken::DecodingKey> {
        // Dispatch based on client_id prefix
        if client_id.is_x509_san_dns() || client_id.is_x509_hash() {
            return self.x509.resolve_key(client_id, header).await;
        }

        // For redirect_uri: prefix, unsigned requests are handled by the client
        // before reaching key resolution. If we get here, the request has a
        // signed Request Object with a prefix we don't yet support.
        Err(cloud_wallet_openid4vc::errors::Error::message(
            cloud_wallet_openid4vc::errors::ErrorKind::InvalidPresentationRequest,
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

/// Credential data prepared for OpenID4VP matching plus wallet display metadata.
#[derive(Debug, Clone)]
pub struct StoredCredentialView {
    pub view: CredentialView,
    pub display: CredentialDisplayMetadata,
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
    /// `x509_trust_anchor_der` are raw DER-encoded X.509 root certificates
    /// used for `x509_san_dns` / `x509_hash` verifier key resolution.
    pub fn new<C, T>(
        client: Oid4vpClient,
        credential_repo: C,
        tenant_repo: T,
        x509_trust_anchor_der: Vec<Vec<u8>>,
    ) -> Self
    where
        C: CredentialRepo,
        T: TenantRepo,
    {
        let trust_anchors: Vec<TrustAnchor<'static>> = x509_trust_anchor_der
            .iter()
            .filter_map(|der| {
                let cert = rustls_pki_types::CertificateDer::from(der.as_slice());
                match webpki::anchor_from_trusted_cert(&cert) {
                    Ok(anchor) => {
                        let anchor: TrustAnchor<'static> = anchor.to_owned();
                        Some(anchor)
                    }
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            "skipping malformed X.509 trust anchor"
                        );
                        None
                    }
                }
            })
            .collect();

        let x509_verifier = X509Verifier::new(Arc::new(trust_anchors));
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
    ///
    /// Delegates to the [`Oid4vpClient`] which handles request parsing,
    /// Request Object resolution, JWT validation (using the verifier key
    /// resolver), DCQL extraction, and transaction data decoding.
    #[instrument(skip_all)]
    pub async fn process_request(&self, raw_request: &str) -> Result<PresentationContext> {
        debug!("processing OID4VP authorization request");
        let context = self
            .client
            .process_authz_request(raw_request, self.key_resolver.as_ref())
            .await?;
        info!(
            client_id = %context.client_id.value(),
            nonce = %context.nonce,
            queries = context.dcql_query.credentials.len(),
            "authorization request validated"
        );
        Ok(context)
    }

    /// Matches the wallet's credentials against the DCQL query in the context.
    pub fn match_credentials(
        &self,
        ctx: &PresentationContext,
        credentials: &[StoredCredentialView],
    ) -> SelectionResult {
        let views = credentials
            .iter()
            .map(|credential| credential.view.clone())
            .collect::<Vec<_>>();
        self.client.match_credentials(ctx, &views)
    }

    /// Builds and sends a VP Token response to the verifier.
    ///
    /// The selected credentials are moved (not cloned) into the VP token
    /// builder.
    #[instrument(skip_all)]
    pub async fn submit_presentation(
        &self,
        ctx: &PresentationContext,
        selected: Vec<SelectedCredential>,
    ) -> Result<cloud_wallet_openid4vc::oid4vp::authorization::DirectPostResponse> {
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
    ) -> Result<cloud_wallet_openid4vc::oid4vp::authorization::DirectPostResponse> {
        info!(
            client_id = %ctx.client_id.value(),
            error = %error_code,
            "sending error response to verifier"
        );
        let response = self.client.create_error_response(ctx, error_code).await?;
        Ok(response)
    }

    /// Loads the tenant's credentials and converts them to [`CredentialView`]
    /// for DCQL matching.
    ///
    /// Credentials that fail format-specific decoding (e.g., malformed SD-JWT)
    /// are logged and skipped rather than failing the entire operation.
    pub async fn load_credential_views(
        &self,
        tenant_id: uuid::Uuid,
    ) -> Result<Vec<StoredCredentialView>> {
        use crate::domain::models::credential::CredentialFilter;

        let filter = CredentialFilter {
            tenant_id: Some(tenant_id),
            exclude_expired: true,
            ..Default::default()
        };

        // list() returns CredentialSummary (lightweight), but we need
        // raw_credential payloads for DCQL claim matching.  Fetch each
        // full credential individually.
        let summaries = self
            .credential_repo
            .list(filter)
            .await
            .map_err(|e| PresentationError::internal(e.to_string()))?;
        tracing::info!("{summaries:#?}");

        let mut views = Vec::with_capacity(summaries.len());
        for summary in &summaries {
            match self.credential_repo.find_by_id(summary.id, tenant_id).await {
                Ok(cred) => match credential_to_view(&cred) {
                    Ok(view) => views.push(StoredCredentialView {
                        view,
                        display: summary.display.clone(),
                    }),
                    Err(err) => {
                        tracing::warn!(
                            credential_id = %cred.id,
                            error = %err,
                            "skipping credential: failed to build CredentialView"
                        );
                    }
                },
                Err(err) => {
                    tracing::warn!(
                        credential_id = %summary.id,
                        error = %err,
                        "skipping credential: failed to load from repo"
                    );
                }
            }
        }

        debug!(count = views.len(), "loaded credential views for matching");
        Ok(views)
    }

    /// Builds a [`SelectedCredential`] from a raw credential payload and its
    /// format, using format-specific presentation factories.
    ///
    /// This is the real entry point called by the consent handler after loading
    /// the credential from the repo.
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
        credential_id: &str,
        tenant_id: uuid::Uuid,
        credential: &crate::domain::models::credential::Credential,
        dcql_result: &SelectionResult,
    ) -> Result<SelectedCredential> {
        // Ensure the selection is a valid candidate for the query.
        let candidate = dcql_result
            .candidates
            .get(query_id)
            .and_then(|candidates| candidates.iter().find(|c| c.credential_id == credential_id))
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
                self.build_sd_jwt_presentation(ctx, query_id, credential, candidate)
                    .await
            }
            crate::domain::models::credential::CredentialFormat::Mdoc => {
                self.build_mdoc_presentation(ctx, query_id, tenant_id, credential)
                    .await
            }
            _ => {
                // jwt_vc_json, jwt_vc_json-ld, ldp_vc — pass raw credential through.
                Ok(SelectedCredential::string(
                    query_id,
                    &credential.raw_credential,
                ))
            }
        }
    }

    /// Builds an SD-JWT VC presentation with selective disclosure.
    #[instrument(skip_all)]
    async fn build_sd_jwt_presentation(
        &self,
        ctx: &PresentationContext,
        query_id: &str,
        credential: &crate::domain::models::credential::Credential,
        candidate: &cloud_wallet_openid4vc::oid4vp::selection::CredentialCandidate,
    ) -> Result<SelectedCredential> {
        use cloud_wallet_openid4vc::oid4vp::presentation::formats::sd_jwt::SdJwtPresentation;

        let matched_claim_paths: Vec<
            cloud_wallet_openid4vc::core::claim_path_pointer::ClaimPathPointer,
        > = candidate
            .matched_claims
            .iter()
            .map(|mc| mc.path.clone())
            .collect();

        // TODO: wire tenant key holder binding when the credential declares
        // `cnf` and the verifier requires cryptographic holder binding.
        let presentation = SdJwtPresentation::builder(
            &credential.raw_credential,
            ctx.client_id.value(),
            &ctx.nonce,
        )
        .requested_claims(matched_claim_paths)
        .build()
        .create_presentation()
        .map_err(|e| {
            PresentationError::internal(format!("SD-JWT presentation creation failed: {e}"))
        })?;

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
        credential: &crate::domain::models::credential::Credential,
    ) -> Result<SelectedCredential> {
        use ciborium::value::Value as CborValue;
        use cloud_wallet_openid4vc::oid4vci::client::ProofSigner;
        use cloud_wallet_openid4vc::oid4vp::presentation::ProofError;
        use cloud_wallet_openid4vc::oid4vp::presentation::formats::mdoc::{
            MdocPresentation, OpenID4VPHandover, SessionTranscript,
        };

        let Some(doctype) = credential.credential_types.first() else {
            return Err(PresentationError::internal(
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
                .map_err(|e| {
                    PresentationError::internal(format!(
                        "failed to build OpenID4VP handover for mdoc: {e}"
                    ))
                })?;
        let session_transcript = SessionTranscript::new(handover);

        let issuer_signed_bytes =
            base64ct::Base64UrlUnpadded::decode_vec(&credential.raw_credential).map_err(|e| {
                PresentationError::internal(format!(
                    "failed to decode base64url mdoc raw credential: {e}"
                ))
            })?;
        let issuer_signed: CborValue = ciborium::de::from_reader(issuer_signed_bytes.as_slice())
            .map_err(|e| {
                PresentationError::internal(format!("failed to decode mdoc IssuerSigned CBOR: {e}"))
            })?;

        let signer = tenant_crypto_signer(self.tenant_repo.as_ref(), tenant_id)
            .await
            .map_err(|e| {
                PresentationError::with_source(
                    PresentationErrorCode::InternalError,
                    "tenant key unavailable",
                    e,
                )
            })?;
        let algorithm = match signer.algorithm() {
            cloud_wallet_openid4vc::oid4vci::client::Algorithm::ES256 => {
                coset::iana::Algorithm::ES256
            }
            cloud_wallet_openid4vc::oid4vci::client::Algorithm::ES384 => {
                coset::iana::Algorithm::ES384
            }
            _ => {
                return Err(PresentationError::internal(
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
            .build()
            .map_err(|e| {
                PresentationError::internal(format!("failed to build mdoc presentation: {e}"))
            })?;

        let presentation = presentation.create_presentation().map_err(|e| {
            PresentationError::internal(format!("mdoc presentation creation failed: {e}"))
        })?;

        Ok(SelectedCredential::new(query_id, presentation))
    }
}

/// Converts a domain [`Credential`](crate::domain::models::credential::Credential)
/// to a [`CredentialView`] for DCQL matching.
///
/// Performs format-specific decoding to extract the claims JSON:
/// - **`dc+sd-jwt`**: Parses the SD-JWT and produces the fully disclosed payload.
/// - **`mso_mdoc`**: Decodes the base64url CBOR and extracts namespace/element pairs.
/// - Other formats: Uses an empty JSON object as claims.
fn credential_to_view(
    credential: &crate::domain::models::credential::Credential,
) -> std::result::Result<CredentialView, PresentationError> {
    let dcql_format = credential.format.to_dcql_format();

    let claims = decode_credential_claims(credential)?;

    let vct = credential.credential_types.first().cloned();

    Ok(CredentialView {
        id: credential.id.to_string(),
        format: dcql_format,
        vct: if matches!(
            credential.format,
            crate::domain::models::credential::CredentialFormat::SdJwtVc
        ) {
            vct.clone()
        } else {
            None
        },
        doctype: if matches!(
            credential.format,
            crate::domain::models::credential::CredentialFormat::Mdoc
        ) {
            vct.clone()
        } else {
            None
        },
        credential_types: credential.credential_types.clone(),
        claims,
        issuer: Some(credential.issuer.clone()),
        trusted_authorities: Vec::new(),
        holder_binding_supported: true,
    })
}

/// Decodes credential claims from the raw credential payload.
///
/// Produces the JSON value needed for DCQL claim path matching.
fn decode_credential_claims(
    credential: &crate::domain::models::credential::Credential,
) -> std::result::Result<serde_json::Value, PresentationError> {
    use cloud_wallet_openid4vc::formats::sd_jwt::SdJwt;

    match credential.format {
        crate::domain::models::credential::CredentialFormat::SdJwtVc => {
            let sd_jwt = SdJwt::parse(&credential.raw_credential)
                .map_err(|e| PresentationError::internal(format!("failed to parse SD-JWT: {e}")))?;
            sd_jwt.to_disclosed_payload().map_err(|e| {
                PresentationError::internal(format!("failed to disclose SD-JWT payload: {e}"))
            })
        }
        crate::domain::models::credential::CredentialFormat::Mdoc => {
            // For mdoc, decode the base64url CBOR IssuerSigned and extract
            // namespace→element pairs as a JSON object.
            let bytes = base64ct::Base64UrlUnpadded::decode_vec(&credential.raw_credential)
                .map_err(|e| {
                    PresentationError::internal(format!("failed to decode mdoc base64url: {e}"))
                })?;
            let cbor_value: ciborium::value::Value = ciborium::de::from_reader(bytes.as_slice())
                .map_err(|e| {
                    PresentationError::internal(format!("failed to decode mdoc CBOR: {e}"))
                })?;
            // Extract nameSpaces from IssuerSigned and convert to JSON
            extract_mdoc_claims(&cbor_value)
        }
        _ => {
            // For JWT-based formats, decode the payload from the JWT
            let parts: Vec<&str> = credential.raw_credential.splitn(3, '.').collect();
            if parts.len() >= 2 {
                use base64ct::Encoding as _;
                let payload_bytes =
                    base64ct::Base64UrlUnpadded::decode_vec(parts[1]).map_err(|e| {
                        PresentationError::internal(format!("failed to decode JWT payload: {e}"))
                    })?;
                serde_json::from_slice(&payload_bytes).map_err(|e| {
                    PresentationError::internal(format!("failed to parse JWT payload JSON: {e}"))
                })
            } else {
                Ok(serde_json::Value::Object(serde_json::Map::new()))
            }
        }
    }
}

/// Extracts claims from an mdoc IssuerSigned CBOR value as a JSON object.
///
/// The result is keyed by namespace, each containing an object of
/// `elementIdentifier → elementValue` pairs.
fn extract_mdoc_claims(
    issuer_signed: &ciborium::value::Value,
) -> std::result::Result<serde_json::Value, PresentationError> {
    use ciborium::value::Value as CborValue;

    let CborValue::Map(top_map) = issuer_signed else {
        return Ok(serde_json::Value::Object(serde_json::Map::new()));
    };

    let namespaces_entry = top_map
        .iter()
        .find(|(k, _)| matches!(k, CborValue::Text(t) if t == "nameSpaces"));

    let Some((_, CborValue::Map(ns_map))) = namespaces_entry else {
        return Ok(serde_json::Value::Object(serde_json::Map::new()));
    };

    let mut result = serde_json::Map::new();
    for (ns_key, ns_items) in ns_map {
        let CborValue::Text(namespace) = ns_key else {
            continue;
        };
        let CborValue::Array(items) = ns_items else {
            continue;
        };

        let mut ns_claims = serde_json::Map::new();
        for item in items {
            // Each item is Tag(24, Bytes(cbor-encoded IssuerSignedItem))
            let item_bytes = match item {
                CborValue::Tag(24, inner) => match inner.as_ref() {
                    CborValue::Bytes(b) => b.as_slice(),
                    _ => continue,
                },
                _ => continue,
            };

            let Ok(item_value) = ciborium::de::from_reader::<CborValue, _>(item_bytes) else {
                continue;
            };

            let CborValue::Map(item_map) = &item_value else {
                continue;
            };

            let element_id = item_map.iter().find_map(|(k, v)| {
                if matches!(k, CborValue::Text(t) if t == "elementIdentifier") {
                    if let CborValue::Text(id) = v {
                        Some(id.clone())
                    } else {
                        None
                    }
                } else {
                    None
                }
            });

            let element_value = item_map.iter().find_map(|(k, v)| {
                if matches!(k, CborValue::Text(t) if t == "elementValue") {
                    cbor_to_json(v).ok()
                } else {
                    None
                }
            });

            if let (Some(id), Some(val)) = (element_id, element_value) {
                ns_claims.insert(id, val);
            }
        }

        result.insert(namespace.clone(), serde_json::Value::Object(ns_claims));
    }

    Ok(serde_json::Value::Object(result))
}

/// Best-effort conversion from CBOR to JSON for mdoc element values.
fn cbor_to_json(
    value: &ciborium::value::Value,
) -> std::result::Result<serde_json::Value, PresentationError> {
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
