use cloud_wallet_openid4vc::oid4vci::client::{IssuanceFlow, ResolvedOfferContext};
use cloud_wallet_openid4vc::oid4vci::credential::offer::TxCode;
use cloud_wallet_openid4vc::oid4vci::metadata::{
    ClaimDescription, CredentialDisplay, IssuerDisplay,
};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

use super::IssuanceError;
use crate::session::IssuanceSession;

const SESSION_TTL: Duration = Duration::minutes(15);

#[derive(Debug, Clone, Deserialize)]
pub struct StartIssuanceRequest {
    pub offer: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct StartIssuanceResponse {
    pub session_id: String,
    pub expires_at: String,
    pub issuer: Vec<IssuerDisplay>,
    pub credential_types: Vec<CredentialTypeDisplay>,
    pub flow: String,
    pub tx_code_required: bool,
    pub tx_code: Option<TxCode>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CredentialTypeDisplay {
    pub credential_configuration_id: String,
    pub format: String,
    pub display: Vec<CredentialDisplay>,
    /// Claims metadata for this credential configuration, if provided by the issuer.
    pub claims: Option<Vec<ClaimDescription>>,
}

impl StartIssuanceResponse {
    pub fn from_context(
        context: &ResolvedOfferContext,
        session: &IssuanceSession,
    ) -> Result<Self, IssuanceError> {
        let issuer = match &context.issuer_metadata.display {
            Some(d) if !d.is_empty() => d.clone(),
            _ => vec![IssuerDisplay {
                name: Some(context.offer.credential_issuer.to_string()),
                locale: None,
                logo: None,
            }],
        };

        let credential_types: Vec<CredentialTypeDisplay> = context
            .offer
            .credential_configuration_ids
            .iter()
            .filter_map(|id| {
                let config = context
                    .issuer_metadata
                    .credential_configurations_supported
                    .get(id)?;

                let display = config
                    .credential_metadata
                    .as_ref()
                    .and_then(|m| m.display.as_ref())
                    .filter(|d| !d.is_empty())
                    .cloned()
                    .unwrap_or_else(|| {
                        vec![CredentialDisplay {
                            name: id.clone(),
                            locale: None,
                            logo: None,
                            background_color: None,
                            background_image: None,
                            text_color: None,
                            description: None,
                        }]
                    });

                let claims = config
                    .credential_metadata
                    .as_ref()
                    .and_then(|m| m.claims.clone());

                Some(CredentialTypeDisplay {
                    credential_configuration_id: id.clone(),
                    format: config.format_details.format_str().to_owned(),
                    display,
                    claims,
                })
            })
            .collect();

        let (flow, tx_code_required, tx_code) = match &context.flow {
            IssuanceFlow::AuthorizationCode { .. } => {
                ("authorization_code".to_owned(), false, None)
            }
            IssuanceFlow::PreAuthorizedCode { tx_code, .. } => {
                let required = tx_code.is_some();
                ("pre_authorized_code".to_owned(), required, tx_code.clone())
            }
        };

        let expires_at = (OffsetDateTime::now_utc() + SESSION_TTL)
            .format(&Rfc3339)
            .map_err(|e| {
                IssuanceError::internal_message(format!(
                    "failed to format expiration timestamp: {e}"
                ))
            })?;

        Ok(Self {
            session_id: session.id.clone(),
            expires_at,
            issuer,
            credential_types,
            flow,
            tx_code_required,
            tx_code,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::issuance::FlowType;
    use crate::session::IssuanceSession;
    use cloud_wallet_openid4vc::core::claim_path_pointer::ClaimPathPointer;

    fn make_session_with_claims(claims_json: Option<serde_json::Value>) -> IssuanceSession {
        let mut credential_config = serde_json::json!({
            "format": "dc+sd-jwt",
            "vct": "https://credentials.example.com/test"
        });

        if let Some(c) = claims_json {
            credential_config["credential_metadata"] = serde_json::json!({
                "display": [{ "name": "Test Credential", "locale": "en-US" }],
                "claims": c
            });
        }

        let context: ResolvedOfferContext = serde_json::from_value(serde_json::json!({
            "offer": {
                "credential_issuer": "https://issuer.example.com",
                "credential_configuration_ids": ["test_config"],
                "grants": {
                    "pre_authorized_code": {
                        "pre_authorized_code": "code123"
                    }
                }
            },
            "issuer_metadata": {
                "credential_issuer": "https://issuer.example.com",
                "credential_endpoint": "https://issuer.example.com/credential",
                "credential_configurations_supported": {
                    "test_config": credential_config
                }
            },
            "as_metadata": {
                "issuer": "https://issuer.example.com",
                "authorization_endpoint": "https://issuer.example.com/authorize",
                "token_endpoint": "https://issuer.example.com/token",
                "response_types_supported": ["code"]
            },
            "flow": {
                "PreAuthorizedCode": {
                    "pre_authorized_code": "code123"
                }
            }
        }))
        .unwrap();

        IssuanceSession::new(uuid::Uuid::new_v4(), context, FlowType::PreAuthorizedCode)
    }

    #[test]
    fn from_context_includes_claims_when_present() {
        let claims = serde_json::json!([
            { "path": ["given_name"], "mandatory": true, "display": [{ "name": "Given Name", "locale": "en-US" }] },
            { "path": ["family_name"], "mandatory": false }
        ]);
        let session = make_session_with_claims(Some(claims));
        let response = StartIssuanceResponse::from_context(&session.context, &session).unwrap();

        assert_eq!(response.credential_types.len(), 1);
        let ctype = &response.credential_types[0];
        assert_eq!(ctype.credential_configuration_id, "test_config");

        let claims = ctype.claims.as_ref().expect("claims should be present");
        assert_eq!(claims.len(), 2);
        assert_eq!(
            claims[0].path,
            ClaimPathPointer::from_strings(["given_name"])
        );
        assert!(claims[0].mandatory);
        assert_eq!(
            claims[0].display.as_ref().unwrap()[0].name,
            Some("Given Name".to_string())
        );
        assert_eq!(
            claims[1].path,
            ClaimPathPointer::from_strings(["family_name"])
        );
        assert!(!claims[1].mandatory);
    }

    #[test]
    fn from_context_claims_is_none_when_missing() {
        let session = make_session_with_claims(None);
        let response = StartIssuanceResponse::from_context(&session.context, &session).unwrap();

        assert_eq!(response.credential_types.len(), 1);
        assert!(response.credential_types[0].claims.is_none());
    }

    #[test]
    fn from_context_claims_is_empty_array_when_issuer_provides_empty() {
        let session = make_session_with_claims(Some(serde_json::json!([])));
        let response = StartIssuanceResponse::from_context(&session.context, &session).unwrap();

        assert_eq!(response.credential_types.len(), 1);
        let claims = response.credential_types[0]
            .claims
            .as_ref()
            .expect("claims should be Some");
        assert!(claims.is_empty());
    }
}
