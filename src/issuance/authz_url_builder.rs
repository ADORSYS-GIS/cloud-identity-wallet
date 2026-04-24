use percent_encoding::{AsciiSet, CONTROLS, percent_encode};
use serde::Deserialize;
use thiserror::Error;
use url::Url;

use cloud_wallet_openid4vc::http::HttpClient;
use cloud_wallet_openid4vc::issuance::authz_details::AuthorizationDetails;
use cloud_wallet_openid4vc::issuance::authz_server_metadata::AuthorizationServerMetadata;

const FRAGMENT_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'<')
    .add(b'>')
    .add(b'`')
    .add(b'#')
    .add(b'{')
    .add(b'}')
    .add(b'[')
    .add(b']')
    .add(b'=')
    .add(b'&');

#[derive(Debug, Error)]
pub enum AuthorizationUrlBuilderError {
    #[error("Missing authorization endpoint in AS metadata")]
    MissingAuthorizationEndpoint,

    #[error("PAR request failed: {0}")]
    ParRequestFailed(String),

    #[error("URL construction failed: {0}")]
    UrlConstructionFailed(String),
}

#[derive(Debug, Clone, Deserialize)]
pub struct ParResponse {
    pub request_uri: String,
    #[serde(default)]
    pub expires_in: Option<u64>,
}

pub struct AuthorizationUrlBuilder {
    client_id: String,
    redirect_uri: Url,
    http_client: HttpClient,
}

impl AuthorizationUrlBuilder {
    pub fn new(client_id: String, redirect_uri: Url, http_client: HttpClient) -> Self {
        Self {
            client_id,
            redirect_uri,
            http_client,
        }
    }

    pub async fn build(
        &self,
        session_id: &str,
        code_challenge: &str,
        issuer_state: Option<&str>,
        authorization_details: Option<&[AuthorizationDetails]>,
        scope: Option<&str>,
        as_metadata: &AuthorizationServerMetadata,
    ) -> Result<String, AuthorizationUrlBuilderError> {
        let authorization_endpoint = as_metadata
            .authorization_endpoint
            .as_ref()
            .ok_or(AuthorizationUrlBuilderError::MissingAuthorizationEndpoint)?;

        if let Some(par_endpoint) = &as_metadata.pushed_authorization_request_endpoint {
            self.build_with_par(
                par_endpoint.as_str(),
                authorization_endpoint.as_str(),
                session_id,
                code_challenge,
                issuer_state,
                authorization_details,
                scope,
            )
            .await
        } else {
            self.build_inline(
                authorization_endpoint.as_str(),
                session_id,
                code_challenge,
                issuer_state,
                authorization_details,
                scope,
            )
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn build_with_par(
        &self,
        par_endpoint: &str,
        authorization_endpoint: &str,
        session_id: &str,
        code_challenge: &str,
        issuer_state: Option<&str>,
        authorization_details: Option<&[AuthorizationDetails]>,
        scope: Option<&str>,
    ) -> Result<String, AuthorizationUrlBuilderError> {
        let mut builder = self
            .http_client
            .post_form::<ParResponse>(par_endpoint)
            .param("response_type", "code")
            .param("client_id", &self.client_id)
            .param("redirect_uri", self.redirect_uri.as_str())
            .param("state", session_id)
            .param("code_challenge", code_challenge)
            .param("code_challenge_method", "S256");

        if let Some(is) = issuer_state {
            builder = builder.param("issuer_state", is);
        }

        if let Some(details) = authorization_details {
            let json = serde_json::to_string(details)
                .map_err(|e| AuthorizationUrlBuilderError::ParRequestFailed(e.to_string()))?;
            let encoded = percent_encode(json.as_bytes(), FRAGMENT_ENCODE_SET).to_string();
            builder = builder.param("authorization_details", encoded.as_str());
        }

        if let Some(s) = scope {
            builder = builder.param("scope", s);
        }

        let response = builder
            .send()
            .await
            .map_err(|e| AuthorizationUrlBuilderError::ParRequestFailed(e.to_string()))?;

        let par_response = response.body;

        let auth_url = format!(
            "{}?client_id={}&request_uri={}",
            authorization_endpoint,
            percent_encode(self.client_id.as_bytes(), FRAGMENT_ENCODE_SET),
            percent_encode(par_response.request_uri.as_bytes(), FRAGMENT_ENCODE_SET)
        );

        Ok(auth_url)
    }

    fn build_inline(
        &self,
        authorization_endpoint: &str,
        session_id: &str,
        code_challenge: &str,
        issuer_state: Option<&str>,
        authorization_details: Option<&[AuthorizationDetails]>,
        scope: Option<&str>,
    ) -> Result<String, AuthorizationUrlBuilderError> {
        let mut url = Url::parse(authorization_endpoint)
            .map_err(|e| AuthorizationUrlBuilderError::UrlConstructionFailed(e.to_string()))?;

        {
            let mut query_pairs = url.query_pairs_mut();
            query_pairs
                .append_pair("response_type", "code")
                .append_pair("client_id", &self.client_id)
                .append_pair("redirect_uri", self.redirect_uri.as_str())
                .append_pair("state", session_id)
                .append_pair("code_challenge", code_challenge)
                .append_pair("code_challenge_method", "S256");

            if let Some(is) = issuer_state {
                query_pairs.append_pair("issuer_state", is);
            }

            if let Some(details) = authorization_details {
                let json = serde_json::to_string(details).map_err(|e| {
                    AuthorizationUrlBuilderError::UrlConstructionFailed(e.to_string())
                })?;
                let encoded = percent_encode(json.as_bytes(), FRAGMENT_ENCODE_SET).to_string();
                query_pairs.append_pair("authorization_details", &encoded);
            }

            if let Some(s) = scope {
                query_pairs.append_pair("scope", s);
            }
        }

        Ok(url.to_string())
    }
}
