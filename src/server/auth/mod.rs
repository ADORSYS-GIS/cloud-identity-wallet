pub mod error;

use axum::http::header;
use axum::{body::Body, extract::Request, middleware::Next, response::IntoResponse};
use error::AuthError;
use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub iat: i64,
    pub exp: i64,
}

pub async fn auth(mut request: Request<Body>, next: Next) -> Result<impl IntoResponse, AuthError> {
    let token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .and_then(|auth| auth.strip_prefix("Bearer "))
        .ok_or(AuthError::InvalidAuthorizationHeader)?;

    let header = decode_header(token)?;

    let jwk = header.jwk.ok_or(AuthError::MissingKey)?;

    let decoding_key = DecodingKey::from_jwk(&jwk)?;

    let validation = Validation::new(header.alg);

    let token_data = decode::<Claims>(token, &decoding_key, &validation)?;

    request.extensions_mut().insert(token_data.claims.sub);

    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::{Extension, Router, body::to_bytes, routing::get};
    use jsonwebtoken::jwk::Jwk;
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use time::OffsetDateTime;
    use tower::ServiceExt;

    fn create_test_keypair() -> (String, Jwk) {
        let private_key_pem = "-----BEGIN PRIVATE KEY-----
            MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgsJyilHyjhzXDVU2A
            5ud6kfXPktY7wx5d8CQFe1nMzK2hRANCAAQ17IW//Yvrs4SmU1smlHTYgWKzj+UV
            b0diaF8Xk6vqb3gB9qnvD4NxkNvLsQPPqjQKncEP831drigLydrC6WPT
            -----END PRIVATE KEY-----
        "
        .to_string();

        let public_key: Jwk = serde_json::from_str(
            r#"{
                "kty": "EC",
                "crv": "P-256",
                "x": "NeyFv_2L67OEplNbJpR02IFis4_lFW9HYmhfF5Or6m8",
                "y": "eAH2qe8Pg3GQ28uxA8-qNAqdwQ_zfV2uKAvJ2sLpY9M"
            }"#,
        )
        .unwrap();

        (private_key_pem, public_key)
    }

    fn create_test_token(sub: &Uuid, encoding_key: &EncodingKey, jwk: Option<Jwk>) -> String {
        let now = OffsetDateTime::now_utc().unix_timestamp();

        let claims = Claims {
            sub: *sub,
            iat: now,
            exp: now + 3600,
        };

        let mut header = Header::new(Algorithm::ES256);
        header.jwk = jwk;

        encode(&header, &claims, encoding_key).unwrap()
    }

    async fn test_handler(Extension(tenant_id): Extension<Uuid>) -> String {
        tenant_id.to_string()
    }

    fn create_test_router() -> Router {
        Router::new()
            .route("/test", get(test_handler))
            .layer(axum::middleware::from_fn(auth))
    }

    #[tokio::test]
    async fn test_missing_authorization_header() {
        let app = create_test_router();

        let request = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(body.contains("Missing or invalid Authorization header"));
    }

    #[tokio::test]
    async fn test_malformed_authorization_header() {
        let app = create_test_router();

        let request = Request::builder()
            .uri("/test")
            .header(header::AUTHORIZATION, "InvalidToken")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(body.contains("Missing or invalid Authorization header"));
    }

    #[tokio::test]
    async fn test_invalid_jwt_token() {
        let app = create_test_router();

        let request = Request::builder()
            .uri("/test")
            .header(header::AUTHORIZATION, "Bearer invalid_jwt_token")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_token_without_jwk() {
        let app = create_test_router();
        let (private_pem, _public_key) = create_test_keypair();

        let tenant_id = Uuid::new_v4();
        let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();
        let token = create_test_token(&tenant_id, &encoding_key, None);

        let request = Request::builder()
            .uri("/test")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(body.contains("Public key JWK not found in token header"));
    }

    #[tokio::test]
    async fn test_successful_authentication() {
        let (private_pem, public_key) = create_test_keypair();

        let app = create_test_router();

        let tenant_id = Uuid::new_v4();
        let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();
        let token = create_test_token(&tenant_id, &encoding_key, Some(public_key));

        let request = Request::builder()
            .uri("/test")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert_eq!(body, tenant_id.to_string());
    }

    #[tokio::test]
    async fn test_token_verification_failure_wrong_key() {
        let (_, public_key) = create_test_keypair();
        let wrong_private_pem = "-----BEGIN PRIVATE KEY-----
            MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUBIUj4mRpgdolCfi
            ajH0ju3KgSj8xQAlcvidrAkwOzChRANCAAQ4Wvc8XUs0zEqMKGtRYFnvYtDlzdH2
            7N3Eo65Js7drssgg7eKUSIlnJWMXHxqr8SfECuXi7sewuw2+mxs2adC5
            -----END PRIVATE KEY-----
        "
        .to_string();

        let app = create_test_router();

        let tenant_id = Uuid::new_v4();
        let wrong_encoding_key = EncodingKey::from_ec_pem(wrong_private_pem.as_bytes()).unwrap();
        let token = create_test_token(&tenant_id, &wrong_encoding_key, Some(public_key));

        let request = Request::builder()
            .uri("/test")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_expired_token() {
        let (private_pem, public_key) = create_test_keypair();

        let app = create_test_router();

        let tenant_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc().unix_timestamp();

        let expired_claims = Claims {
            sub: tenant_id,
            iat: now - 7200,
            exp: now - 3600,
        };

        let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();
        let mut header = Header::new(Algorithm::ES256);
        header.jwk = Some(public_key);
        let token = encode(&header, &expired_claims, &encoding_key).unwrap();

        let request = Request::builder()
            .uri("/test")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_request_extension_contains_tenant_id() {
        let (private_pem, public_key) = create_test_keypair();

        async fn extension_test_handler(Extension(tenant_id): Extension<Uuid>) -> String {
            tenant_id.to_string()
        }

        let app = Router::new()
            .route("/test", get(extension_test_handler))
            .layer(axum::middleware::from_fn(auth));

        let tenant_id = Uuid::new_v4();
        let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();
        let token = create_test_token(&tenant_id, &encoding_key, Some(public_key));

        let request = Request::builder()
            .uri("/test")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert_eq!(body, tenant_id.to_string());
    }
}
