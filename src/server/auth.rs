use axum::{
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::error::{unauthorized, ApiError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub iat: i64,
    pub exp: i64,
}

#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub tenant_id: Uuid,
}

impl AuthenticatedUser {
    pub fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }
}

impl<S> FromRequestParts<S> for AuthenticatedUser
where
    crate::config::JwtConfig: FromRef<S>,
    S: Send + Sync + 'static,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let jwt_config = crate::config::JwtConfig::from_ref(state);

        let auth_header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .ok_or_else(unauthorized)?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or_else(unauthorized)?;

        let claims = validate_token(token, &jwt_config.secret)?;

        let tenant_id = claims.sub;

        Ok(AuthenticatedUser { tenant_id })
    }
}

fn validate_token(token: &str, secret: &str) -> Result<Claims, ApiError> {
    let decoding_key = DecodingKey::from_secret(secret.as_bytes());
    let validation = Validation::new(Algorithm::HS256);

    let token_data = decode::<Claims>(token, &decoding_key, &validation)
        .map_err(|e| {
            tracing::debug!("Token validation failed: {}", e);
            unauthorized()
        })?;

    let claims = token_data.claims;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    if claims.exp < now {
        tracing::debug!("Token expired");
        return Err(unauthorized());
    }

    if claims.iat > now {
        tracing::debug!("Token issued in the future");
        return Err(unauthorized());
    }

    Ok(claims)
}

pub fn generate_token(tenant_id: Uuid, secret: &str, expires_in_secs: i64) -> Result<String, ApiError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let claims = Claims {
        sub: tenant_id,
        iat: now,
        exp: now + expires_in_secs,
    };

    let encoding_key = EncodingKey::from_secret(secret.as_bytes());
    encode(&Header::new(Algorithm::HS256), &claims, &encoding_key)
        .map_err(|e| {
            tracing::error!("Failed to generate token: {}", e);
            ApiError::Internal
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: &str = "test-secret-key-for-testing";

    #[test]
    fn test_generate_and_validate_token() {
        let tenant_id = Uuid::new_v4();
        let token = generate_token(tenant_id, TEST_SECRET, 3600).unwrap();

        let claims = validate_token(&token, TEST_SECRET).unwrap();
        assert_eq!(claims.sub, tenant_id);
    }

    #[test]
    fn test_invalid_secret_fails() {
        let tenant_id = Uuid::new_v4();
        let token = generate_token(tenant_id, TEST_SECRET, 3600).unwrap();

        let result = validate_token(&token, "wrong-secret");
        assert!(result.is_err());
    }

    #[test]
    fn test_expired_token_fails() {
        let tenant_id = Uuid::new_v4();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let claims = Claims {
            sub: tenant_id,
            iat: now - 7200,
            exp: now - 3600,
        };

        let encoding_key = EncodingKey::from_secret(TEST_SECRET.as_bytes());
        let token = encode(&Header::new(Algorithm::HS256), &claims, &encoding_key).unwrap();

        let result = validate_token(&token, TEST_SECRET);
        assert!(result.is_err());
    }

    #[test]
    fn test_future_issued_at_fails() {
        let tenant_id = Uuid::new_v4();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let claims = Claims {
            sub: tenant_id,
            iat: now + 3600,
            exp: now + 7200,
        };

        let encoding_key = EncodingKey::from_secret(TEST_SECRET.as_bytes());
        let token = encode(&Header::new(Algorithm::HS256), &claims, &encoding_key).unwrap();

        let result = validate_token(&token, TEST_SECRET);
        assert!(result.is_err());
    }
}
