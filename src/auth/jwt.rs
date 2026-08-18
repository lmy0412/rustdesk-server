use crate::{
    config::ProConfig,
    models::user::{User, MAX_SAFE_INTEGER},
};
use chrono::Utc;
use jsonwebtoken::{
    decode, encode, errors::ErrorKind, DecodingKey, EncodingKey, Header, Validation,
};
use serde_derive::{Deserialize, Serialize};
use std::{error::Error, fmt};

pub const DEFAULT_JWT_EXPIRY_HOURS: i64 = 24;
pub const DEFAULT_REFRESH_EXPIRY_DAYS: i64 = 7;
const TOKEN_TYPE_ACCESS: &str = "access";
const TOKEN_TYPE_REFRESH: &str = "refresh";

#[derive(Debug, Clone)]
pub struct AuthState {
    pub jwt_secret: String,
    pub jwt_expiry_hours: i64,
    pub refresh_expiry_days: i64,
}

impl AuthState {
    pub fn from_config(pro: &ProConfig) -> Self {
        Self {
            jwt_secret: pro.jwt_secret.clone(),
            jwt_expiry_hours: pro.jwt_expiry_hours,
            refresh_expiry_days: pro.refresh_expiry_days,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub typ: String,
    pub sub: i64,
    pub role: String,
    pub token_ver: i64,
    pub exp: usize,
    pub iat: usize,
}

#[derive(Debug, Clone)]
pub struct CurrentUser {
    pub id: i64,
    pub username: String,
    pub role: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefreshIdentity {
    pub user_id: i64,
    pub token_version: i64,
    pub issued_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RefreshClaims {
    typ: String,
    sub: i64,
    token_ver: i64,
    exp: usize,
    iat: usize,
}

#[derive(Debug)]
pub enum JwtError {
    InvalidToken,
    Expired,
    Encode(String),
}

impl fmt::Display for JwtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JwtError::InvalidToken => write!(f, "invalid token"),
            JwtError::Expired => write!(f, "token expired"),
            JwtError::Encode(err) => write!(f, "token encode failed: {}", err),
        }
    }
}

impl Error for JwtError {}

pub fn sign_token(user: &User, secret: &str, expiry_hours: i64) -> Result<String, JwtError> {
    let expiry_seconds = expiry_hours
        .checked_mul(3600)
        .ok_or(JwtError::InvalidToken)?;
    sign_token_seconds(user, secret, expiry_seconds)
}

pub fn sign_token_seconds(
    user: &User,
    secret: &str,
    expiry_seconds: i64,
) -> Result<String, JwtError> {
    validate_claim_numbers(user.id, user.token_version)?;
    let now = Utc::now().timestamp();
    let exp = now
        .checked_add(expiry_seconds)
        .ok_or(JwtError::InvalidToken)?;
    let claims = Claims {
        typ: TOKEN_TYPE_ACCESS.to_string(),
        sub: user.id,
        role: user.role.clone(),
        token_ver: user.token_version,
        exp: exp as usize,
        iat: now as usize,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|err| JwtError::Encode(err.to_string()))
}

pub fn sign_refresh_token(user: &User, secret: &str, expiry_days: i64) -> Result<String, JwtError> {
    validate_claim_numbers(user.id, user.token_version)?;
    let now = Utc::now().timestamp();
    let exp = now + expiry_days * 24 * 3600;
    let claims = RefreshClaims {
        typ: TOKEN_TYPE_REFRESH.to_string(),
        sub: user.id,
        token_ver: user.token_version,
        exp: exp as usize,
        iat: now as usize,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|err| JwtError::Encode(err.to_string()))
}

pub fn verify_token(token: &str, secret: &str) -> Result<Claims, JwtError> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .map(|data| {
        let claims = data.claims;
        if claims.typ == TOKEN_TYPE_ACCESS
            && validate_claim_numbers(claims.sub, claims.token_ver).is_ok()
        {
            Ok(claims)
        } else {
            Err(JwtError::InvalidToken)
        }
    })
    .map_err(map_decode_error)?
}

pub fn verify_refresh_token(token: &str, secret: &str) -> Result<RefreshIdentity, JwtError> {
    decode::<RefreshClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .map(|data| {
        let claims = data.claims;
        if claims.typ == TOKEN_TYPE_REFRESH
            && validate_claim_numbers(claims.sub, claims.token_ver).is_ok()
        {
            Ok(RefreshIdentity {
                user_id: claims.sub,
                token_version: claims.token_ver,
                issued_at: i64::try_from(claims.iat).map_err(|_| JwtError::InvalidToken)?,
            })
        } else {
            Err(JwtError::InvalidToken)
        }
    })
    .map_err(map_decode_error)?
}

fn validate_claim_numbers(user_id: i64, token_version: i64) -> Result<(), JwtError> {
    if !(1..=MAX_SAFE_INTEGER).contains(&user_id)
        || !(0..=MAX_SAFE_INTEGER).contains(&token_version)
    {
        return Err(JwtError::InvalidToken);
    }
    Ok(())
}

fn map_decode_error(err: jsonwebtoken::errors::Error) -> JwtError {
    match err.kind() {
        ErrorKind::ExpiredSignature => JwtError::Expired,
        _ => JwtError::InvalidToken,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, NaiveDateTime};

    fn epoch() -> NaiveDateTime {
        DateTime::from_timestamp(0, 0).unwrap().naive_utc()
    }

    fn fake_user() -> User {
        User {
            id: 7,
            username: "alice".to_string(),
            password_hash: "hash".to_string(),
            email: None,
            role: "admin".to_string(),
            is_active: true,
            token_version: 3,
            failed_login_count: 0,
            locked_until: None,
            oauth_provider: None,
            oauth_subject: None,
            last_login_at: None,
            created_at: epoch(),
            updated_at: epoch(),
        }
    }

    #[test]
    fn test_access_token_contains_token_version() {
        let user = fake_user();
        let token = sign_token(&user, "secret", 1).unwrap();
        let claims = verify_token(&token, "secret").unwrap();
        assert_eq!(claims.typ, "access");
        assert_eq!(claims.sub, 7);
        assert_eq!(claims.role, "admin");
        assert_eq!(claims.token_ver, 3);
    }

    #[test]
    fn test_refresh_token_contains_token_version() {
        let user = fake_user();
        let token = sign_refresh_token(&user, "secret", 1).unwrap();
        let identity = verify_refresh_token(&token, "secret").unwrap();
        assert_eq!(identity.user_id, 7);
        assert_eq!(identity.token_version, 3);
    }

    #[test]
    fn test_access_token_cannot_be_used_as_refresh_token() {
        let user = fake_user();
        let token = sign_token(&user, "secret", 1).unwrap();
        assert!(matches!(
            verify_refresh_token(&token, "secret"),
            Err(JwtError::InvalidToken)
        ));
    }

    #[test]
    fn test_refresh_token_cannot_be_used_as_access_token() {
        let user = fake_user();
        let token = sign_refresh_token(&user, "secret", 1).unwrap();
        assert!(matches!(
            verify_token(&token, "secret"),
            Err(JwtError::InvalidToken)
        ));
    }

    #[test]
    fn signing_rejects_claim_numbers_outside_json_safe_integer_range() {
        let mut user = fake_user();
        user.id = MAX_SAFE_INTEGER + 1;
        assert!(matches!(
            sign_token(&user, "secret", 1),
            Err(JwtError::InvalidToken)
        ));
        assert!(matches!(
            sign_refresh_token(&user, "secret", 1),
            Err(JwtError::InvalidToken)
        ));

        user.id = 1;
        user.token_version = MAX_SAFE_INTEGER + 1;
        assert!(matches!(
            sign_token(&user, "secret", 1),
            Err(JwtError::InvalidToken)
        ));
        assert!(matches!(
            sign_refresh_token(&user, "secret", 1),
            Err(JwtError::InvalidToken)
        ));
    }

    #[test]
    fn verification_rejects_forged_unsafe_access_and_refresh_claims() {
        let now = Utc::now().timestamp() as usize;
        let access = encode(
            &Header::default(),
            &Claims {
                typ: TOKEN_TYPE_ACCESS.to_string(),
                sub: MAX_SAFE_INTEGER + 1,
                role: "user".to_string(),
                token_ver: 0,
                exp: now + 3600,
                iat: now,
            },
            &EncodingKey::from_secret(b"secret"),
        )
        .unwrap();
        assert!(matches!(
            verify_token(&access, "secret"),
            Err(JwtError::InvalidToken)
        ));

        let refresh = encode(
            &Header::default(),
            &RefreshClaims {
                typ: TOKEN_TYPE_REFRESH.to_string(),
                sub: 1,
                token_ver: MAX_SAFE_INTEGER + 1,
                exp: now + 3600,
                iat: now,
            },
            &EncodingKey::from_secret(b"secret"),
        )
        .unwrap();
        assert!(matches!(
            verify_refresh_token(&refresh, "secret"),
            Err(JwtError::InvalidToken)
        ));
    }
}
