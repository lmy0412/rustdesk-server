use crate::{
    api::{
        access::ApiError,
        admin_init,
        middleware::{invalidate_token_cache, ApiProtectionState},
    },
    auth::jwt::{sign_token, AuthState},
    database::Database,
    models::user::{validate_plain_password, validate_safe_user_id, validate_username, User},
};
use argon2::{
    password_hash::{PasswordHash, PasswordVerifier},
    Argon2,
};
use axum::http::StatusCode;

pub async fn verify_password_and_load_active_user(
    db: &Database,
    protection: &ApiProtectionState,
    username: &str,
    password: &str,
) -> Result<User, ApiError> {
    validate_username(username).map_err(ApiError::bad_request)?;
    validate_plain_password(password).map_err(ApiError::bad_request)?;

    let initial = db
        .find_user_by_username(username)
        .await
        .map_err(|_| ApiError::internal("user lookup failed"))?
        .ok_or_else(invalid_credentials)?;
    if !initial.is_active {
        return Err(ApiError::forbidden("account disabled"));
    }

    let password_owned = password.to_string();
    let password_hash = initial.password_hash.clone();
    let expected_id = initial.id;
    let expected_token_version = initial.token_version;
    let permit = protection.acquire_argon2().await?;
    let verified = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        verify_password(&password_owned, &password_hash)
    })
    .await
    .map_err(|_| ApiError::internal("password verification failed"))?;
    if !verified {
        return Err(invalid_credentials());
    }

    let current = db
        .find_user_by_id(expected_id)
        .await
        .map_err(|_| ApiError::internal("user lookup failed"))?
        .ok_or_else(invalid_credentials)?;
    if !current.is_active {
        return Err(ApiError::forbidden("account disabled"));
    }
    if current.token_version != expected_token_version || current.username != username {
        return Err(invalid_credentials());
    }
    validate_safe_user_id(current.id).map_err(|_| ApiError::internal("invalid user id"))?;
    Ok(current)
}

pub async fn hash_plain_password(
    protection: &ApiProtectionState,
    password: &str,
) -> Result<String, ApiError> {
    validate_plain_password(password).map_err(ApiError::bad_request)?;
    admin_init::hash_password_bounded(protection, password)
        .await
        .map_err(|_| ApiError::internal("password hash failed"))
}

pub fn sign_access_token(user: &User, auth_state: &AuthState) -> Result<String, ApiError> {
    validate_safe_user_id(user.id).map_err(|_| ApiError::internal("invalid user id"))?;
    sign_token(user, &auth_state.jwt_secret, auth_state.jwt_expiry_hours)
        .map_err(|_| ApiError::internal("token sign failed"))
}

pub async fn revoke_all_user_tokens(db: &Database, user_id: i64) -> Result<i64, ApiError> {
    validate_safe_user_id(user_id).map_err(|_| ApiError::internal("invalid user id"))?;
    let version = db
        .increment_token_version(user_id)
        .await
        .map_err(|_| ApiError::internal("logout failed"))?;
    invalidate_token_cache(user_id);
    Ok(version)
}

fn verify_password(password: &str, password_hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(password_hash) {
        Ok(hash) => hash,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

fn invalid_credentials() -> ApiError {
    ApiError::new(StatusCode::UNAUTHORIZED, "invalid username or password")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_hash_never_authenticates() {
        assert!(!verify_password("secret", "not-an-argon2-hash"));
    }
}
