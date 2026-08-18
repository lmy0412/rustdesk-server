use crate::{
    api::{
        access::ApiError,
        admin_init,
        middleware::{invalidate_token_cache, ApiProtectionState},
    },
    audit::{resource_fingerprint, AuditEvent, AuditService},
    auth::jwt::{sign_token_seconds, AuthState},
    database::Database,
    models::user::{validate_plain_password, validate_safe_user_id, validate_username, User},
    security::SecurityPolicyState,
};
use argon2::{
    password_hash::{PasswordHash, PasswordVerifier},
    Argon2,
};
use axum::http::StatusCode;
use chrono::Utc;
use serde_json::json;
use std::net::IpAddr;

pub async fn verify_password_and_load_active_user(
    db: &Database,
    protection: &ApiProtectionState,
    security: &SecurityPolicyState,
    audit: &AuditService,
    peer_ip: IpAddr,
    username: &str,
    password: &str,
) -> Result<User, ApiError> {
    let target_id = resource_fingerprint(username);
    if let Err(message) = validate_username(username) {
        audit.record(login_event(
            "auth.login.failure",
            &target_id,
            peer_ip,
            json!({"reason": "invalid_input"}),
        ));
        return Err(ApiError::bad_request(message));
    }
    if let Err(message) = validate_plain_password(password) {
        audit.record(login_event(
            "auth.login.failure",
            &target_id,
            peer_ip,
            json!({"reason": "invalid_input"}),
        ));
        return Err(ApiError::bad_request(message));
    }

    let policy = security
        .snapshot()
        .map_err(|_| ApiError::internal("security policy read failed"))?;

    let initial = db
        .find_user_by_username(username)
        .await
        .map_err(|_| ApiError::internal("user lookup failed"))?
        .ok_or_else(|| {
            audit.record(login_event(
                "auth.login.failure",
                &target_id,
                peer_ip,
                json!({"reason": "invalid_credentials"}),
            ));
            invalid_credentials()
        })?;
    if let Some(locked_until) = initial.locked_until {
        if locked_until > Utc::now().naive_utc() {
            let retry = (locked_until - Utc::now().naive_utc()).num_seconds().max(1) as u64;
            audit.record(
                login_event(
                    "auth.login.locked",
                    &target_id,
                    peer_ip,
                    json!({"retry_after_seconds": retry}),
                )
                .actor(initial.id),
            );
            return Err(
                ApiError::new(StatusCode::TOO_MANY_REQUESTS, "account temporarily locked")
                    .retry_after(retry),
            );
        }
    }
    if !initial.is_active {
        audit.record(
            login_event(
                "auth.login.failure",
                &target_id,
                peer_ip,
                json!({"reason": "account_disabled"}),
            )
            .actor(initial.id),
        );
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
        let failure = db
            .record_login_failure(
                initial.id,
                policy.login_max_failures,
                policy.login_lock_minutes,
            )
            .await
            .map_err(|_| ApiError::internal("login failure state update failed"))?;
        let locked = failure.locked_until.is_some();
        audit.record(login_event(
            if locked { "auth.login.locked" } else { "auth.login.failure" },
            &target_id,
            peer_ip,
            json!({"reason": "invalid_credentials", "failed_count": failure.failed_login_count}),
        ).actor(initial.id));
        if let Some(locked_until) = failure.locked_until {
            let retry = (locked_until - Utc::now().naive_utc()).num_seconds().max(1) as u64;
            return Err(
                ApiError::new(StatusCode::TOO_MANY_REQUESTS, "account temporarily locked")
                    .retry_after(retry),
            );
        }
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
    if current.role == "admin"
        && !security
            .admin_ip_allowed(peer_ip)
            .map_err(|_| ApiError::internal("administrator IP policy check failed"))?
    {
        audit.record(
            login_event(
                "auth.login.ip_denied",
                &target_id,
                peer_ip,
                json!({"reason": "admin_ip_not_allowed"}),
            )
            .actor(current.id),
        );
        return Err(ApiError::forbidden("administrator IP is not allowed"));
    }
    let current = db
        .record_login_success(current.id)
        .await
        .map_err(|_| ApiError::internal("login success state update failed"))?;
    validate_safe_user_id(current.id).map_err(|_| ApiError::internal("invalid user id"))?;
    Ok(current)
}

pub async fn hash_plain_password(
    protection: &ApiProtectionState,
    security: &SecurityPolicyState,
    password: &str,
) -> Result<String, ApiError> {
    validate_plain_password(password).map_err(ApiError::bad_request)?;
    security
        .validate_new_password(password)
        .map_err(ApiError::bad_request)?;
    admin_init::hash_password_bounded(protection, password)
        .await
        .map_err(|_| ApiError::internal("password hash failed"))
}

pub fn sign_access_token(
    user: &User,
    auth_state: &AuthState,
    security: &SecurityPolicyState,
) -> Result<(String, i64), ApiError> {
    validate_safe_user_id(user.id).map_err(|_| ApiError::internal("invalid user id"))?;
    let lifetime = security
        .access_lifetime_seconds(auth_state.jwt_expiry_hours)
        .map_err(|_| ApiError::internal("session lifetime calculation failed"))?;
    let token = sign_token_seconds(user, &auth_state.jwt_secret, lifetime)
        .map_err(|_| ApiError::internal("token sign failed"))?;
    Ok((token, lifetime))
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

fn login_event(
    action: &str,
    target_id: &str,
    peer_ip: IpAddr,
    detail: serde_json::Value,
) -> AuditEvent {
    AuditEvent::new(action)
        .target("user", target_id)
        .ip(peer_ip)
        .detail(detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_hash_never_authenticates() {
        assert!(!verify_password("secret", "not-an-argon2-hash"));
    }
}
