use crate::{
    api::access::ApiError,
    audit::{AuditEvent, AuditService},
    auth::jwt::CurrentUser,
    config::{validate_security_config, SecurityConfig},
    database::Database,
    security::SecurityPolicyState,
};
use axum::{
    extract::{connect_info::ConnectInfo, Extension},
    Json,
};
use serde_json::json;
use std::net::SocketAddr;

pub async fn handle_get_policies(
    Extension(current): Extension<CurrentUser>,
    Extension(security): Extension<SecurityPolicyState>,
) -> Result<Json<SecurityConfig>, ApiError> {
    require_admin(&current)?;
    security
        .snapshot()
        .map(Json)
        .map_err(|_| ApiError::internal("security policy read failed"))
}

pub async fn handle_update_policies(
    Extension(db): Extension<Database>,
    Extension(current): Extension<CurrentUser>,
    Extension(security): Extension<SecurityPolicyState>,
    Extension(audit): Extension<AuditService>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    Json(config): Json<SecurityConfig>,
) -> Result<Json<SecurityConfig>, ApiError> {
    require_admin(&current)?;
    validate_security_config(&config).map_err(ApiError::bad_request)?;
    let candidate = SecurityPolicyState::new(config.clone()).map_err(ApiError::bad_request)?;
    if !candidate
        .admin_ip_allowed(peer.ip())
        .map_err(|_| ApiError::internal("security policy CIDR check failed"))?
    {
        return Err(ApiError::bad_request(
            "new policy would exclude the current administrator IP",
        ));
    }
    let old = security
        .snapshot()
        .map_err(|_| ApiError::internal("security policy read failed"))?;
    security
        .update(&db, config.clone())
        .await
        .map_err(ApiError::internal)?;
    audit.record(
        AuditEvent::new("security.policy.update")
            .actor(current.id)
            .target("security_policy", "1")
            .ip(peer.ip())
            .detail(json!({ "changed_fields": changed_fields(&old, &config) })),
    );
    Ok(Json(config))
}

fn require_admin(current: &CurrentUser) -> Result<(), ApiError> {
    if current.role == "admin" {
        Ok(())
    } else {
        Err(ApiError::forbidden("admin role required"))
    }
}

fn changed_fields(old: &SecurityConfig, new: &SecurityConfig) -> Vec<&'static str> {
    let mut fields = Vec::new();
    if old.password_min_length != new.password_min_length {
        fields.push("password_min_length");
    }
    if old.password_require_number != new.password_require_number {
        fields.push("password_require_number");
    }
    if old.password_require_symbol != new.password_require_symbol {
        fields.push("password_require_symbol");
    }
    if old.login_max_failures != new.login_max_failures {
        fields.push("login_max_failures");
    }
    if old.login_lock_minutes != new.login_lock_minutes {
        fields.push("login_lock_minutes");
    }
    if old.session_timeout_minutes != new.session_timeout_minutes {
        fields.push("session_timeout_minutes");
    }
    if old.allowed_admin_cidrs != new.allowed_admin_cidrs {
        fields.push("allowed_admin_cidrs");
    }
    if old.audit_retention_days != new.audit_retention_days {
        fields.push("audit_retention_days");
    }
    fields
}
