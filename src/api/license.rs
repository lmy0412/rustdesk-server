use crate::{
    audit::{resource_fingerprint, AuditEvent, AuditService},
    auth::jwt::CurrentUser,
    database::{Database, InactiveUpdate},
    peer::{
        DeviceInvalidationCommand, DeviceInvalidationPredicate, DeviceInvalidationSender,
        InvalidationResult,
    },
};
use axum::{
    extract::{connect_info::ConnectInfo, Extension, Path},
    http::StatusCode,
    Json,
};
use once_cell::sync::Lazy;
use serde_derive::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::SocketAddr;
use tokio::{
    sync::{mpsc::error::TrySendError, oneshot, Mutex},
    time::{timeout, Duration},
};

type ApiError = (StatusCode, Json<Value>);
static LICENSE_UPLOAD_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LicenseUploadRequest {
    pub license_key: String,
}

impl std::fmt::Debug for LicenseUploadRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LicenseUploadRequest")
            .field("license_key", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Serialize)]
pub struct LicenseStatusResponse {
    pub active: bool,
    pub issued_to: Option<String>,
    pub max_devices: Option<u32>,
    pub max_users: Option<u32>,
    pub features: Option<u64>,
    pub issued_at: Option<i64>,
    pub expires_at: Option<i64>,
    pub days_remaining: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct LicenseUploadResponse {
    pub status: String,
    pub issued_to: String,
    pub max_devices: u32,
    pub max_users: u32,
    pub features: u64,
    pub issued_at: i64,
    pub expires_at: i64,
    pub warning: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LicenseUsageResponse {
    pub max_devices: u32,
    pub current_devices: u32,
    pub online_devices: u32,
    pub offline_devices: u32,
    pub inactive_devices: u32,
    pub max_users: u32,
    pub current_users: u32,
    pub expires_at: Option<i64>,
    pub days_remaining: Option<i64>,
    pub device_usage_pct: f64,
    pub user_usage_pct: f64,
}

#[derive(Debug, Serialize)]
pub struct DeviceInactiveResponse {
    pub device_id: String,
    pub status: String,
    pub cache_invalidation: String,
    pub database_inactive_committed: bool,
    pub retryable: bool,
}

pub async fn handle_license_upload(
    Extension(db): Extension<Database>,
    Extension(current): Extension<CurrentUser>,
    Extension(audit): Extension<AuditService>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    Json(payload): Json<LicenseUploadRequest>,
) -> Result<Json<LicenseUploadResponse>, ApiError> {
    require_admin(&current)?;
    let fingerprint = resource_fingerprint(&payload.license_key);
    let license = match crate::license::parse_license_key(&payload.license_key) {
        Ok(license) => license,
        Err(err) => {
            audit.record(
                AuditEvent::new("license.upload.failure")
                    .actor(current.id)
                    .target("license", &fingerprint)
                    .ip(peer.ip())
                    .detail(json!({"reason": error_message(err)})),
            );
            return Err(bad_request("license validation failed".to_string()));
        }
    };
    let _upload_guard = LICENSE_UPLOAD_LOCK.lock().await;
    db.upsert_license(
        &payload.license_key,
        license.max_devices,
        if license.expires_at == 0 {
            None
        } else {
            Some(license.expires_at)
        },
        license.features,
        Some(current.id),
    )
    .await
    .map_err(|_| internal_error("license save failed"))?;
    crate::license::set_license(license.clone());
    if let Ok(usage) = db.device_usage().await {
        crate::license::log_quota_usage_event(
            "许可证上传或降额",
            usage.current(),
            license.max_devices,
        );
    }

    let warning = if crate::license::is_license_expired(&license) {
        audit.record(
            AuditEvent::new("license.expired")
                .actor(current.id)
                .target("license", &fingerprint)
                .ip(peer.ip())
                .detail(json!({"source": "upload"})),
        );
        Some("license has expired".to_string())
    } else {
        None
    };

    audit.record(AuditEvent::new("license.upload.success").actor(current.id).target("license", &fingerprint).ip(peer.ip()).detail(json!({"max_devices": license.max_devices, "max_users": license.max_users, "expires_at": license.expires_at})));
    Ok(Json(LicenseUploadResponse {
        status: "activated".to_string(),
        issued_to: license.issued_to.clone(),
        max_devices: license.max_devices,
        max_users: license.max_users,
        features: license.features,
        issued_at: license.issued_at,
        expires_at: license.expires_at,
        warning,
    }))
}

pub async fn handle_license_status() -> Result<Json<LicenseStatusResponse>, ApiError> {
    let Some(license) = crate::license::current_license() else {
        return Ok(Json(LicenseStatusResponse {
            active: false,
            issued_to: None,
            max_devices: None,
            max_users: None,
            features: None,
            issued_at: None,
            expires_at: None,
            days_remaining: None,
        }));
    };

    Ok(Json(LicenseStatusResponse {
        active: true,
        issued_to: Some(license.issued_to.clone()),
        max_devices: Some(license.max_devices),
        max_users: Some(license.max_users),
        features: Some(license.features),
        issued_at: Some(license.issued_at),
        expires_at: Some(license.expires_at),
        days_remaining: crate::license::days_remaining(&license),
    }))
}

pub async fn handle_license_usage(
    Extension(db): Extension<Database>,
    Extension(current): Extension<CurrentUser>,
) -> Result<Json<LicenseUsageResponse>, ApiError> {
    require_admin(&current)?;
    let license = crate::license::current_license();
    let max_devices = license
        .as_ref()
        .map(|license| license.max_devices)
        .unwrap_or(0);
    let max_users = license
        .as_ref()
        .map(|license| license.max_users)
        .unwrap_or(0);
    let usage = db
        .device_usage()
        .await
        .map_err(|_| internal_error("device usage lookup failed"))?;
    let current_devices = usage.current();
    let current_users = db
        .count_users()
        .await
        .map_err(|_| internal_error("user usage lookup failed"))?
        .max(0) as u32;

    Ok(Json(LicenseUsageResponse {
        max_devices,
        current_devices,
        online_devices: usage.online,
        offline_devices: usage.offline,
        inactive_devices: usage.inactive,
        max_users,
        current_users,
        expires_at: license.as_ref().map(|license| license.expires_at),
        days_remaining: license.as_ref().and_then(crate::license::days_remaining),
        device_usage_pct: pct(current_devices, max_devices),
        user_usage_pct: pct(current_users, max_users),
    }))
}

pub async fn handle_device_inactive(
    Path(device_id): Path<String>,
    Extension(db): Extension<Database>,
    Extension(device_control_tx): Extension<DeviceInvalidationSender>,
    Extension(current): Extension<CurrentUser>,
    Extension(audit): Extension<AuditService>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
) -> Result<Json<DeviceInactiveResponse>, ApiError> {
    require_admin(&current)?;
    match db
        .set_device_inactive(&device_id)
        .await
        .map_err(|_| internal_error("device inactive update failed"))?
    {
        InactiveUpdate::NotFound => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "device not found" })),
            ));
        }
        InactiveUpdate::Updated | InactiveUpdate::AlreadyInactive => {}
    }

    // 即使数据库原本已 inactive，也必须重发失效命令，以便幂等重试修复缓存。
    let ack_rx = enqueue_invalidation(
        &device_control_tx,
        device_id.clone(),
        DeviceInvalidationPredicate::StillInactive,
    )?;

    let invalidation = match timeout(Duration::from_secs(2), ack_rx).await {
        Ok(Ok(Ok(result))) => result,
        Ok(Ok(Err(()))) | Ok(Err(_)) | Err(_) => return Err(invalidation_unavailable()),
    };
    audit.record(
        AuditEvent::new("device.inactive")
            .actor(current.id)
            .target("device", resource_fingerprint(&device_id))
            .ip(peer.ip())
            .detail(json!({"invalidation": invalidation_name(invalidation)})),
    );
    Ok(Json(DeviceInactiveResponse {
        device_id,
        status: "inactive_committed".to_string(),
        cache_invalidation: invalidation_name(invalidation).to_string(),
        database_inactive_committed: true,
        retryable: false,
    }))
}

fn pct(current: u32, max: u32) -> f64 {
    if max == 0 {
        0.0
    } else {
        current as f64 * 100.0 / max as f64
    }
}

fn require_admin(current: &CurrentUser) -> Result<(), ApiError> {
    if current.role != "admin" {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "admin role required" })),
        ));
    }
    Ok(())
}

fn error_message(err: crate::license::LicenseError) -> String {
    match err {
        crate::license::LicenseError::SignatureVerification => {
            "license signature verification failed".to_string()
        }
        other => other.to_string(),
    }
}

fn bad_request(message: String) -> ApiError {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": message })))
}

fn internal_error(message: &str) -> ApiError {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": message })),
    )
}

fn invalidation_unavailable() -> ApiError {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({
            "error": "device is inactive in database, but rendezvous cache invalidation was not confirmed",
            "database_inactive_committed": true,
            "retryable": true
        })),
    )
}

fn enqueue_invalidation(
    sender: &DeviceInvalidationSender,
    device_id: String,
    predicate: DeviceInvalidationPredicate,
) -> Result<oneshot::Receiver<Result<InvalidationResult, ()>>, ApiError> {
    let (ack_tx, ack_rx) = oneshot::channel();
    match sender.try_send(DeviceInvalidationCommand {
        device_id,
        predicate,
        ack: ack_tx,
    }) {
        Ok(()) => Ok(ack_rx),
        Err(TrySendError::Full(_)) | Err(TrySendError::Closed(_)) => {
            Err(invalidation_unavailable())
        }
    }
}

fn invalidation_name(result: InvalidationResult) -> &'static str {
    match result {
        InvalidationResult::Removed => "removed",
        InvalidationResult::AlreadyAbsent => "already_absent",
        InvalidationResult::Replaced => "replaced",
        InvalidationResult::NoLongerInactive => "no_longer_inactive",
        InvalidationResult::GenerationStillPresent => "generation_still_present",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_invalidation_channel_keeps_issue_7_retryable() {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let first = enqueue_invalidation(
            &tx,
            "device-first".to_string(),
            DeviceInvalidationPredicate::StillInactive,
        );
        assert!(first.is_ok());

        let second = enqueue_invalidation(
            &tx,
            "device-second".to_string(),
            DeviceInvalidationPredicate::StillInactive,
        );
        assert_retryable_invalidation_error(second);
    }

    #[test]
    fn closed_invalidation_channel_keeps_issue_7_retryable() {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        drop(rx);

        let result = enqueue_invalidation(
            &tx,
            "device-closed".to_string(),
            DeviceInvalidationPredicate::StillInactive,
        );
        assert_retryable_invalidation_error(result);
    }

    fn assert_retryable_invalidation_error(
        result: Result<oneshot::Receiver<Result<InvalidationResult, ()>>, ApiError>,
    ) {
        let Err((status, Json(body))) = result else {
            panic!("expected retryable invalidation error");
        };
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["database_inactive_committed"], true);
        assert_eq!(body["retryable"], true);
    }
}
