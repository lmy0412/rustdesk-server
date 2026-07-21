use crate::{auth::jwt::CurrentUser, database::Database};
use axum::{extract::Extension, http::StatusCode, Json};
use once_cell::sync::Lazy;
use serde_derive::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::Mutex;

type ApiError = (StatusCode, Json<Value>);
static LICENSE_UPLOAD_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

#[derive(Debug, Deserialize)]
pub struct LicenseUploadRequest {
    pub license_key: String,
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
    pub max_users: u32,
    pub current_users: u32,
    pub device_usage_pct: f64,
    pub user_usage_pct: f64,
}

pub async fn handle_license_upload(
    Extension(db): Extension<Database>,
    Extension(current): Extension<CurrentUser>,
    Json(payload): Json<LicenseUploadRequest>,
) -> Result<Json<LicenseUploadResponse>, ApiError> {
    require_admin(&current)?;
    let license = crate::license::parse_license_key(&payload.license_key)
        .map_err(|err| bad_request(error_message(err)))?;
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

    let warning = if crate::license::is_license_expired(&license) {
        Some("license has expired".to_string())
    } else {
        None
    };

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
    let current_devices = db
        .count_active_devices()
        .await
        .map_err(|_| internal_error("device usage lookup failed"))?;
    let current_users = db
        .count_users()
        .await
        .map_err(|_| internal_error("user usage lookup failed"))?
        .max(0) as u32;

    Ok(Json(LicenseUsageResponse {
        max_devices,
        current_devices,
        max_users,
        current_users,
        device_usage_pct: pct(current_devices, max_devices),
        user_usage_pct: pct(current_users, max_users),
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
