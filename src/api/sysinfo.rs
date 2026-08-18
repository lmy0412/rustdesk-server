use crate::{
    api::{
        access::ApiError, addressbook::map_address_book_error, client_auth::validate_identity_pair,
        middleware::ApiProtectionState,
    },
    auth::jwt::CurrentUser,
    database::Database,
    models::{addressbook::AddressBookDeltaPage, user::MAX_SAFE_INTEGER},
};
use axum::{
    body::Bytes,
    extract::Extension,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_derive::{Deserialize, Serialize};
use serde_json::Value;

pub const SYSINFO_UPDATED: &str = "SYSINFO_UPDATED";
pub const ID_NOT_FOUND: &str = "ID_NOT_FOUND";

#[derive(Debug, Deserialize)]
struct SysinfoRequest {
    id: String,
    uuid: String,
    hostname: Option<String>,
    os: Option<String>,
    ab_ver: Option<i64>,
    address_book_json: Option<bool>,
}

#[derive(Debug, Serialize)]
struct SysinfoAddressBookResponse {
    status: &'static str,
    address_book: AddressBookDeltaPage,
}

pub async fn handle_sysinfo(
    Extension(db): Extension<Database>,
    Extension(protection): Extension<ApiProtectionState>,
    current: Option<Extension<CurrentUser>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    require_json_or_text(&headers)?;
    let payload = parse_sysinfo_request(&body)?;
    validate_sysinfo_request(&payload)?;
    validate_auth_cursor_matrix(&current, payload.ab_ver, "sysinfo")?;
    let uuid =
        base64::decode(&payload.uuid).map_err(|_| ApiError::bad_request("invalid device uuid"))?;

    let Some(snapshot) = db
        .match_sysinfo_device(&payload.id, &uuid)
        .await
        .map_err(map_address_book_error)?
    else {
        return Ok(plain_text(StatusCode::OK, ID_NOT_FOUND));
    };
    protection.check_device(&snapshot.management_generation)?;

    let Some(Extension(current)) = current else {
        return Ok(plain_text(StatusCode::OK, SYSINFO_UPDATED));
    };
    let requested_ab_ver = payload
        .ab_ver
        .ok_or_else(|| ApiError::bad_request("authenticated sysinfo requires ab_ver"))?;

    let (current_version, device_changed, cursor_was_future) =
        match (payload.hostname.as_deref(), payload.os.as_deref()) {
            (hostname, os)
                if (hostname.is_some() || os.is_some())
                    && snapshot.owner_user_id == Some(current.id) =>
            {
                let update = db
                    .update_owned_device_sysinfo(
                        current.id,
                        &payload.id,
                        &uuid,
                        &snapshot.management_generation,
                        hostname,
                        os,
                    )
                    .await
                    .map_err(map_address_book_error)?;
                if !update.matched {
                    return Ok(plain_text(StatusCode::OK, ID_NOT_FOUND));
                }
                (
                    update.address_book_version,
                    update.changed,
                    // 本次 sysinfo 写入可能恰好把版本推进到 future 游标，必须相对写入前版本判定。
                    requested_ab_ver > update.previous_address_book_version,
                )
            }
            _ => {
                let version = db
                    .get_address_book_version(current.id)
                    .await
                    .map_err(map_address_book_error)?
                    .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "invalid token user"))?;
                (version, false, false)
            }
        };

    if requested_ab_ver == current_version && !device_changed {
        return Ok(StatusCode::NO_CONTENT.into_response());
    }
    if payload.address_book_json == Some(true) {
        let address_book = db
            .get_address_book_delta_with_reset(current.id, requested_ab_ver, 50, cursor_was_future)
            .await
            .map_err(map_address_book_error)?;
        return Ok(Json(SysinfoAddressBookResponse {
            status: SYSINFO_UPDATED,
            address_book,
        })
        .into_response());
    }
    Ok(plain_text(StatusCode::OK, SYSINFO_UPDATED))
}

pub async fn handle_heartbeat(
    Extension(db): Extension<Database>,
    Extension(protection): Extension<ApiProtectionState>,
    current: Option<Extension<CurrentUser>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    require_json_or_text(&headers)?;
    let payload = parse_sysinfo_request(&body)?;
    validate_sysinfo_request(&payload)?;
    validate_auth_cursor_matrix(&current, payload.ab_ver, "heartbeat")?;
    let uuid =
        base64::decode(&payload.uuid).map_err(|_| ApiError::bad_request("invalid device uuid"))?;
    let Some(snapshot) = db
        .match_sysinfo_device(&payload.id, &uuid)
        .await
        .map_err(map_address_book_error)?
    else {
        return Ok(plain_text(StatusCode::OK, ID_NOT_FOUND));
    };
    protection.check_device(&snapshot.management_generation)?;

    let Some(Extension(current)) = current else {
        return Ok(Json(serde_json::json!({ "sysinfo": true })).into_response());
    };
    let requested_ab_ver = payload
        .ab_ver
        .ok_or_else(|| ApiError::bad_request("authenticated heartbeat requires ab_ver"))?;
    let current_version = db
        .get_address_book_version(current.id)
        .await
        .map_err(map_address_book_error)?
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "invalid token user"))?;
    if requested_ab_ver == current_version {
        Ok(Json(serde_json::json!({})).into_response())
    } else {
        Ok(Json(serde_json::json!({ "sysinfo": true })).into_response())
    }
}

fn validate_auth_cursor_matrix(
    current: &Option<Extension<CurrentUser>>,
    ab_ver: Option<i64>,
    endpoint: &str,
) -> Result<(), ApiError> {
    match (current.is_some(), ab_ver.is_some()) {
        (false, true) => Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "authorization is required when ab_ver is present",
        )),
        (true, false) => Err(ApiError::bad_request(format!(
            "authenticated {endpoint} requires ab_ver"
        ))),
        _ => Ok(()),
    }
}

fn parse_sysinfo_request(body: &[u8]) -> Result<SysinfoRequest, ApiError> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|_| ApiError::bad_request("invalid JSON request body"))?;
    let object = value
        .as_object()
        .ok_or_else(|| ApiError::bad_request("invalid JSON request body"))?;
    for name in ["hostname", "os", "ab_ver", "address_book_json"] {
        if object.get(name).is_some_and(Value::is_null) {
            return Err(ApiError::bad_request(format!(
                "{name} must not be null when present"
            )));
        }
    }
    serde_json::from_value(value).map_err(|_| ApiError::bad_request("invalid JSON request body"))
}

fn validate_sysinfo_request(payload: &SysinfoRequest) -> Result<(), ApiError> {
    validate_identity_pair(Some(&payload.id), Some(&payload.uuid))?;
    if payload
        .ab_ver
        .is_some_and(|value| !(0..=MAX_SAFE_INTEGER).contains(&value))
    {
        return Err(ApiError::bad_request(
            "ab_ver must be a non-negative JavaScript safe integer",
        ));
    }
    if let Some(hostname) = payload.hostname.as_deref() {
        validate_sysinfo_text(hostname, 200, "hostname")?;
    }
    if let Some(os) = payload.os.as_deref() {
        validate_sysinfo_text(os, 100, "os")?;
    }
    Ok(())
}

fn validate_sysinfo_text(value: &str, max_bytes: usize, field: &str) -> Result<(), ApiError> {
    if value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(ApiError::bad_request(format!("invalid {field}")));
    }
    Ok(())
}

pub(crate) fn require_json_or_text(headers: &HeaderMap) -> Result<(), ApiError> {
    let value = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "Content-Type must be application/json or text/plain",
            )
        })?;
    let mime = value.split(';').next().unwrap_or_default().trim();
    if mime.eq_ignore_ascii_case("application/json") || mime.eq_ignore_ascii_case("text/plain") {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Content-Type must be application/json or text/plain",
        ))
    }
}

pub(crate) fn plain_text(status: StatusCode, body: impl Into<String>) -> Response {
    let mut response = (status, body.into()).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_control_characters_and_oversized_text() {
        assert!(validate_sysinfo_text("Windows", 100, "os").is_ok());
        assert!(validate_sysinfo_text("bad\nvalue", 100, "os").is_err());
        assert!(validate_sysinfo_text(&"a".repeat(201), 200, "hostname").is_err());
    }

    #[test]
    fn auth_cursor_matrix_is_checked_before_device_lookup() {
        let current = Some(Extension(CurrentUser {
            id: 1,
            username: "user".to_owned(),
            role: "user".to_owned(),
        }));
        assert!(validate_auth_cursor_matrix(&None, Some(0), "sysinfo").is_err());
        assert!(validate_auth_cursor_matrix(&current, None, "sysinfo").is_err());
        assert!(validate_auth_cursor_matrix(&None, None, "sysinfo").is_ok());
        assert!(validate_auth_cursor_matrix(&current, Some(0), "sysinfo").is_ok());
    }

    #[test]
    fn address_book_version_requires_javascript_safe_integer() {
        let request = |ab_ver| SysinfoRequest {
            id: "device".to_owned(),
            uuid: base64::encode("uuid"),
            hostname: None,
            os: None,
            ab_ver,
            address_book_json: None,
        };
        assert!(validate_sysinfo_request(&request(Some(MAX_SAFE_INTEGER))).is_ok());
        assert!(validate_sysinfo_request(&request(Some(MAX_SAFE_INTEGER + 1))).is_err());
        assert!(validate_sysinfo_request(&request(Some(-1))).is_err());
    }

    #[test]
    fn sysinfo_rejects_null_optional_fields() {
        let uuid = base64::encode("uuid");
        for field in [
            r#""ab_ver":null"#,
            r#""hostname":null"#,
            r#""os":null"#,
            r#""address_book_json":null"#,
        ] {
            let body = format!(r#"{{"id":"device","uuid":"{uuid}",{field}}}"#);
            assert!(parse_sysinfo_request(body.as_bytes()).is_err(), "{field}");
        }
    }
}
