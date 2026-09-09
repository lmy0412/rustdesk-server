use crate::{
    api::access::ApiError,
    audit::{AuditLogFilter, AuditLogItem},
    auth::jwt::CurrentUser,
    database::Database,
    models::user::{validate_safe_user_id, MAX_SAFE_INTEGER},
};
use axum::{
    extract::{Extension, Query},
    Json,
};
use chrono::{DateTime, NaiveDateTime};
use serde_derive::{Deserialize, Serialize};

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditLogQuery {
    action: Option<String>,
    target_type: Option<String>,
    user_id: Option<i64>,
    from: Option<String>,
    to: Option<String>,
    page: Option<i64>,
    page_size: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct AuditLogResponse {
    items: Vec<AuditLogItem>,
    total: i64,
    page: i64,
    page_size: i64,
}

pub async fn handle_list_audit_logs(
    Extension(db): Extension<Database>,
    Extension(current): Extension<CurrentUser>,
    Query(query): Query<AuditLogQuery>,
) -> Result<Json<AuditLogResponse>, ApiError> {
    require_admin(&current)?;
    let page = query.page.unwrap_or(1);
    let page_size = query.page_size.unwrap_or(50);
    if page < 1 {
        return Err(ApiError::bad_request("page must be positive"));
    }
    if !(1..=200).contains(&page_size) {
        return Err(ApiError::bad_request("page_size must be within 1..=200"));
    }
    if page
        .checked_sub(1)
        .and_then(|page| page.checked_mul(page_size))
        .is_none()
    {
        return Err(ApiError::bad_request("audit pagination is out of range"));
    }
    validate_filter(&query.action, 100, "action")?;
    validate_filter(&query.target_type, 50, "target_type")?;
    if let Some(user_id) = query.user_id {
        validate_safe_user_id(user_id).map_err(ApiError::bad_request)?;
    }
    let from = parse_time(query.from.as_deref(), "from")?;
    let to = parse_time(query.to.as_deref(), "to")?;
    if from.zip(to).is_some_and(|(from, to)| from > to) {
        return Err(ApiError::bad_request("from must not be later than to"));
    }
    let filter = AuditLogFilter {
        action: query.action,
        target_type: query.target_type,
        user_id: query.user_id,
        from,
        to,
        page,
        page_size,
    };
    let (rows, total) = db
        .list_audit_logs(&filter)
        .await
        .map_err(|_| ApiError::internal("list audit logs failed"))?;
    if !(0..=MAX_SAFE_INTEGER).contains(&total)
        || rows
            .iter()
            .any(|row| !(1..=MAX_SAFE_INTEGER).contains(&row.id))
    {
        return Err(ApiError::internal(
            "audit log result is outside the JSON safe range",
        ));
    }
    Ok(Json(AuditLogResponse {
        items: rows.into_iter().map(AuditLogItem::from).collect(),
        total,
        page,
        page_size,
    }))
}

fn require_admin(current: &CurrentUser) -> Result<(), ApiError> {
    if current.role == "admin" {
        Ok(())
    } else {
        Err(ApiError::forbidden("admin role required"))
    }
}

fn validate_filter(value: &Option<String>, max: usize, name: &str) -> Result<(), ApiError> {
    if let Some(value) = value {
        if value.is_empty() || value.chars().count() > max || value.chars().any(char::is_control) {
            return Err(ApiError::bad_request(format!("invalid {name} filter")));
        }
    }
    Ok(())
}

fn parse_time(value: Option<&str>, name: &str) -> Result<Option<NaiveDateTime>, ApiError> {
    value
        .map(|value| {
            DateTime::parse_from_rfc3339(value)
                .map(|value| value.naive_utc())
                .map_err(|_| ApiError::bad_request(format!("{name} must be RFC 3339")))
        })
        .transpose()
}
