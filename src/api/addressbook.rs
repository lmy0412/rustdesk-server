use crate::{
    api::{
        access::{ApiError, LimitedJson},
        middleware::ApiProtectionState,
    },
    audit::{AuditEvent, AuditService},
    auth::jwt::CurrentUser,
    database::{AddressBookError, Database},
    models::addressbook::{
        AddressBookDeltaPage, AddressBookFullPage, PendingSharePage, SafeDeviceDto, ShareDto,
        ShareMutation, SharePermission,
    },
};
use axum::{
    extract::{
        connect_info::ConnectInfo,
        rejection::{PathRejection, QueryRejection},
        Extension, Path, Query,
    },
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use data_encoding::HEXLOWER;
use hbb_common::log;
use serde_derive::{Deserialize, Serialize};
use serde_json::json;
use sodiumoxide::crypto::hash::sha256;
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddressBookQuery {
    page: Option<u64>,
    page_size: Option<u64>,
    sync_ver: Option<i64>,
    ab_ver: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingQuery {
    after_id: Option<i64>,
    page_size: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareRequest {
    to_username: String,
    permission: SharePermission,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelQuery {
    to_username: String,
}

#[derive(Debug, Serialize)]
pub struct LegacyAddressBookResponse {
    licensed_devices: i32,
    writable: bool,
    ab_ver: i64,
    data: String,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum AddressBookResponse {
    Legacy(LegacyAddressBookResponse),
    Full(AddressBookFullPage),
    Delta(AddressBookDeltaPage),
}

#[derive(Debug, Serialize)]
struct LegacyBook {
    tags: Vec<String>,
    peers: Vec<LegacyPeer>,
    tag_colors: &'static str,
}

#[derive(Debug, Serialize)]
struct LegacyPeer {
    id: String,
    hostname: String,
    platform: String,
    alias: String,
    tags: Vec<String>,
    username: String,
    hash: String,
}

pub async fn handle_get_address_book(
    Extension(db): Extension<Database>,
    Extension(current): Extension<CurrentUser>,
    query: Result<Query<AddressBookQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query.map_err(|_| ApiError::bad_request("invalid address-book query"))?;
    ensure_read_role(&current)?;

    if let Some(ab_ver) = query.ab_ver {
        if query.page.is_some() || query.sync_ver.is_some() {
            return Err(ApiError::bad_request(
                "ab_ver cannot be combined with page or sync_ver",
            ));
        }
        if ab_ver < 0 {
            return Err(ApiError::bad_request("ab_ver must be non-negative"));
        }
        let page_size = query.page_size.unwrap_or(50);
        let page_size = i64::try_from(page_size)
            .map_err(|_| ApiError::bad_request("page_size is out of range"))?;
        let delta = db
            .get_address_book_delta(current.id, ab_ver, page_size)
            .await
            .map_err(map_address_book_error)?;
        let mut response = Json(AddressBookResponse::Delta(delta)).into_response();
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=utf-8"),
        );
        return Ok(response);
    }

    let is_v2 = query.page.is_some() || query.page_size.is_some() || query.sync_ver.is_some();
    if is_v2 {
        if query.sync_ver.is_some_and(|value| value < 0) {
            return Err(ApiError::bad_request("sync_ver must be non-negative"));
        }
        let full = db
            .get_address_book_full(
                current.id,
                query.page.unwrap_or(1),
                query.page_size.unwrap_or(50),
                query.sync_ver,
            )
            .await
            .map_err(map_address_book_error)?;
        return Ok(Json(AddressBookResponse::Full(full)).into_response());
    }

    let snapshot = db
        .get_address_book_snapshot(current.id)
        .await
        .map_err(map_address_book_error)?;
    let licensed_devices = i32::try_from(snapshot.items.len())
        .map_err(|_| ApiError::internal("address-book result is too large"))?;
    let peers = snapshot
        .items
        .into_iter()
        .map(legacy_peer)
        .collect::<Vec<_>>();
    let data = serde_json::to_string(&LegacyBook {
        tags: Vec::new(),
        peers,
        tag_colors: "{}",
    })
    .map_err(|_| ApiError::internal("address-book serialization failed"))?;
    Ok(Json(AddressBookResponse::Legacy(LegacyAddressBookResponse {
        licensed_devices,
        writable: false,
        ab_ver: snapshot.ab_ver,
        data,
    }))
    .into_response())
}

pub async fn handle_pending_shares(
    Extension(db): Extension<Database>,
    Extension(current): Extension<CurrentUser>,
    query: Result<Query<PendingQuery>, QueryRejection>,
) -> Result<Json<PendingSharePage>, ApiError> {
    let Query(query) = query.map_err(|_| ApiError::bad_request("invalid pending query"))?;
    ensure_read_role(&current)?;
    let after_id = query.after_id.unwrap_or(0);
    if after_id < 0 {
        return Err(ApiError::bad_request("after_id must be non-negative"));
    }
    let page = db
        .get_pending_shares(current.id, after_id, query.page_size.unwrap_or(50))
        .await
        .map_err(map_address_book_error)?;
    Ok(Json(page))
}

pub async fn handle_share_device(
    Extension(db): Extension<Database>,
    Extension(current): Extension<CurrentUser>,
    Extension(protection): Extension<ApiProtectionState>,
    Extension(audit): Extension<AuditService>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    path: Result<Path<String>, PathRejection>,
    payload: Result<LimitedJson<ShareRequest>, ApiError>,
) -> Result<(StatusCode, Json<ShareDto>), ApiError> {
    ensure_write_role(&current)?;
    let Path(device_id) =
        path.map_err(|_| ApiError::bad_request("invalid address-book resource path"))?;
    let LimitedJson(payload) = payload?;
    protection.check_address_book_actor(current.id)?;
    let resource_hash = resource_hash(&format!("{device_id}\n{}", payload.to_username));
    let result = db
        .share_device(
            current.id,
            &device_id,
            &payload.to_username,
            payload.permission,
        )
        .await;
    audit_result(
        &audit,
        current.id,
        peer.ip(),
        "share",
        &resource_hash,
        &result,
    );
    let ShareMutation { created, share } = result.map_err(map_address_book_error)?;
    Ok((
        if created {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        Json(share),
    ))
}

pub async fn handle_cancel_share(
    Extension(db): Extension<Database>,
    Extension(current): Extension<CurrentUser>,
    Extension(protection): Extension<ApiProtectionState>,
    Extension(audit): Extension<AuditService>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    path: Result<Path<String>, PathRejection>,
    query: Result<Query<CancelQuery>, QueryRejection>,
) -> Result<StatusCode, ApiError> {
    ensure_write_role(&current)?;
    let Path(device_id) =
        path.map_err(|_| ApiError::bad_request("invalid address-book resource path"))?;
    let Query(query) = query.map_err(|_| ApiError::bad_request("invalid cancel query"))?;
    protection.check_address_book_actor(current.id)?;
    let resource_hash = resource_hash(&format!("{device_id}\n{}", query.to_username));
    let result = db
        .cancel_device_share(current.id, &device_id, &query.to_username)
        .await;
    audit_result(
        &audit,
        current.id,
        peer.ip(),
        "cancel",
        &resource_hash,
        &result,
    );
    result.map_err(map_address_book_error)?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn handle_accept_share(
    Extension(db): Extension<Database>,
    Extension(current): Extension<CurrentUser>,
    Extension(protection): Extension<ApiProtectionState>,
    Extension(audit): Extension<AuditService>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    path: Result<Path<i64>, PathRejection>,
) -> Result<Json<ShareDto>, ApiError> {
    ensure_write_role(&current)?;
    let Path(share_id) =
        path.map_err(|_| ApiError::bad_request("invalid address-book resource path"))?;
    protection.check_address_book_actor(current.id)?;
    let resource_hash = resource_hash(&share_id.to_string());
    let result = db.accept_device_share(current.id, share_id).await;
    audit_result(
        &audit,
        current.id,
        peer.ip(),
        "accept",
        &resource_hash,
        &result,
    );
    Ok(Json(result.map_err(map_address_book_error)?))
}

pub async fn handle_reject_share(
    Extension(db): Extension<Database>,
    Extension(current): Extension<CurrentUser>,
    Extension(protection): Extension<ApiProtectionState>,
    Extension(audit): Extension<AuditService>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    path: Result<Path<i64>, PathRejection>,
) -> Result<Json<ShareDto>, ApiError> {
    ensure_write_role(&current)?;
    let Path(share_id) =
        path.map_err(|_| ApiError::bad_request("invalid address-book resource path"))?;
    protection.check_address_book_actor(current.id)?;
    let resource_hash = resource_hash(&share_id.to_string());
    let result = db.reject_device_share(current.id, share_id).await;
    audit_result(
        &audit,
        current.id,
        peer.ip(),
        "reject",
        &resource_hash,
        &result,
    );
    Ok(Json(result.map_err(map_address_book_error)?))
}

fn legacy_peer(item: SafeDeviceDto) -> LegacyPeer {
    LegacyPeer {
        id: item.device_id,
        hostname: item.hostname,
        platform: item.os,
        alias: item.alias,
        tags: Vec::new(),
        username: item.shared_by_username.unwrap_or_default(),
        hash: String::new(),
    }
}

fn ensure_read_role(current: &CurrentUser) -> Result<(), ApiError> {
    match current.role.as_str() {
        "admin" | "user" | "viewer" => Ok(()),
        _ => Err(ApiError::forbidden("unknown role is not permitted")),
    }
}

fn ensure_write_role(current: &CurrentUser) -> Result<(), ApiError> {
    match current.role.as_str() {
        "admin" | "user" => Ok(()),
        "viewer" => Err(ApiError::forbidden("viewer role is read-only")),
        _ => Err(ApiError::forbidden("unknown role is not permitted")),
    }
}

pub(crate) fn map_address_book_error(error: AddressBookError) -> ApiError {
    match error {
        AddressBookError::InvalidInput(_) | AddressBookError::TooLarge => {
            ApiError::bad_request("invalid address-book request")
        }
        AddressBookError::Forbidden => ApiError::forbidden("address-book operation not permitted"),
        AddressBookError::NotFound => ApiError::new(StatusCode::NOT_FOUND, "resource not found"),
        AddressBookError::Conflict(_) => {
            ApiError::conflict("address-book state transition conflicts with current state")
        }
        AddressBookError::Busy => {
            ApiError::service_unavailable("database is busy; retry the request").retry_after(1)
        }
        AddressBookError::Integrity(detail) => {
            log::error!("address-book integrity check failed: {}", detail);
            ApiError::internal("address-book integrity check failed")
        }
        AddressBookError::Internal(detail) => {
            log::error!("address-book database operation failed: {}", detail);
            ApiError::internal("address-book database operation failed")
        }
    }
}

fn resource_hash(resource: &str) -> String {
    let digest = sha256::hash(resource.as_bytes());
    HEXLOWER.encode(&digest.0[..16])
}

fn audit_result<T>(
    audit: &AuditService,
    actor_id: i64,
    peer_ip: IpAddr,
    action: &'static str,
    resource_hash: &str,
    result: &Result<T, AddressBookError>,
) {
    let result_class = match result {
        Ok(_) => "success",
        Err(AddressBookError::InvalidInput(_)) => "invalid",
        Err(AddressBookError::Forbidden) => "forbidden",
        Err(AddressBookError::NotFound) => "not_found",
        Err(AddressBookError::Conflict(_)) => "conflict",
        Err(AddressBookError::TooLarge) => "too_large",
        Err(AddressBookError::Busy) => "busy",
        Err(AddressBookError::Integrity(_)) => "integrity_error",
        Err(AddressBookError::Internal(_)) => "internal_error",
    };
    log::info!(
        "address_book_audit actor={} action={} result={} resource_hash={}",
        actor_id,
        action,
        result_class,
        resource_hash
    );
    audit.record(
        AuditEvent::new(format!("address_book.{action}"))
            .actor(actor_id)
            .target("address_book_share", resource_hash.to_string())
            .ip(peer_ip)
            .detail(json!({"result": result_class})),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_hash_does_not_contain_the_resource() {
        let hash = resource_hash("device-secret\nusername-secret");
        assert_eq!(hash.len(), 32);
        assert!(!hash.contains("device-secret"));
        assert!(!hash.contains("username-secret"));
    }
}
