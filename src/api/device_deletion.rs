use crate::{
    api::access::{inventory_error, validation_error, write_access, ApiError},
    audit::{resource_fingerprint, AuditEvent, AuditService},
    auth::jwt::CurrentUser,
    database::{
        Database, DeletionReceipt, DeletionReceiptState, DeviceDeleteOutcome, InventoryError,
    },
    models::device::{validate_device_id, validate_generation},
    peer::{
        DeviceInvalidationCommand, DeviceInvalidationPredicate, DeviceInvalidationSender,
        InvalidationResult,
    },
};
use axum::{
    extract::{connect_info::ConnectInfo, Extension, Path},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use hbb_common::log;
use serde_json::json;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::{
    sync::{mpsc::error::TrySendError, oneshot},
    time::{sleep, timeout},
};

const DELETE_ACK_TIMEOUT: Duration = Duration::from_secs(2);
const DELETE_LEASE_SECONDS: i64 = 5;
const COMPLETED_TTL_SECONDS: i64 = 5 * 60;
const DISPATCH_BATCH_SIZE: i64 = 32;
const DISPATCH_IDLE_DELAY: Duration = Duration::from_millis(500);
const MAX_RETRY_SECONDS: i64 = 60;

pub fn spawn_dispatcher(db: Database, sender: DeviceInvalidationSender) {
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        log::error!("无法启动设备删除 dispatcher：当前线程没有 Tokio runtime");
        return;
    };
    runtime.spawn(run_dispatcher(db, sender));
}

pub async fn run_dispatcher(db: Database, sender: DeviceInvalidationSender) {
    loop {
        if sender.is_closed() {
            return;
        }

        match db
            .claim_due_deletion_receipts(DISPATCH_BATCH_SIZE, DELETE_LEASE_SECONDS)
            .await
        {
            Ok(receipts) => {
                for receipt in receipts {
                    let db = db.clone();
                    let sender = sender.clone();
                    tokio::spawn(async move {
                        let _ = dispatch_claimed_receipt(&db, &sender, receipt).await;
                    });
                }
            }
            Err(InventoryError::Busy) => {}
            Err(error) => {
                log::error!("设备删除 dispatcher 领取 Pending 回执失败: {:?}", error);
            }
        }
        sleep(DISPATCH_IDLE_DELAY).await;
    }
}

pub async fn handle_delete_device(
    Path(device_id): Path<String>,
    Extension(db): Extension<Database>,
    Extension(sender): Extension<DeviceInvalidationSender>,
    Extension(current): Extension<CurrentUser>,
    Extension(audit): Extension<AuditService>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let access = write_access(&current)?;
    let device_id = validate_device_id(device_id).map_err(validation_error)?;
    let generation_header = headers
        .get("x-device-generation")
        .ok_or_else(|| ApiError::new(status_code(428), "X-Device-Generation header is required"))?
        .to_str()
        .map_err(|_| {
            ApiError::bad_request("X-Device-Generation header must contain valid ASCII")
        })?;
    let generation = validate_generation(generation_header).map_err(validation_error)?;

    let outcome = db
        .delete_managed_device(current.id, access.scope, &device_id, &generation)
        .await
        .map_err(delete_database_error)?;
    match outcome {
        DeviceDeleteOutcome::Completed => {
            audit.record(
                AuditEvent::new("device.delete")
                    .actor(current.id)
                    .target("device", resource_fingerprint(&device_id))
                    .ip(peer.ip())
                    .detail(json!({"state": "completed"})),
            );
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        DeviceDeleteOutcome::Pending(receipt) | DeviceDeleteOutcome::DeletedAndPending(receipt) => {
            audit.record(
                AuditEvent::new("device.delete")
                    .actor(current.id)
                    .target("device", resource_fingerprint(&device_id))
                    .ip(peer.ip())
                    .detail(json!({"state": "database_committed_invalidation_pending"})),
            );
            finish_pending_delete(&db, &sender, receipt).await
        }
        DeviceDeleteOutcome::ScopedMiss => Err(ApiError::not_found("device")),
        DeviceDeleteOutcome::GenerationMismatch => Err(ApiError::new(
            StatusCode::PRECONDITION_FAILED,
            "device generation does not match",
        )),
        DeviceDeleteOutcome::CapacityFull => Err(ApiError::with_body(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({
                "error": "device deletion queue is at capacity; retry the request",
                "database_deleted_committed": false,
                "quota_released": false,
                "retryable": true
            }),
        )
        .retry_after(1)),
    }
}

fn delete_database_error(error: InventoryError) -> ApiError {
    match error {
        InventoryError::Busy => ApiError::with_body(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({
                "error": "database is busy; retry the device deletion",
                "database_deleted_committed": false,
                "quota_released": false,
                "retryable": true
            }),
        )
        .retry_after(1),
        error => inventory_error(error, "delete device failed"),
    }
}

async fn finish_pending_delete(
    db: &Database,
    sender: &DeviceInvalidationSender,
    receipt: DeletionReceipt,
) -> Result<Response, ApiError> {
    let claimed = db
        .claim_deletion_receipt(
            receipt.actor_user_id,
            &receipt.device_id,
            &receipt.management_generation,
            DELETE_LEASE_SECONDS,
        )
        .await
        .map_err(|error| {
            log::error!("设备删除回执 claim 失败: {:?}", error);
            committed_pending_error("device deletion is committed, but invalidation claim failed")
        })?;

    let Some(claimed) = claimed else {
        return pending_or_completed_response(db, &receipt).await;
    };
    if dispatch_claimed_receipt(db, sender, claimed).await {
        Ok(StatusCode::NO_CONTENT.into_response())
    } else {
        Err(committed_pending_error(
            "device deletion is committed, but cache invalidation is pending",
        ))
    }
}

async fn pending_or_completed_response(
    db: &Database,
    receipt: &DeletionReceipt,
) -> Result<Response, ApiError> {
    match db
        .get_deletion_receipt(
            receipt.actor_user_id,
            &receipt.device_id,
            &receipt.management_generation,
        )
        .await
    {
        Ok(Some(current)) if current.state == DeletionReceiptState::Completed => {
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        Ok(Some(_)) => Err(committed_pending_error(
            "device deletion is committed and another worker is invalidating the cache",
        )),
        Ok(None) => {
            log::error!(
                "Pending 设备删除回执在 claim 竞争后消失: receipt_id={}",
                receipt.id
            );
            Err(committed_pending_error(
                "device deletion is committed, but its durable receipt is unavailable",
            ))
        }
        Err(error) => {
            log::error!("设备删除回执复查失败: {:?}", error);
            Err(committed_pending_error(
                "device deletion is committed, but receipt lookup failed",
            ))
        }
    }
}

async fn dispatch_claimed_receipt(
    db: &Database,
    sender: &DeviceInvalidationSender,
    receipt: DeletionReceipt,
) -> bool {
    let Some(lease_token) = receipt.lease_token.clone() else {
        log::error!(
            "数据库返回了没有 lease_token 的 claimed 删除回执: receipt_id={}",
            receipt.id
        );
        return false;
    };

    let (ack_tx, ack_rx) = oneshot::channel();
    let command = DeviceInvalidationCommand {
        device_id: receipt.device_id.clone(),
        predicate: DeviceInvalidationPredicate::DeletedGeneration {
            guid: receipt.deleted_guid.clone(),
        },
        ack: ack_tx,
    };
    if let Err(error) = sender.try_send(command) {
        match error {
            TrySendError::Full(_) => {
                log::warn!("设备失效通道已满，保留 Pending 回执 {}", receipt.id);
            }
            TrySendError::Closed(_) => {
                log::warn!("设备失效通道已关闭，保留 Pending 回执 {}", receipt.id);
            }
        }
        fail_claim(db, &receipt, &lease_token).await;
        return false;
    }

    let safely_acknowledged = match timeout(DELETE_ACK_TIMEOUT, ack_rx).await {
        Ok(Ok(Ok(result))) => is_safe_deleted_generation_ack(result),
        Ok(Ok(Err(()))) | Ok(Err(_)) | Err(_) => false,
    };
    if !safely_acknowledged {
        fail_claim(db, &receipt, &lease_token).await;
        return false;
    }

    match db
        .complete_deletion_receipt(receipt.id, &lease_token, COMPLETED_TTL_SECONDS)
        .await
    {
        Ok(true) => true,
        Ok(false) => {
            log::warn!(
                "设备缓存已安全失效，但回执 lease 已变化: receipt_id={}",
                receipt.id
            );
            false
        }
        Err(error) => {
            log::error!(
                "设备缓存已安全失效，但 Completed 回执写入失败: receipt_id={}, error={:?}",
                receipt.id,
                error
            );
            false
        }
    }
}

async fn fail_claim(db: &Database, receipt: &DeletionReceipt, lease_token: &str) {
    let retry_seconds = retry_seconds(receipt.attempt_count);
    match db
        .fail_deletion_receipt(receipt.id, lease_token, retry_seconds)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            log::warn!(
                "设备删除回执 lease 已变化，失败退避未覆盖新 worker: receipt_id={}",
                receipt.id
            );
        }
        Err(error) => {
            log::error!(
                "设备删除回执失败退避写入失败: receipt_id={}, error={:?}",
                receipt.id,
                error
            );
        }
    }
}

fn retry_seconds(attempt_count: i64) -> i64 {
    let exponent = attempt_count.saturating_sub(1).clamp(0, 6) as u32;
    (1_i64 << exponent).min(MAX_RETRY_SECONDS)
}

fn is_safe_deleted_generation_ack(result: InvalidationResult) -> bool {
    matches!(
        result,
        InvalidationResult::Removed
            | InvalidationResult::AlreadyAbsent
            | InvalidationResult::Replaced
    )
}

fn committed_pending_error(message: &str) -> ApiError {
    ApiError::with_body(
        StatusCode::SERVICE_UNAVAILABLE,
        json!({
            "error": message,
            "database_deleted_committed": true,
            "quota_released": true,
            "retryable": true
        }),
    )
    .retry_after(1)
}

fn status_code(value: u16) -> StatusCode {
    StatusCode::from_u16(value).expect("valid HTTP status code")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deletion_retry_backoff_is_bounded() {
        assert_eq!(retry_seconds(1), 1);
        assert_eq!(retry_seconds(2), 2);
        assert_eq!(retry_seconds(7), 60);
        assert_eq!(retry_seconds(i64::MAX), 60);
    }

    #[test]
    fn only_terminal_deleted_generation_results_are_safe_acks() {
        assert!(is_safe_deleted_generation_ack(InvalidationResult::Removed));
        assert!(is_safe_deleted_generation_ack(
            InvalidationResult::AlreadyAbsent
        ));
        assert!(is_safe_deleted_generation_ack(InvalidationResult::Replaced));
        assert!(!is_safe_deleted_generation_ack(
            InvalidationResult::GenerationStillPresent
        ));
        assert!(!is_safe_deleted_generation_ack(
            InvalidationResult::NoLongerInactive
        ));
    }
}
