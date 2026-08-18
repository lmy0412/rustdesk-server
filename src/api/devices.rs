use crate::{
    api::{
        access::{
            inventory_error, read_access, validation_error, write_access, ApiError, LimitedJson,
        },
        device_deletion,
    },
    audit::{resource_fingerprint, AuditEvent, AuditService},
    auth::jwt::CurrentUser,
    database::{Database, DeviceListFilter, DeviceUpdate, ManagedDevice},
    models::device::{
        validate_device_id, BatchTagRequest, BatchTagResponse, DeviceListQuery, DeviceListResponse,
        DeviceResponse, UpdateDeviceRequest,
    },
};
use axum::{
    extract::{connect_info::ConnectInfo, Extension, Path, Query},
    Json,
};
use serde_json::json;
use std::net::SocketAddr;

pub use device_deletion::handle_delete_device;

pub async fn handle_list_devices(
    Extension(db): Extension<Database>,
    Extension(current): Extension<CurrentUser>,
    Query(query): Query<DeviceListQuery>,
) -> Result<Json<DeviceListResponse>, ApiError> {
    let query = query.validate().map_err(validation_error)?;
    let scope = read_access(&current)?.scope;
    let (devices, total) = db
        .list_managed_devices(
            scope,
            &DeviceListFilter {
                group_id: query.group_id,
                tag: query.tag,
                status: query.status,
                query: query.q,
                page: query.page,
                page_size: query.page_size,
            },
        )
        .await
        .map_err(|error| inventory_error(error, "list devices failed"))?;
    Ok(Json(DeviceListResponse {
        items: devices.into_iter().map(device_response).collect(),
        page: query.page,
        page_size: query.page_size,
        total,
    }))
}

pub async fn handle_get_device(
    Extension(db): Extension<Database>,
    Extension(current): Extension<CurrentUser>,
    Path(device_id): Path<String>,
) -> Result<Json<DeviceResponse>, ApiError> {
    let device_id = validate_device_id(device_id).map_err(validation_error)?;
    let scope = read_access(&current)?.scope;
    let device = db
        .get_managed_device(scope, &device_id)
        .await
        .map_err(|error| inventory_error(error, "get device failed"))?
        .ok_or_else(|| ApiError::not_found("device"))?;
    Ok(Json(device_response(device)))
}

pub async fn handle_update_device(
    Extension(db): Extension<Database>,
    Extension(current): Extension<CurrentUser>,
    Extension(audit): Extension<AuditService>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    Path(device_id): Path<String>,
    LimitedJson(payload): LimitedJson<UpdateDeviceRequest>,
) -> Result<Json<DeviceResponse>, ApiError> {
    let device_id = validate_device_id(device_id).map_err(validation_error)?;
    let payload = payload.validate().map_err(validation_error)?;
    let access = write_access(&current)?;
    if payload.owner_field_was_set && !access.is_admin() {
        return Err(ApiError::forbidden("only admin can update owner_user_id"));
    }
    let device = db
        .update_managed_device(
            access.scope,
            &device_id,
            &DeviceUpdate {
                alias: payload.alias,
                note: payload.note,
                group_id: payload.group_id,
                owner_user_id: payload.owner_user_id,
            },
        )
        .await
        .map_err(|error| inventory_error(error, "update device failed"))?
        .ok_or_else(|| ApiError::not_found("device"))?;
    audit.record(
        AuditEvent::new("device.update")
            .actor(current.id)
            .target("device", resource_fingerprint(&device_id))
            .ip(peer.ip())
            .detail(json!({"group_id": device.group_id, "owner_user_id": device.owner_user_id})),
    );
    Ok(Json(device_response(device)))
}

pub async fn handle_batch_tag(
    Extension(db): Extension<Database>,
    Extension(current): Extension<CurrentUser>,
    Extension(audit): Extension<AuditService>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    LimitedJson(payload): LimitedJson<BatchTagRequest>,
) -> Result<Json<BatchTagResponse>, ApiError> {
    let payload = payload.validate().map_err(validation_error)?;
    let scope = write_access(&current)?.scope;
    let outcome = db
        .batch_update_device_tags(
            scope,
            &payload.device_ids,
            &payload.add_tags,
            &payload.remove_tags,
        )
        .await
        .map_err(|error| inventory_error(error, "batch update device tags failed"))?;
    let batch_fingerprint = resource_fingerprint(&payload.device_ids.join("\n"));
    audit.record(AuditEvent::new("device.tags.update").actor(current.id).target("device_batch", batch_fingerprint).ip(peer.ip()).detail(json!({"matched_devices": outcome.devices, "added_relations": outcome.added, "removed_relations": outcome.removed})));
    Ok(Json(BatchTagResponse {
        matched_devices: outcome.devices,
        added_relations: outcome.added,
        removed_relations: outcome.removed,
    }))
}

fn device_response(device: ManagedDevice) -> DeviceResponse {
    DeviceResponse {
        device_id: device.device_id,
        owner_user_id: device.owner_user_id,
        group_id: device.group_id,
        alias: device.alias,
        hostname: device.device_name,
        os: device.os,
        note: device.note,
        status: device.status,
        generation: device.management_generation,
        tags: device.tags,
        last_seen: device.last_seen,
        created_at: device.created_at,
        updated_at: device.updated_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        api::{admin_init::hash_password, build_router},
        auth::AuthState,
        config::OidcConfig,
        database::{DeletionReceiptState, OwnerScope},
        peer::{
            DeviceInvalidationPredicate, InvalidationResult, DEVICE_INVALIDATION_CHANNEL_CAPACITY,
        },
    };
    use axum::{
        body::{Body, HttpBody},
        http::{header, Request, StatusCode},
        response::Response,
        Router,
    };
    use serde_json::{json, Value};
    use sqlx::{Connection, Executor, SqliteConnection};
    use std::{
        collections::BTreeSet,
        time::{SystemTime, UNIX_EPOCH},
    };
    use tokio::sync::mpsc;
    use tower::ServiceExt;

    #[test]
    fn inventory_acceptance_and_rbac_work_end_to_end() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let path = temp_db_path("inventory-acceptance");
            let db = Database::new(&path).await.unwrap();
            let user_a = create_user(&db, "user-a", "user").await;
            let user_b = create_user(&db, "user-b", "user").await;
            create_user(&db, "viewer", "viewer").await;
            create_user(&db, "inventory-admin", "admin").await;
            insert_owned_device(&db, "device-a1", user_a).await;
            insert_owned_device(&db, "device-a2", user_a).await;
            insert_owned_device(&db, "device-a3", user_a).await;
            insert_owned_device(&db, "device-b1", user_b).await;

            let (sender, receiver) = mpsc::channel(DEVICE_INVALIDATION_CHANNEL_CAPACITY);
            let app = test_router(db.clone(), sender);
            let user_a_token = login(&app, "user-a").await;
            let user_b_token = login(&app, "user-b").await;
            let viewer_token = login(&app, "viewer").await;
            let admin_token = login(&app, "inventory-admin").await;

            let company = post_json(
                &app,
                "/api/groups",
                &user_a_token,
                json!({ "name": "公司" }),
            )
            .await;
            assert_eq!(company.status(), StatusCode::CREATED);
            let company_id = response_json(company).await["id"].as_i64().unwrap();
            let department = post_json(
                &app,
                "/api/groups",
                &user_a_token,
                json!({ "name": "技术部", "parent_group_id": company_id }),
            )
            .await;
            assert_eq!(department.status(), StatusCode::CREATED);
            let department_id = response_json(department).await["id"].as_i64().unwrap();
            let backend = post_json(
                &app,
                "/api/groups",
                &user_a_token,
                json!({ "name": "后端组", "parent_group_id": department_id }),
            )
            .await;
            assert_eq!(backend.status(), StatusCode::CREATED);

            let other_owner_group = post_json(
                &app,
                "/api/groups",
                &user_b_token,
                json!({ "name": "其他用户组" }),
            )
            .await;
            assert_eq!(other_owner_group.status(), StatusCode::CREATED);
            let other_owner_group_id = response_json(other_owner_group).await["id"]
                .as_i64()
                .unwrap();

            let hidden_parent = post_json(
                &app,
                "/api/groups",
                &user_a_token,
                json!({ "name": "不可见父组", "parent_group_id": other_owner_group_id }),
            )
            .await;
            assert_eq!(hidden_parent.status(), StatusCode::NOT_FOUND);
            let admin_cross_owner_create = post_json(
                &app,
                "/api/groups",
                &admin_token,
                json!({
                    "name": "跨归属子组",
                    "owner_user_id": user_a,
                    "parent_group_id": other_owner_group_id
                }),
            )
            .await;
            assert_eq!(admin_cross_owner_create.status(), StatusCode::CONFLICT);
            let admin_cross_owner_update = put_json(
                &app,
                &format!("/api/groups/{company_id}"),
                &admin_token,
                json!({ "parent_group_id": other_owner_group_id }),
            )
            .await;
            assert_eq!(admin_cross_owner_update.status(), StatusCode::CONFLICT);
            let admin_cross_owner_device = put_json(
                &app,
                "/api/devices/device-a1",
                &admin_token,
                json!({ "group_id": other_owner_group_id }),
            )
            .await;
            assert_eq!(admin_cross_owner_device.status(), StatusCode::CONFLICT);

            let groups = get(&app, "/api/groups", &user_a_token).await;
            assert_eq!(groups.status(), StatusCode::OK);
            let groups = response_json(groups).await;
            assert_eq!(groups["items"][0]["name"], "公司");
            assert_eq!(groups["items"][0]["children"][0]["name"], "技术部");
            assert_eq!(
                groups["items"][0]["children"][0]["children"][0]["name"],
                "后端组"
            );
            let updated_company = put_json(
                &app,
                &format!("/api/groups/{company_id}"),
                &user_a_token,
                json!({ "name": "公司总部" }),
            )
            .await;
            assert_eq!(updated_company.status(), StatusCode::OK);
            let updated_company = response_json(updated_company).await;
            assert_eq!(updated_company["name"], "公司总部");
            assert_eq!(updated_company["children"][0]["name"], "技术部");
            assert_eq!(
                updated_company["children"][0]["children"][0]["name"],
                "后端组"
            );

            let hidden_group = get(&app, &format!("/api/groups/{company_id}"), &user_b_token).await;
            assert_eq!(hidden_group.status(), StatusCode::NOT_FOUND);

            let grouped = post_json(
                &app,
                &format!("/api/groups/{department_id}/devices"),
                &user_a_token,
                json!({ "device_ids": ["device-a3"] }),
            )
            .await;
            assert_eq!(grouped.status(), StatusCode::OK);
            let viewer_remove = delete_json(
                &app,
                &format!("/api/groups/{department_id}/devices"),
                &viewer_token,
                json!({ "device_ids": ["device-a3"] }),
            )
            .await;
            assert_eq!(viewer_remove.status(), StatusCode::FORBIDDEN);
            let unknown_remove = delete_json(
                &app,
                &format!("/api/groups/{department_id}/devices"),
                &user_a_token,
                json!({ "device_ids": ["device-a3"], "unknown": true }),
            )
            .await;
            assert_eq!(unknown_remove.status(), StatusCode::BAD_REQUEST);
            let removed = delete_json(
                &app,
                &format!("/api/groups/{department_id}/devices"),
                &user_a_token,
                json!({ "device_ids": ["device-a3"] }),
            )
            .await;
            assert_eq!(removed.status(), StatusCode::OK);
            let removed = response_json(removed).await;
            assert_eq!(removed["matched_devices"], 1);
            assert_eq!(removed["changed_devices"], 1);
            let ungrouped = get(&app, "/api/devices/device-a3", &user_a_token).await;
            assert_eq!(ungrouped.status(), StatusCode::OK);
            assert!(response_json(ungrouped).await["group_id"].is_null());

            let tagged = post_json(
                &app,
                "/api/devices/batch-tag",
                &user_a_token,
                json!({
                    "device_ids": ["device-a1", "device-a2"],
                    "add_tags": ["prod"],
                    "remove_tags": []
                }),
            )
            .await;
            assert_eq!(tagged.status(), StatusCode::OK);
            let tagged = response_json(tagged).await;
            assert_eq!(tagged["matched_devices"], 2);

            let filtered = get(&app, "/api/devices?tag=prod&page_size=999", &user_a_token).await;
            assert_eq!(filtered.status(), StatusCode::OK);
            let filtered = response_json(filtered).await;
            assert_eq!(filtered["page_size"], 200);
            let ids = filtered["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|item| item["device_id"].as_str().unwrap().to_string())
                .collect::<BTreeSet<_>>();
            assert_eq!(
                ids,
                BTreeSet::from(["device-a1".to_string(), "device-a2".to_string()])
            );

            for device_id in ["device-a1", "device-a2"] {
                let device = get(&app, &format!("/api/devices/{device_id}"), &user_a_token).await;
                assert_eq!(device.status(), StatusCode::OK);
                let device = response_json(device).await;
                assert!(device["tags"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|tag| tag == "prod"));
                for secret in [
                    "guid",
                    "uuid",
                    "pk",
                    "info",
                    "ip",
                    "features",
                    "token_version",
                ] {
                    assert!(device.get(secret).is_none(), "{secret} leaked");
                }
            }

            let all_user_a = get(&app, "/api/devices", &user_a_token).await;
            let all_user_a = response_json(all_user_a).await;
            assert_eq!(all_user_a["total"], 3);
            assert!(all_user_a["items"]
                .as_array()
                .unwrap()
                .iter()
                .all(|item| item["device_id"] != "device-b1"));

            let hidden_device = get(&app, "/api/devices/device-b1", &user_a_token).await;
            assert_eq!(hidden_device.status(), StatusCode::NOT_FOUND);

            let viewer_write = put_json(
                &app,
                "/api/devices/device-a1",
                &viewer_token,
                json!({ "alias": "blocked" }),
            )
            .await;
            assert_eq!(viewer_write.status(), StatusCode::FORBIDDEN);

            drop(app);
            drop(receiver);
            tokio::time::sleep(std::time::Duration::from_millis(600)).await;
            drop(db);
            cleanup(&path);
        });
    }

    #[test]
    fn body_limit_runs_after_authentication_and_unknown_json_is_rejected() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let path = temp_db_path("inventory-body-limit");
            let db = Database::new(&path).await.unwrap();
            create_user(&db, "body-user", "user").await;
            create_user(&db, "body-viewer", "viewer").await;
            let (sender, receiver) = mpsc::channel(DEVICE_INVALIDATION_CHANNEL_CAPACITY);
            let app = test_router(db.clone(), sender);
            let token = login(&app, "body-user").await;
            let viewer_token = login(&app, "body-viewer").await;
            let oversized = format!(
                r#"{{"device_ids":["{}"],"add_tags":["x"],"remove_tags":[]}}"#,
                "x".repeat(270_000)
            );

            let unauthenticated =
                raw_json(&app, "/api/devices/batch-tag", None, oversized.clone()).await;
            assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
            let unauthenticated_declared_oversized = raw_json_with_content_length(
                &app,
                "/api/devices/batch-tag",
                None,
                oversized.clone(),
            )
            .await;
            assert_eq!(
                unauthenticated_declared_oversized.status(),
                StatusCode::UNAUTHORIZED
            );

            let authenticated = raw_json(
                &app,
                "/api/devices/batch-tag",
                Some(&token),
                oversized.clone(),
            )
            .await;
            assert_eq!(authenticated.status(), StatusCode::PAYLOAD_TOO_LARGE);
            let authenticated_declared_oversized = raw_json_with_content_length(
                &app,
                "/api/devices/batch-tag",
                Some(&token),
                oversized.clone(),
            )
            .await;
            assert_eq!(
                authenticated_declared_oversized.status(),
                StatusCode::PAYLOAD_TOO_LARGE
            );

            let viewer_malformed = raw_json(
                &app,
                "/api/devices/batch-tag",
                Some(&viewer_token),
                "{".to_string(),
            )
            .await;
            assert_eq!(viewer_malformed.status(), StatusCode::FORBIDDEN);

            let viewer_oversized = raw_json(
                &app,
                "/api/devices/batch-tag",
                Some(&viewer_token),
                oversized.clone(),
            )
            .await;
            assert_eq!(viewer_oversized.status(), StatusCode::FORBIDDEN);

            let viewer_declared_oversized = raw_json_with_content_length(
                &app,
                "/api/devices/batch-tag",
                Some(&viewer_token),
                oversized,
            )
            .await;
            assert_eq!(viewer_declared_oversized.status(), StatusCode::FORBIDDEN);

            let unknown = post_json(
                &app,
                "/api/devices/batch-tag",
                &token,
                json!({
                    "device_ids": ["device"],
                    "add_tags": ["x"],
                    "unknown": true
                }),
            )
            .await;
            assert_eq!(unknown.status(), StatusCode::BAD_REQUEST);

            drop(app);
            drop(receiver);
            tokio::time::sleep(std::time::Duration::from_millis(600)).await;
            drop(db);
            cleanup(&path);
        });
    }

    #[test]
    fn delete_generation_scope_and_durable_receipt_work_end_to_end() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let path = temp_db_path("inventory-delete");
            let db = Database::new(&path).await.unwrap();
            let user_a = create_user(&db, "delete-a", "user").await;
            let user_b = create_user(&db, "delete-b", "user").await;
            insert_owned_device(&db, "delete-a1", user_a).await;
            insert_owned_device(&db, "delete-a2", user_a).await;
            insert_owned_device(&db, "delete-b1", user_b).await;
            let a1 = db
                .get_managed_device(OwnerScope::All, "delete-a1")
                .await
                .unwrap()
                .unwrap();
            let a2 = db
                .get_managed_device(OwnerScope::All, "delete-a2")
                .await
                .unwrap()
                .unwrap();
            let b1 = db
                .get_managed_device(OwnerScope::All, "delete-b1")
                .await
                .unwrap()
                .unwrap();
            let old_guid = db.get_peer("delete-a1").await.unwrap().unwrap().guid;

            let (sender, mut receiver) = mpsc::channel(DEVICE_INVALIDATION_CHANNEL_CAPACITY);
            let app = test_router(db.clone(), sender);
            let token = login(&app, "delete-a").await;

            let missing_header = delete(&app, "/api/devices/delete-a1", &token, None).await;
            assert_eq!(missing_header.status().as_u16(), 428);
            let invalid_header =
                delete(&app, "/api/devices/delete-a1", &token, Some("invalid")).await;
            assert_eq!(invalid_header.status(), StatusCode::BAD_REQUEST);
            let wrong_generation = delete(
                &app,
                "/api/devices/delete-a1",
                &token,
                Some("00000000000000000000000000000000"),
            )
            .await;
            assert_eq!(wrong_generation.status(), StatusCode::PRECONDITION_FAILED);

            let hidden = delete(
                &app,
                "/api/devices/delete-b1",
                &token,
                Some(&b1.management_generation),
            )
            .await;
            let hidden_status = hidden.status();
            let hidden_body = response_json(hidden).await;
            let missing = delete(
                &app,
                "/api/devices/does-not-exist",
                &token,
                Some("11111111111111111111111111111111"),
            )
            .await;
            let missing_status = missing.status();
            let missing_body = response_json(missing).await;
            assert_eq!(hidden_status, StatusCode::NOT_FOUND);
            assert_eq!(hidden_status, missing_status);
            assert_eq!(hidden_body, missing_body);
            assert!(matches!(
                receiver.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ));
            assert!(db
                .get_deletion_receipt(user_a, "delete-b1", &b1.management_generation)
                .await
                .unwrap()
                .is_none());

            let mut blocker = SqliteConnection::connect(&path).await.unwrap();
            blocker.execute("BEGIN IMMEDIATE").await.unwrap();
            let busy = delete(
                &app,
                "/api/devices/delete-a1",
                &token,
                Some(&a1.management_generation),
            )
            .await;
            assert_eq!(busy.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(busy.headers().get(header::RETRY_AFTER).unwrap(), "1");
            let busy = response_json(busy).await;
            assert_eq!(busy["database_deleted_committed"], false);
            assert_eq!(busy["quota_released"], false);
            assert_eq!(busy["retryable"], true);
            assert!(db
                .get_managed_device(OwnerScope::All, "delete-a1")
                .await
                .unwrap()
                .is_some());
            assert!(db
                .get_deletion_receipt(user_a, "delete-a1", &a1.management_generation)
                .await
                .unwrap()
                .is_none());
            assert!(matches!(
                receiver.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ));
            blocker.execute("ROLLBACK").await.unwrap();
            drop(blocker);

            let controller = tokio::spawn(async move {
                let command = receiver.recv().await.unwrap();
                assert_eq!(command.device_id, "delete-a1");
                match command.predicate {
                    DeviceInvalidationPredicate::DeletedGeneration { guid } => {
                        assert_eq!(guid, old_guid);
                    }
                    DeviceInvalidationPredicate::StillInactive => {
                        panic!("delete used the inactive predicate");
                    }
                }
                command
                    .ack
                    .send(Ok(InvalidationResult::AlreadyAbsent))
                    .unwrap();
                receiver
            });
            let deleted = delete(
                &app,
                "/api/devices/delete-a1",
                &token,
                Some(&a1.management_generation),
            )
            .await;
            let mut receiver = controller.await.unwrap();
            if deleted.status() == StatusCode::SERVICE_UNAVAILABLE {
                assert_eq!(
                    response_json(deleted).await["database_deleted_committed"],
                    true
                );
            } else {
                assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
            }
            let retried = delete(
                &app,
                "/api/devices/delete-a1",
                &token,
                Some(&a1.management_generation),
            )
            .await;
            assert_eq!(retried.status(), StatusCode::NO_CONTENT);
            let receipt = db
                .get_deletion_receipt(user_a, "delete-a1", &a1.management_generation)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(receipt.state, DeletionReceiptState::Completed);
            assert!(db
                .get_managed_device(OwnerScope::All, "delete-a1")
                .await
                .unwrap()
                .is_none());
            assert!(matches!(
                receiver.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ));

            drop(app);
            drop(receiver);
            tokio::time::sleep(std::time::Duration::from_millis(600)).await;

            let (closed_sender, closed_receiver) =
                mpsc::channel(DEVICE_INVALIDATION_CHANNEL_CAPACITY);
            drop(closed_receiver);
            let closed_app = test_router(db.clone(), closed_sender);
            let pending = delete(
                &closed_app,
                "/api/devices/delete-a2",
                &token,
                Some(&a2.management_generation),
            )
            .await;
            assert_eq!(pending.status(), StatusCode::SERVICE_UNAVAILABLE);
            let pending_body = response_json(pending).await;
            assert_eq!(pending_body["database_deleted_committed"], true);
            assert_eq!(pending_body["quota_released"], true);
            assert_eq!(pending_body["retryable"], true);
            let receipt = db
                .get_deletion_receipt(user_a, "delete-a2", &a2.management_generation)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(receipt.state, DeletionReceiptState::Pending);
            drop(closed_app);
            tokio::time::sleep(std::time::Duration::from_millis(600)).await;

            let (retry_sender, mut retry_receiver) =
                mpsc::channel(DEVICE_INVALIDATION_CHANNEL_CAPACITY);
            let retry_app = test_router(db.clone(), retry_sender);
            let retry_controller = tokio::spawn(async move {
                let command = retry_receiver.recv().await.unwrap();
                assert_eq!(command.device_id, "delete-a2");
                command
                    .ack
                    .send(Ok(InvalidationResult::AlreadyAbsent))
                    .unwrap();
                retry_receiver
            });
            let recovered = delete(
                &retry_app,
                "/api/devices/delete-a2",
                &token,
                Some(&a2.management_generation),
            )
            .await;
            let retry_receiver = retry_controller.await.unwrap();
            if recovered.status() == StatusCode::SERVICE_UNAVAILABLE {
                let after_dispatch = delete(
                    &retry_app,
                    "/api/devices/delete-a2",
                    &token,
                    Some(&a2.management_generation),
                )
                .await;
                assert_eq!(after_dispatch.status(), StatusCode::NO_CONTENT);
            } else {
                assert_eq!(recovered.status(), StatusCode::NO_CONTENT);
            }
            let completed = db
                .get_deletion_receipt(user_a, "delete-a2", &a2.management_generation)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(completed.state, DeletionReceiptState::Completed);

            drop(retry_app);
            drop(retry_receiver);
            tokio::time::sleep(std::time::Duration::from_millis(600)).await;
            drop(db);
            cleanup(&path);
        });
    }

    async fn create_user(db: &Database, username: &str, role: &str) -> i64 {
        let password_hash = hash_password("secret").unwrap();
        db.create_user(username, &password_hash, None, role)
            .await
            .unwrap()
            .id
    }

    async fn insert_owned_device(db: &Database, device_id: &str, owner_user_id: i64) {
        let uuid = format!("uuid-{device_id}");
        let pk = format!("pk-{device_id}");
        db.insert_peer(device_id, uuid.as_bytes(), pk.as_bytes(), "{}")
            .await
            .unwrap();
        db.update_managed_device(
            OwnerScope::All,
            device_id,
            &DeviceUpdate {
                owner_user_id: Some(Some(owner_user_id)),
                ..DeviceUpdate::default()
            },
        )
        .await
        .unwrap()
        .unwrap();
    }

    fn test_router(db: Database, sender: crate::peer::DeviceInvalidationSender) -> Router {
        build_router(
            db,
            AuthState {
                jwt_secret: "inventory-test-secret".to_string(),
                jwt_expiry_hours: 24,
                refresh_expiry_days: 7,
            },
            OidcConfig::default(),
            sender,
        )
    }

    async fn login(app: &Router, username: &str) -> String {
        let response = app
            .clone()
            .oneshot(json_request(
                "POST",
                "/api/auth/login",
                None,
                json!({ "username": username, "password": "secret" }).to_string(),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        response_json(response).await["access_token"]
            .as_str()
            .unwrap()
            .to_string()
    }

    async fn get(app: &Router, uri: &str, token: &str) -> Response {
        app.clone()
            .oneshot(json_request("GET", uri, Some(token), String::new(), None))
            .await
            .unwrap()
    }

    async fn post_json(app: &Router, uri: &str, token: &str, value: Value) -> Response {
        app.clone()
            .oneshot(json_request(
                "POST",
                uri,
                Some(token),
                value.to_string(),
                None,
            ))
            .await
            .unwrap()
    }

    async fn put_json(app: &Router, uri: &str, token: &str, value: Value) -> Response {
        app.clone()
            .oneshot(json_request(
                "PUT",
                uri,
                Some(token),
                value.to_string(),
                None,
            ))
            .await
            .unwrap()
    }

    async fn delete_json(app: &Router, uri: &str, token: &str, value: Value) -> Response {
        app.clone()
            .oneshot(json_request(
                "DELETE",
                uri,
                Some(token),
                value.to_string(),
                None,
            ))
            .await
            .unwrap()
    }

    async fn raw_json(app: &Router, uri: &str, token: Option<&str>, body: String) -> Response {
        app.clone()
            .oneshot(json_request("POST", uri, token, body, None))
            .await
            .unwrap()
    }

    async fn raw_json_with_content_length(
        app: &Router,
        uri: &str,
        token: Option<&str>,
        body: String,
    ) -> Response {
        let body_len = body.len();
        let mut request = json_request("POST", uri, token, body, None);
        request.headers_mut().insert(
            header::CONTENT_LENGTH,
            body_len.to_string().parse().unwrap(),
        );
        app.clone().oneshot(request).await.unwrap()
    }

    async fn delete(app: &Router, uri: &str, token: &str, generation: Option<&str>) -> Response {
        app.clone()
            .oneshot(json_request(
                "DELETE",
                uri,
                Some(token),
                String::new(),
                generation,
            ))
            .await
            .unwrap()
    }

    fn json_request(
        method: &str,
        uri: &str,
        token: Option<&str>,
        body: String,
        generation: Option<&str>,
    ) -> Request<Body> {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(token) = token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        if let Some(generation) = generation {
            builder = builder.header("x-device-generation", generation);
        }
        builder.body(Body::from(body)).unwrap()
    }

    async fn response_json(response: Response) -> Value {
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        while let Some(chunk) = body.data().await {
            bytes.extend_from_slice(&chunk.unwrap());
        }
        serde_json::from_slice(&bytes).unwrap()
    }

    fn temp_db_path(name: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir()
            .join(format!(
                "rustdesk-{name}-{}-{nanos}.sqlite3",
                std::process::id()
            ))
            .to_string_lossy()
            .to_string()
    }

    fn cleanup(path: &str) {
        std::fs::remove_file(path).ok();
        std::fs::remove_file(format!("{path}-shm")).ok();
        std::fs::remove_file(format!("{path}-wal")).ok();
    }
}
