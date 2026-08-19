pub mod access;
pub mod addressbook;
pub mod admin_init;
pub mod audit;
pub mod auth;
pub mod auth_service;
pub mod client_auth;
pub mod device_deletion;
pub mod devices;
pub mod groups;
pub mod health;
pub mod license;
pub mod middleware;
pub mod oidc;
pub mod security;
pub mod sysinfo;
pub mod sysinfo_ver;
pub mod users;
pub mod version;

#[cfg(test)]
use crate::config::{ApiRateLimitConfig, SecurityConfig};
#[cfg(test)]
use crate::peer::DEVICE_INVALIDATION_CHANNEL_CAPACITY;
use crate::{
    audit::AuditService,
    auth::AuthState,
    config::{global_config, OidcConfig},
    database::Database,
    peer::DeviceInvalidationSender,
    security::SecurityPolicyState,
};
#[cfg(test)]
use axum::extract::connect_info::ConnectInfo;
#[cfg(any(test, not(feature = "pro")))]
use axum::http::StatusCode;
#[cfg(not(feature = "pro"))]
use axum::Json;
use axum::{
    routing::{any, get, post},
    Extension, Router,
};
use hbb_common::log;
#[cfg(any(test, not(feature = "pro")))]
use serde_json::{json, Value};
use std::{net::SocketAddr, sync::mpsc::Sender};
use tower::ServiceBuilder;
use tower_http::limit::RequestBodyLimitLayer;

pub fn build_router(
    db: Database,
    auth_state: AuthState,
    oidc_config: OidcConfig,
    device_control_tx: DeviceInvalidationSender,
) -> Router {
    build_router_with_protection(
        db,
        auth_state,
        oidc_config,
        device_control_tx,
        new_api_protection_state(),
    )
}

fn new_api_protection_state() -> middleware::ApiProtectionState {
    let rate_limit_config = global_config()
        .and_then(|config| {
            config
                .read()
                .ok()
                .map(|config| config.api_rate_limit.clone())
        })
        .unwrap_or_default();
    middleware::ApiProtectionState::new(rate_limit_config)
}

fn build_router_with_protection(
    db: Database,
    auth_state: AuthState,
    oidc_config: OidcConfig,
    device_control_tx: DeviceInvalidationSender,
    protection: middleware::ApiProtectionState,
) -> Router {
    let security_config = global_config()
        .and_then(|config| config.read().ok().map(|config| config.pro.security.clone()))
        .unwrap_or_default();
    let security =
        SecurityPolicyState::new(security_config).expect("default security policy must be valid");
    build_router_with_states(
        db,
        auth_state,
        oidc_config,
        device_control_tx,
        protection,
        security,
    )
}

fn build_router_with_states(
    db: Database,
    auth_state: AuthState,
    oidc_config: OidcConfig,
    device_control_tx: DeviceInvalidationSender,
    protection: middleware::ApiProtectionState,
    security: SecurityPolicyState,
) -> Router {
    #[cfg(test)]
    middleware::clear_token_rejection_cache();
    device_deletion::spawn_dispatcher(db.clone(), device_control_tx.clone());
    let audit = AuditService::start(db.clone(), Some(security.clone()));

    let inventory_router = Router::new()
        .route(
            "/api/groups",
            get(groups::handle_list_groups).post(groups::handle_create_group),
        )
        .route(
            "/api/groups/:id",
            get(groups::handle_get_group)
                .put(groups::handle_update_group)
                .delete(groups::handle_delete_group),
        )
        .route(
            "/api/groups/:id/devices",
            post(groups::handle_add_group_devices).delete(groups::handle_remove_group_devices),
        )
        .route("/api/devices", get(devices::handle_list_devices))
        .route("/api/devices/batch-tag", post(devices::handle_batch_tag))
        .route(
            "/api/devices/:id",
            get(devices::handle_get_device)
                .put(devices::handle_update_device)
                .delete(devices::handle_delete_device),
        )
        .layer(RequestBodyLimitLayer::new(256 * 1024))
        .layer(axum::middleware::from_fn(
            access::require_inventory_write_access,
        ));

    let address_book_router = Router::new()
        .route("/api/ab", get(addressbook::handle_get_address_book))
        .route("/api/ab/pending", get(addressbook::handle_pending_shares))
        .route(
            "/api/ab/share/:device_id",
            post(addressbook::handle_share_device).delete(addressbook::handle_cancel_share),
        )
        .route(
            "/api/ab/accept/:share_id",
            post(addressbook::handle_accept_share),
        )
        .route(
            "/api/ab/reject/:share_id",
            post(addressbook::handle_reject_share),
        )
        .layer(axum::middleware::from_fn(
            client_auth::header_only_auth_layer,
        ))
        .layer(axum::middleware::from_fn(
            middleware::protect_shared_endpoint,
        ))
        .layer(RequestBodyLimitLayer::new(256 * 1024))
        .layer(axum::middleware::from_fn(
            middleware::normalize_api_error_response,
        ));

    let client_auth_router = Router::new()
        .route("/api/login", post(client_auth::handle_client_login))
        .layer(axum::middleware::from_fn(middleware::protect_auth_endpoint))
        .layer(RequestBodyLimitLayer::new(64 * 1024))
        .layer(axum::middleware::from_fn(
            middleware::normalize_api_error_response,
        ));

    let client_session_router = Router::new()
        .route("/api/currentUser", post(client_auth::handle_current_user))
        .route("/api/logout", post(client_auth::handle_client_logout))
        .layer(axum::middleware::from_fn(
            client_auth::header_only_auth_layer,
        ))
        .layer(axum::middleware::from_fn(middleware::protect_auth_endpoint))
        .layer(RequestBodyLimitLayer::new(64 * 1024))
        .layer(axum::middleware::from_fn(
            middleware::normalize_api_error_response,
        ));

    let telemetry_router = Router::new()
        .route("/api/sysinfo", post(sysinfo::handle_sysinfo))
        .route("/api/heartbeat", post(sysinfo::handle_heartbeat))
        .layer(axum::middleware::from_fn(
            client_auth::optional_header_auth_layer,
        ))
        .layer(axum::middleware::from_fn(
            middleware::protect_telemetry_endpoint,
        ))
        .layer(RequestBodyLimitLayer::new(64 * 1024))
        .layer(axum::middleware::from_fn(
            middleware::normalize_api_error_response,
        ));

    let sysinfo_version_router = Router::new()
        .route("/api/sysinfo_ver", post(sysinfo_ver::handle_sysinfo_ver))
        .layer(axum::middleware::from_fn(
            middleware::protect_telemetry_endpoint,
        ))
        .layer(RequestBodyLimitLayer::new(64 * 1024))
        .layer(axum::middleware::from_fn(
            middleware::normalize_api_error_response,
        ));

    let standard_auth_public_router = Router::new()
        .route("/api/auth/login", post(auth::handle_login))
        .route("/api/auth/refresh", post(auth::handle_refresh))
        .layer(axum::middleware::from_fn(middleware::protect_auth_endpoint))
        .layer(RequestBodyLimitLayer::new(64 * 1024))
        .layer(axum::middleware::from_fn(
            middleware::normalize_api_error_response,
        ));

    let standard_logout_router = Router::new()
        .route("/api/auth/logout", post(auth::handle_logout))
        .layer(axum::middleware::from_fn(middleware::auth_layer))
        .layer(axum::middleware::from_fn(middleware::protect_auth_endpoint))
        .layer(RequestBodyLimitLayer::new(64 * 1024))
        .layer(axum::middleware::from_fn(
            middleware::normalize_api_error_response,
        ));

    let protected_router = Router::new()
        .route(
            "/api/users",
            get(users::handle_list_users).post(users::handle_create_user),
        )
        .route(
            "/api/users/:id",
            get(users::handle_get_user)
                .put(users::handle_update_user)
                .delete(users::handle_delete_user),
        )
        .route("/api/license/status", get(license::handle_license_status))
        .route("/api/license/usage", get(license::handle_license_usage))
        .route("/api/license/upload", post(license::handle_license_upload))
        .route(
            "/api/license/devices/:device_id/inactive",
            post(license::handle_device_inactive),
        )
        .merge(inventory_router)
        .layer(ServiceBuilder::new().layer(axum::middleware::from_fn(middleware::auth_layer)))
        .layer(axum::middleware::from_fn(
            middleware::protect_shared_endpoint,
        ));

    let audit_security_router = Router::new()
        .route("/api/audit-logs", get(audit::handle_list_audit_logs))
        .route(
            "/api/security/policies",
            get(security::handle_get_policies).put(security::handle_update_policies),
        )
        .layer(axum::middleware::from_fn(middleware::auth_layer))
        .layer(axum::middleware::from_fn(
            middleware::protect_shared_endpoint,
        ))
        .layer(RequestBodyLimitLayer::new(64 * 1024))
        .layer(axum::middleware::from_fn(
            middleware::normalize_api_error_response,
        ));

    let public_utility_router = Router::new()
        .route("/api/auth/oidc/login", get(oidc::handle_oidc_login))
        .route("/api/auth/oidc/callback", get(oidc::handle_oidc_callback))
        .route("/api/health", get(health::handle_health))
        .route("/api/version", get(version::handle_version))
        .layer(axum::middleware::from_fn(
            middleware::protect_shared_endpoint,
        ));

    let app = Router::new()
        .merge(public_utility_router)
        .merge(standard_auth_public_router)
        .merge(standard_logout_router)
        .merge(client_auth_router)
        .merge(client_session_router)
        .merge(telemetry_router)
        .merge(sysinfo_version_router)
        .merge(address_book_router)
        .merge(audit_security_router)
        .merge(protected_router)
        .layer(
            ServiceBuilder::new()
                .layer(Extension(db))
                .layer(Extension(device_control_tx))
                .layer(Extension(auth_state))
                .layer(Extension(oidc_config.clone()))
                .layer(Extension(protection))
                .layer(Extension(security))
                .layer(Extension(audit)),
        );

    #[cfg(feature = "pro")]
    let app = app.fallback(any(crate::web::handle_web_request));
    #[cfg(not(feature = "pro"))]
    let app = app.fallback(any(handle_404));

    let app = app
        .layer(middleware::rate_limit_layer())
        .layer(axum::middleware::from_fn(middleware::request_logger))
        .layer(middleware::cors_middleware(&oidc_config));

    #[cfg(test)]
    let app = app.layer(Extension(ConnectInfo(SocketAddr::from((
        [127, 0, 0, 1],
        1,
    )))));

    app
}

pub fn api_server_forever(
    addr: SocketAddr,
    ready_tx: Sender<Result<(), String>>,
    db_url: String,
    auth_state: AuthState,
    oidc_config: OidcConfig,
    device_control_tx: DeviceInvalidationSender,
) {
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(err) => {
            let message = format!("failed to create tokio runtime for API server: {}", err);
            let _ = ready_tx.send(Err(message.clone()));
            eprintln!("Fatal: {}", message);
            std::process::exit(1);
        }
    };

    rt.block_on(async move {
        let db = match Database::new(&db_url).await {
            Ok(db) => db,
            Err(err) => {
                let message = format!("API server failed to initialize database: {}", err);
                let _ = ready_tx.send(Err(message.clone()));
                eprintln!("Fatal: {}", message);
                std::process::exit(1);
            }
        };
        let protection = new_api_protection_state();
        let security_config = global_config()
            .and_then(|config| config.read().ok().map(|config| config.pro.security.clone()))
            .unwrap_or_default();
        let security = match SecurityPolicyState::load(&db, &security_config).await {
            Ok(security) => security,
            Err(err) => {
                let message = format!("API server failed to load security policy: {}", err);
                let _ = ready_tx.send(Err(message.clone()));
                eprintln!("Fatal: {}", message);
                std::process::exit(1);
            }
        };
        if let Err(err) = admin_init::create_initial_admin(&db, &protection, &security).await {
            let message = format!("API server failed to initialize admin user: {}", err);
            let _ = ready_tx.send(Err(message.clone()));
            eprintln!("Fatal: {}", message);
            std::process::exit(1);
        }
        crate::license::init_license_state();
        if let Err(err) = crate::license::load_license_from_database(&db).await {
            log::warn!("许可证加载失败，Pro 模式新连接将被拒绝: {}", err);
        }

        let app = build_router_with_states(
            db,
            auth_state,
            oidc_config,
            device_control_tx,
            protection,
            security,
        );
        log::info!("API server binding to {}", addr);
        match axum::Server::try_bind(&addr) {
            Ok(server) => {
                let _ = ready_tx.send(Ok(()));
                log::info!("API server listening on {}", addr);
                if let Err(err) = server
                    .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                    .await
                {
                    eprintln!("Fatal: API server error: {}", err);
                    std::process::exit(1);
                }
            }
            Err(err) => {
                let message = format!("API server failed to bind to {}: {}", addr, err);
                let _ = ready_tx.send(Err(message.clone()));
                eprintln!("Fatal: {}", message);
                std::process::exit(1);
            }
        }
    });
}

#[cfg(not(feature = "pro"))]
async fn handle_404() -> (StatusCode, Json<Value>) {
    (StatusCode::NOT_FOUND, Json(json!({ "error": "not found" })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{Body, Bytes, HttpBody},
        http::{header, HeaderValue, Request},
    };
    use std::{
        fmt::Debug,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };
    use tower::ServiceExt;

    fn build_test_router(db: Database, auth_state: AuthState, oidc_config: OidcConfig) -> Router {
        let (tx, _rx) = tokio::sync::mpsc::channel(DEVICE_INVALIDATION_CHANNEL_CAPACITY);
        build_router(db, auth_state, oidc_config, tx)
    }

    #[test]
    fn test_build_router() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("api-build-router");
            let db = Database::new(&path).await.unwrap();
            let _app = build_test_router(db, test_auth_state(), test_oidc_config());
            cleanup(&path);
        });
    }

    #[test]
    fn test_health_route_is_public() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("api-health");
            let db = Database::new(&path).await.unwrap();
            let response = build_test_router(db, test_auth_state(), test_oidc_config())
                .oneshot(
                    Request::builder()
                        .uri("/api/health")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::OK);
            let body = read_body(response.into_body()).await;
            let value: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(value["status"], "ok");
            cleanup(&path);
        });
    }

    #[test]
    fn public_utility_routes_use_ordinary_capacity_and_recover_after_saturation() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("api-public-utility-capacity");
            let db = Database::new(&path).await.unwrap();
            let protection = middleware::ApiProtectionState::new(ApiRateLimitConfig::default());
            let ordinary_permits = protection.occupy_all_other_for_test();
            let (tx, _rx) = tokio::sync::mpsc::channel(DEVICE_INVALIDATION_CHANNEL_CAPACITY);
            let app = build_router_with_protection(
                db,
                test_auth_state(),
                test_oidc_config(),
                tx,
                protection,
            );

            for uri in [
                "/api/health",
                "/api/version",
                "/api/auth/oidc/login",
                "/api/auth/oidc/callback",
            ] {
                let response = app
                    .clone()
                    .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "{uri}");
                assert_eq!(
                    response.headers().get(header::RETRY_AFTER).unwrap(),
                    "1",
                    "{uri}"
                );
            }

            drop(ordinary_permits);
            let response = app
                .oneshot(
                    Request::builder()
                        .uri("/api/health")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            cleanup(&path);
        });
    }

    #[test]
    fn test_unknown_route_returns_404_without_token() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("api-404");
            let db = Database::new(&path).await.unwrap();
            let response = build_test_router(db, test_auth_state(), test_oidc_config())
                .oneshot(
                    Request::builder()
                        .uri("/api/does-not-exist")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            let body = read_body(response.into_body()).await;
            let value: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(value, json!({ "error": "not found" }));
            cleanup(&path);
        });
    }

    #[test]
    fn issue9_router_rejections_use_json_error_envelopes_without_changing_existing_routes() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("api-json-errors");
            let db = Database::new(&path).await.unwrap();
            let password_hash = admin_init::hash_password("secret").unwrap();
            db.create_user("user", &password_hash, None, "user")
                .await
                .unwrap();
            let app = build_test_router(db, test_auth_state(), test_oidc_config());

            let wrong_method = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/api/login")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_json_error(wrong_method, StatusCode::METHOD_NOT_ALLOWED).await;

            let malformed_json = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/login")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from("{"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_json_error(malformed_json, StatusCode::BAD_REQUEST).await;

            let wrong_mime = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/login")
                        .header(header::ORIGIN, "https://console.example.com")
                        .header(header::CONTENT_TYPE, "application/xml")
                        .body(Body::from(r#"{"username":"user","password":"secret"}"#))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                wrong_mime
                    .headers()
                    .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                    .and_then(|value| value.to_str().ok()),
                Some("*")
            );
            assert_json_error(wrong_mime, StatusCode::UNSUPPORTED_MEDIA_TYPE).await;

            let oversized_body = vec![b'a'; 70 * 1024];
            let oversized = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/login")
                        .header(header::ORIGIN, "https://console.example.com")
                        .header(header::CONTENT_TYPE, "application/json")
                        .header(header::CONTENT_LENGTH, oversized_body.len())
                        .body(Body::from(oversized_body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                oversized
                    .headers()
                    .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                    .and_then(|value| value.to_str().ok()),
                Some("*")
            );
            assert_json_error(oversized, StatusCode::PAYLOAD_TOO_LARGE).await;

            let token = login_access_token(&app, "user", "secret").await;
            let address_book_post = app
                .clone()
                .oneshot(authenticated_request("POST", "/api/ab", &token))
                .await
                .unwrap();
            assert_json_error(address_book_post, StatusCode::METHOD_NOT_ALLOWED).await;

            let invalid_path = app
                .clone()
                .oneshot(authenticated_request(
                    "POST",
                    "/api/ab/accept/not-a-number",
                    &token,
                ))
                .await
                .unwrap();
            assert_json_error(invalid_path, StatusCode::BAD_REQUEST).await;

            let json_suffix_mime = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/ab/share/device")
                        .header(header::AUTHORIZATION, format!("Bearer {token}"))
                        .header(header::CONTENT_TYPE, "application/merge-patch+json")
                        .body(Body::from(
                            r#"{"to_username":"target","permission":"view_only"}"#,
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_json_error(json_suffix_mime, StatusCode::UNSUPPORTED_MEDIA_TYPE).await;

            let existing_route_wrong_method = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/health")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                existing_route_wrong_method.status(),
                StatusCode::METHOD_NOT_ALLOWED
            );
            assert_ne!(
                existing_route_wrong_method
                    .headers()
                    .get(header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok()),
                Some("application/json")
            );
            cleanup(&path);
        });
    }

    #[test]
    fn issue9_auth_and_telemetry_routes_enforce_exact_64_kib_body_limit_and_recover() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("api-body-limit-matrix");
            let db = Database::new(&path).await.unwrap();
            let password_hash = admin_init::hash_password("secret").unwrap();
            let client_user = db
                .create_user("body-client", &password_hash, None, "user")
                .await
                .unwrap();
            let standard_user = db
                .create_user("body-standard", &password_hash, None, "user")
                .await
                .unwrap();
            let auth_state = test_auth_state();
            let client_token = crate::auth::jwt::sign_token(
                &client_user,
                &auth_state.jwt_secret,
                auth_state.jwt_expiry_hours,
            )
            .unwrap();
            let standard_token = crate::auth::jwt::sign_token(
                &standard_user,
                &auth_state.jwt_secret,
                auth_state.jwt_expiry_hours,
            )
            .unwrap();
            let app = build_test_router(db, auth_state, test_oidc_config());

            let routes = [
                ("/api/login", None),
                ("/api/currentUser", Some(client_token.as_str())),
                ("/api/auth/login", None),
                ("/api/auth/refresh", None),
                ("/api/sysinfo", None),
                ("/api/heartbeat", None),
                ("/api/sysinfo_ver", None),
                ("/api/auth/logout", Some(standard_token.as_str())),
                ("/api/logout", Some(client_token.as_str())),
            ];

            for (uri, token) in routes {
                let oversized_body = vec![b' '; 64 * 1024 + 1];
                let oversized = app
                    .clone()
                    .oneshot(post_sized_request_with_optional_token(
                        uri,
                        "application/json",
                        oversized_body,
                        token,
                    ))
                    .await
                    .unwrap();
                assert_json_error(oversized, StatusCode::PAYLOAD_TOO_LARGE).await;

                let boundary_body = vec![b' '; 64 * 1024];
                let boundary = app
                    .clone()
                    .oneshot(post_sized_request_with_optional_token(
                        uri,
                        "application/json",
                        boundary_body,
                        token,
                    ))
                    .await
                    .unwrap();
                assert_ne!(
                    boundary.status(),
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "{uri} 应接受精确 64 KiB 请求体并在 413 后恢复"
                );
            }
            cleanup(&path);
        });
    }

    #[test]
    fn issue9_auth_and_telemetry_slow_bodies_timeout_with_retry_after_and_recover() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("api-slow-body-matrix");
            let db = Database::new(&path).await.unwrap();
            let password_hash = admin_init::hash_password("secret").unwrap();
            let user = db
                .create_user("slow-body-user", &password_hash, None, "user")
                .await
                .unwrap();
            let auth_state = test_auth_state();
            let token = crate::auth::jwt::sign_token(
                &user,
                &auth_state.jwt_secret,
                auth_state.jwt_expiry_hours,
            )
            .unwrap();
            let config = ApiRateLimitConfig {
                request_timeout_ms: 100,
                ..ApiRateLimitConfig::default()
            };
            let app = build_test_router_with_config(db, auth_state, config);

            let routes = [
                ("/api/login", None),
                ("/api/currentUser", Some(token.as_str())),
                ("/api/logout", Some(token.as_str())),
                ("/api/auth/login", None),
                ("/api/auth/refresh", None),
                ("/api/auth/logout", Some(token.as_str())),
                ("/api/sysinfo", None),
                ("/api/heartbeat", None),
                ("/api/sysinfo_ver", None),
            ];

            for (uri, request_token) in routes {
                let (body, body_entered, release_body, feeder) = slow_streaming_body();
                let request =
                    post_request_with_optional_token(uri, "application/json", body, request_token);
                let response_task = tokio::spawn(app.clone().oneshot(request));
                tokio::time::timeout(Duration::from_secs(2), body_entered)
                    .await
                    .expect("慢请求体读取阶段等待超时")
                    .expect("慢请求体必须已进入真实路由读取阶段");

                let response = response_task.await.unwrap().unwrap();
                assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "{uri}");
                assert_eq!(
                    response.headers().get(header::RETRY_AFTER).unwrap(),
                    "1",
                    "{uri}"
                );
                assert_json_error(response, StatusCode::SERVICE_UNAVAILABLE).await;

                let recovered = app
                    .clone()
                    .oneshot(
                        Request::builder()
                            .method("POST")
                            .uri(uri)
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_ne!(
                    recovered.status(),
                    StatusCode::SERVICE_UNAVAILABLE,
                    "{uri} 超时后必须释放并发许可"
                );

                let _ = release_body.send(());
                feeder.await.unwrap();
            }
            cleanup(&path);
        });
    }

    #[test]
    fn issue9_slow_auth_saturation_preserves_real_telemetry_route_capacity() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("api-auth-telemetry-isolation");
            let db = Database::new(&path).await.unwrap();
            let uuid = vec![9_u8; 16];
            db.insert_peer("isolation-device", &uuid, b"pk", "{}")
                .await
                .unwrap();

            let config = ApiRateLimitConfig {
                max_in_flight: 3,
                telemetry_max_in_flight: 1,
                auth_max_in_flight: 1,
                argon2_max_in_flight: 1,
                request_timeout_ms: 1_000,
                ..ApiRateLimitConfig::default()
            };
            let app = build_test_router_with_config(db, test_auth_state(), config);

            let (body, body_entered, release_body, feeder) = slow_streaming_body();
            let slow_login = tokio::spawn(
                app.clone().oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/login")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(body)
                        .unwrap(),
                ),
            );
            tokio::time::timeout(Duration::from_secs(2), body_entered)
                .await
                .expect("慢登录读取阶段等待超时")
                .expect("慢登录必须先占有 auth 隔舱和共享许可");

            let rejected_login = app
                .clone()
                .oneshot(json_request(
                    "/api/login",
                    json!({ "username": "nobody", "password": "secret" }),
                ))
                .await
                .unwrap();
            assert_eq!(rejected_login.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(
                rejected_login.headers().get(header::RETRY_AFTER).unwrap(),
                "1"
            );
            assert_json_error(rejected_login, StatusCode::SERVICE_UNAVAILABLE).await;

            let heartbeat = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/heartbeat")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(
                            json!({
                                "id": "isolation-device",
                                "uuid": base64::encode(&uuid)
                            })
                            .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(heartbeat.status(), StatusCode::OK);
            assert_content_type(&heartbeat, "application/json");
            let heartbeat_body: Value =
                serde_json::from_slice(&read_body(heartbeat.into_body()).await).unwrap();
            assert_eq!(heartbeat_body, json!({ "sysinfo": true }));

            let slow_response = slow_login.await.unwrap().unwrap();
            assert_eq!(slow_response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(
                slow_response.headers().get(header::RETRY_AFTER).unwrap(),
                "1"
            );

            let recovered_login = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/login")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from("{"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(recovered_login.status(), StatusCode::BAD_REQUEST);

            let _ = release_body.send(());
            feeder.await.unwrap();
            cleanup(&path);
        });
    }

    #[test]
    fn issue9_router_peer_and_device_rate_limits_return_retryable_429() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("api-router-rate-limits");
            let db = Database::new(&path).await.unwrap();
            let uuid = vec![4_u8; 16];
            db.insert_peer("limited-device", &uuid, b"pk", "{}")
                .await
                .unwrap();

            let peer_config = ApiRateLimitConfig {
                auth_peer_capacity: 1,
                auth_peer_refill_per_minute: 1,
                telemetry_peer_capacity: 1,
                telemetry_peer_refill_per_minute: 1,
                ..ApiRateLimitConfig::default()
            };
            let peer_limited =
                build_test_router_with_config(db.clone(), test_auth_state(), peer_config);

            let first_auth = peer_limited
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/auth/refresh")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(first_auth.status(), StatusCode::UNAUTHORIZED);
            let limited_auth = peer_limited
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/auth/refresh")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                limited_auth.headers().get(header::RETRY_AFTER).unwrap(),
                "1"
            );
            assert_json_error(limited_auth, StatusCode::TOO_MANY_REQUESTS).await;

            let first_telemetry = peer_limited
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/sysinfo_ver")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(first_telemetry.status(), StatusCode::OK);
            let limited_telemetry = peer_limited
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/sysinfo_ver")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                limited_telemetry
                    .headers()
                    .get(header::RETRY_AFTER)
                    .unwrap(),
                "1"
            );
            assert_json_error(limited_telemetry, StatusCode::TOO_MANY_REQUESTS).await;

            let device_config = ApiRateLimitConfig {
                telemetry_peer_capacity: 10,
                telemetry_peer_refill_per_minute: 10,
                device_capacity: 1,
                device_refill_per_minute: 1,
                ..ApiRateLimitConfig::default()
            };
            let device_limited =
                build_test_router_with_config(db, test_auth_state(), device_config);
            let heartbeat_body = json!({
                "id": "limited-device",
                "uuid": base64::encode(&uuid)
            })
            .to_string();
            let first_device = device_limited
                .clone()
                .oneshot(post_request_with_optional_token(
                    "/api/heartbeat",
                    "application/json",
                    heartbeat_body.clone(),
                    None,
                ))
                .await
                .unwrap();
            assert_eq!(first_device.status(), StatusCode::OK);
            let limited_device = device_limited
                .clone()
                .oneshot(post_request_with_optional_token(
                    "/api/heartbeat",
                    "application/json",
                    heartbeat_body,
                    None,
                ))
                .await
                .unwrap();
            assert_eq!(
                limited_device.headers().get(header::RETRY_AFTER).unwrap(),
                "1"
            );
            assert_json_error(limited_device, StatusCode::TOO_MANY_REQUESTS).await;

            drop(peer_limited);
            drop(device_limited);
            cleanup(&path);
        });
    }

    #[test]
    fn issue9_telemetry_concurrency_saturation_returns_503_and_recovers() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("api-telemetry-concurrency");
            let db = Database::new(&path).await.unwrap();
            let config = ApiRateLimitConfig {
                max_in_flight: 3,
                telemetry_max_in_flight: 1,
                auth_max_in_flight: 1,
                request_timeout_ms: 1_000,
                ..ApiRateLimitConfig::default()
            };
            let app = build_test_router_with_config(db, test_auth_state(), config);

            let (body, body_entered, release_body, feeder) = slow_streaming_body();
            let holding = tokio::spawn(
                app.clone().oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/sysinfo_ver")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(body)
                        .unwrap(),
                ),
            );
            tokio::time::timeout(Duration::from_secs(2), body_entered)
                .await
                .expect("telemetry 慢请求读取阶段等待超时")
                .expect("telemetry 慢请求必须先占有隔舱许可");

            let saturated = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/sysinfo_ver")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(saturated.headers().get(header::RETRY_AFTER).unwrap(), "1");
            assert_json_error(saturated, StatusCode::SERVICE_UNAVAILABLE).await;

            release_body.send(()).unwrap();
            feeder.await.unwrap();
            let holding_response = holding.await.unwrap().unwrap();
            assert_eq!(holding_response.status(), StatusCode::BAD_REQUEST);

            let recovered = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/sysinfo_ver")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_text_response(
                recovered,
                StatusCode::OK,
                &format!("{}-pro", crate::version::VERSION),
            )
            .await;
            cleanup(&path);
        });
    }

    #[test]
    fn issue9_sysinfo_heartbeat_and_version_router_contract_matrix() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            use crate::database::{DeviceUpdate, OwnerScope};

            let path = temp_db_path("api-telemetry-contract");
            let db = Database::new(&path).await.unwrap();
            let password_hash = admin_init::hash_password("secret").unwrap();
            let owner = db
                .create_user("telemetry-owner", &password_hash, None, "user")
                .await
                .unwrap();
            let uuid = vec![5_u8; 16];
            db.insert_peer("telemetry-device", &uuid, b"pk", "{}")
                .await
                .unwrap();
            db.update_managed_device(
                OwnerScope::All,
                "telemetry-device",
                &DeviceUpdate {
                    owner_user_id: Some(Some(owner.id)),
                    ..DeviceUpdate::default()
                },
            )
            .await
            .unwrap();
            let owner_version = db
                .get_address_book_version(owner.id)
                .await
                .unwrap()
                .unwrap();
            let auth_state = test_auth_state();
            let token = crate::auth::jwt::sign_token(
                &owner,
                &auth_state.jwt_secret,
                auth_state.jwt_expiry_hours,
            )
            .unwrap();
            let app = build_test_router(db, auth_state, test_oidc_config());
            let legacy_payload = json!({
                "id": "telemetry-device",
                "uuid": base64::encode(&uuid),
                "future_legacy_field": { "ignored": true }
            });

            for content_type in ["application/json", "text/plain; charset=utf-8"] {
                let response = app
                    .clone()
                    .oneshot(post_request_with_optional_token(
                        "/api/sysinfo",
                        content_type,
                        legacy_payload.to_string(),
                        None,
                    ))
                    .await
                    .unwrap();
                assert_text_response(response, StatusCode::OK, sysinfo::SYSINFO_UPDATED).await;
            }

            let missing_mime = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/sysinfo")
                        .body(Body::from(legacy_payload.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_json_error(missing_mime, StatusCode::UNSUPPORTED_MEDIA_TYPE).await;

            for uri in ["/api/sysinfo", "/api/heartbeat"] {
                let bad_json = app
                    .clone()
                    .oneshot(post_request_with_optional_token(
                        uri,
                        "application/json",
                        "{",
                        None,
                    ))
                    .await
                    .unwrap();
                assert_json_error(bad_json, StatusCode::BAD_REQUEST).await;

                let bad_uuid = app
                    .clone()
                    .oneshot(post_request_with_optional_token(
                        uri,
                        "application/json",
                        json!({
                            "id": "telemetry-device",
                            "uuid": "***"
                        })
                        .to_string(),
                        None,
                    ))
                    .await
                    .unwrap();
                assert_json_error(bad_uuid, StatusCode::BAD_REQUEST).await;
            }

            let bad_mime = app
                .clone()
                .oneshot(post_request_with_optional_token(
                    "/api/sysinfo",
                    "application/xml",
                    legacy_payload.to_string(),
                    None,
                ))
                .await
                .unwrap();
            assert_json_error(bad_mime, StatusCode::UNSUPPORTED_MEDIA_TYPE).await;

            let invalid_token_precedes_mime = app
                .clone()
                .oneshot(post_request_with_optional_token(
                    "/api/sysinfo",
                    "application/xml",
                    legacy_payload.to_string(),
                    Some("invalid"),
                ))
                .await
                .unwrap();
            assert_json_error(invalid_token_precedes_mime, StatusCode::UNAUTHORIZED).await;

            let duplicate_authorization = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/heartbeat")
                        .header(header::CONTENT_TYPE, "application/json")
                        .header(header::AUTHORIZATION, format!("Bearer {token}"))
                        .header(header::AUTHORIZATION, format!("Bearer {token}"))
                        .body(Body::from(legacy_payload.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_json_error(duplicate_authorization, StatusCode::UNAUTHORIZED).await;

            let unauthenticated_cursor = app
                .clone()
                .oneshot(post_request_with_optional_token(
                    "/api/sysinfo",
                    "application/json",
                    json!({
                        "id": "telemetry-device",
                        "uuid": base64::encode(&uuid),
                        "ab_ver": owner_version
                    })
                    .to_string(),
                    None,
                ))
                .await
                .unwrap();
            assert_json_error(unauthenticated_cursor, StatusCode::UNAUTHORIZED).await;

            let authenticated_without_cursor = app
                .clone()
                .oneshot(post_request_with_optional_token(
                    "/api/sysinfo",
                    "application/json",
                    legacy_payload.to_string(),
                    Some(&token),
                ))
                .await
                .unwrap();
            assert_json_error(authenticated_without_cursor, StatusCode::BAD_REQUEST).await;

            let unchanged = app
                .clone()
                .oneshot(post_request_with_optional_token(
                    "/api/sysinfo",
                    "application/json",
                    json!({
                        "id": "telemetry-device",
                        "uuid": base64::encode(&uuid),
                        "ab_ver": owner_version,
                        "address_book_json": true
                    })
                    .to_string(),
                    Some(&token),
                ))
                .await
                .unwrap();
            assert_eq!(unchanged.status(), StatusCode::NO_CONTENT);
            assert!(unchanged.headers().get(header::CONTENT_TYPE).is_none());
            assert!(read_body(unchanged.into_body()).await.is_empty());

            let changed_json = app
                .clone()
                .oneshot(post_request_with_optional_token(
                    "/api/sysinfo",
                    "application/json",
                    json!({
                        "id": "telemetry-device",
                        "uuid": base64::encode(&uuid),
                        "ab_ver": 0,
                        "address_book_json": true
                    })
                    .to_string(),
                    Some(&token),
                ))
                .await
                .unwrap();
            assert_eq!(changed_json.status(), StatusCode::OK);
            assert_content_type(&changed_json, "application/json");
            let changed_json_body: Value =
                serde_json::from_slice(&read_body(changed_json.into_body()).await).unwrap();
            assert_eq!(changed_json_body["status"], sysinfo::SYSINFO_UPDATED);
            assert_eq!(changed_json_body["address_book"]["mode"], "delta");
            assert_eq!(changed_json_body["address_book"]["ab_ver"], owner_version);

            let changed_text = app
                .clone()
                .oneshot(post_request_with_optional_token(
                    "/api/sysinfo",
                    "text/plain",
                    json!({
                        "id": "telemetry-device",
                        "uuid": base64::encode(&uuid),
                        "ab_ver": 0
                    })
                    .to_string(),
                    Some(&token),
                ))
                .await
                .unwrap();
            assert_text_response(changed_text, StatusCode::OK, sysinfo::SYSINFO_UPDATED).await;

            let legacy_heartbeat = app
                .clone()
                .oneshot(post_request_with_optional_token(
                    "/api/heartbeat",
                    "text/plain",
                    legacy_payload.to_string(),
                    None,
                ))
                .await
                .unwrap();
            assert_eq!(legacy_heartbeat.status(), StatusCode::OK);
            assert_content_type(&legacy_heartbeat, "application/json");
            let legacy_heartbeat_body: Value =
                serde_json::from_slice(&read_body(legacy_heartbeat.into_body()).await).unwrap();
            assert_eq!(legacy_heartbeat_body, json!({ "sysinfo": true }));

            let unchanged_heartbeat = app
                .clone()
                .oneshot(post_request_with_optional_token(
                    "/api/heartbeat",
                    "application/json",
                    json!({
                        "id": "telemetry-device",
                        "uuid": base64::encode(&uuid),
                        "ab_ver": owner_version
                    })
                    .to_string(),
                    Some(&token),
                ))
                .await
                .unwrap();
            assert_eq!(unchanged_heartbeat.status(), StatusCode::OK);
            assert_content_type(&unchanged_heartbeat, "application/json");
            let unchanged_heartbeat_body: Value =
                serde_json::from_slice(&read_body(unchanged_heartbeat.into_body()).await).unwrap();
            assert_eq!(unchanged_heartbeat_body, json!({}));

            let future_cursor = owner_version + 1;
            let future_cursor_collision = app
                .clone()
                .oneshot(post_request_with_optional_token(
                    "/api/sysinfo",
                    "application/json",
                    json!({
                        "id": "telemetry-device",
                        "uuid": base64::encode(&uuid),
                        "hostname": "future-collision-host",
                        "ab_ver": future_cursor,
                        "address_book_json": true
                    })
                    .to_string(),
                    Some(&token),
                ))
                .await
                .unwrap();
            assert_eq!(future_cursor_collision.status(), StatusCode::OK);
            assert_content_type(&future_cursor_collision, "application/json");
            let future_cursor_collision_body: Value =
                serde_json::from_slice(&read_body(future_cursor_collision.into_body()).await)
                    .unwrap();
            assert_eq!(
                future_cursor_collision_body["address_book"]["ab_ver"],
                future_cursor
            );
            assert_eq!(
                future_cursor_collision_body["address_book"]["next_ab_ver"],
                future_cursor
            );
            assert_eq!(
                future_cursor_collision_body["address_book"]["reset_required"],
                true
            );
            assert!(future_cursor_collision_body["address_book"]["changes"]
                .as_array()
                .is_some_and(|changes| !changes.is_empty()));

            let text_future_cursor = future_cursor + 1;
            let text_future_cursor_collision = app
                .clone()
                .oneshot(post_request_with_optional_token(
                    "/api/sysinfo",
                    "application/json",
                    json!({
                        "id": "telemetry-device",
                        "uuid": base64::encode(&uuid),
                        "hostname": "future-collision-text-host",
                        "ab_ver": text_future_cursor
                    })
                    .to_string(),
                    Some(&token),
                ))
                .await
                .unwrap();
            assert_text_response(
                text_future_cursor_collision,
                StatusCode::OK,
                sysinfo::SYSINFO_UPDATED,
            )
            .await;

            let full_after_text_sentinel = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/api/ab?page=1&page_size=50")
                        .header(header::AUTHORIZATION, format!("Bearer {token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(full_after_text_sentinel.status(), StatusCode::OK);
            let full_after_text_sentinel_body: Value =
                serde_json::from_slice(&read_body(full_after_text_sentinel.into_body()).await)
                    .unwrap();
            assert_eq!(full_after_text_sentinel_body["ab_ver"], text_future_cursor);
            assert_eq!(
                full_after_text_sentinel_body["items"][0]["hostname"],
                "future-collision-text-host"
            );

            let missing_device = app
                .clone()
                .oneshot(post_request_with_optional_token(
                    "/api/sysinfo",
                    "application/json",
                    json!({
                        "id": "missing-device",
                        "uuid": base64::encode(&uuid)
                    })
                    .to_string(),
                    None,
                ))
                .await
                .unwrap();
            assert_text_response(missing_device, StatusCode::OK, sysinfo::ID_NOT_FOUND).await;

            for content_type in [None, Some("application/json"), Some("text/plain")] {
                let mut builder = Request::builder().method("POST").uri("/api/sysinfo_ver");
                if let Some(content_type) = content_type {
                    builder = builder.header(header::CONTENT_TYPE, content_type);
                }
                let response = app
                    .clone()
                    .oneshot(builder.body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                assert_text_response(
                    response,
                    StatusCode::OK,
                    &format!("{}-pro", crate::version::VERSION),
                )
                .await;
            }

            let bad_version_mime = app
                .clone()
                .oneshot(post_request_with_optional_token(
                    "/api/sysinfo_ver",
                    "application/xml",
                    "",
                    None,
                ))
                .await
                .unwrap();
            assert_json_error(bad_version_mime, StatusCode::UNSUPPORTED_MEDIA_TYPE).await;

            let nonempty_version_body = app
                .oneshot(post_request_with_optional_token(
                    "/api/sysinfo_ver",
                    "application/json",
                    "{}",
                    None,
                ))
                .await
                .unwrap();
            assert_json_error(nonempty_version_body, StatusCode::BAD_REQUEST).await;
            cleanup(&path);
        });
    }

    #[test]
    fn issue9_sysinfo_maps_database_busy_to_retryable_503_and_recovers() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            use crate::database::{DeviceUpdate, OwnerScope};

            let path = temp_db_path("api-sysinfo-busy");
            let holder_db = Database::new(&path).await.unwrap();
            let password_hash = admin_init::hash_password("secret").unwrap();
            let owner = holder_db
                .create_user("busy-owner", &password_hash, None, "user")
                .await
                .unwrap();
            let uuid = vec![6_u8; 16];
            holder_db
                .insert_peer("busy-device", &uuid, b"pk", "{}")
                .await
                .unwrap();
            holder_db
                .update_managed_device(
                    OwnerScope::All,
                    "busy-device",
                    &DeviceUpdate {
                        owner_user_id: Some(Some(owner.id)),
                        ..DeviceUpdate::default()
                    },
                )
                .await
                .unwrap();
            let owner_version = holder_db
                .get_address_book_version(owner.id)
                .await
                .unwrap()
                .unwrap();
            let auth_state = test_auth_state();
            let token = crate::auth::jwt::sign_token(
                &owner,
                &auth_state.jwt_secret,
                auth_state.jwt_expiry_hours,
            )
            .unwrap();
            let request_db = Database::new(&path).await.unwrap();
            let app = build_test_router(request_db, auth_state, test_oidc_config());
            let body = json!({
                "id": "busy-device",
                "uuid": base64::encode(&uuid),
                "hostname": "hostname-after-retry",
                "ab_ver": owner_version,
                "address_book_json": true
            })
            .to_string();

            let (acquired_tx, acquired_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = tokio::sync::oneshot::channel();
            let holder = {
                let holder_db = holder_db.clone();
                tokio::spawn(async move {
                    holder_db
                        .hold_inventory_write_lock_for_test(acquired_tx, release_rx)
                        .await
                })
            };
            tokio::time::timeout(Duration::from_secs(2), acquired_rx)
                .await
                .expect("测试库存写锁获取超时")
                .expect("测试库存写锁必须成功获取");

            let busy = app
                .clone()
                .oneshot(post_request_with_optional_token(
                    "/api/sysinfo",
                    "application/json",
                    body.clone(),
                    Some(&token),
                ))
                .await
                .unwrap();
            assert_eq!(busy.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(busy.headers().get(header::RETRY_AFTER).unwrap(), "1");
            assert_json_error(busy, StatusCode::SERVICE_UNAVAILABLE).await;

            release_tx.send(()).unwrap();
            holder.await.unwrap().unwrap();

            let recovered = app
                .oneshot(post_request_with_optional_token(
                    "/api/sysinfo",
                    "application/json",
                    body,
                    Some(&token),
                ))
                .await
                .unwrap();
            assert_eq!(recovered.status(), StatusCode::OK);
            assert_content_type(&recovered, "application/json");
            cleanup(&path);
        });
    }

    #[test]
    fn issue9_telemetry_router_rejects_stale_accounts_and_cookie_only_authentication() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("api-telemetry-auth-rejections");
            let db = Database::new(&path).await.unwrap();
            let password_hash = admin_init::hash_password("secret").unwrap();
            let expired_user = db
                .create_user("expired-user", &password_hash, None, "user")
                .await
                .unwrap();
            let inactive_user = db
                .create_user("inactive-user", &password_hash, None, "user")
                .await
                .unwrap();
            let revoked_user = db
                .create_user("revoked-user", &password_hash, None, "user")
                .await
                .unwrap();
            let unknown_role_user = db
                .create_user("unknown-role-user", &password_hash, None, "unknown")
                .await
                .unwrap();
            let cookie_user = db
                .create_user("cookie-user", &password_hash, None, "user")
                .await
                .unwrap();
            let auth_state = test_auth_state();
            let expired_token =
                crate::auth::jwt::sign_token(&expired_user, &auth_state.jwt_secret, -1).unwrap();
            let inactive_token = crate::auth::jwt::sign_token(
                &inactive_user,
                &auth_state.jwt_secret,
                auth_state.jwt_expiry_hours,
            )
            .unwrap();
            let revoked_token = crate::auth::jwt::sign_token(
                &revoked_user,
                &auth_state.jwt_secret,
                auth_state.jwt_expiry_hours,
            )
            .unwrap();
            let unknown_role_token = crate::auth::jwt::sign_token(
                &unknown_role_user,
                &auth_state.jwt_secret,
                auth_state.jwt_expiry_hours,
            )
            .unwrap();
            let cookie_token = crate::auth::jwt::sign_token(
                &cookie_user,
                &auth_state.jwt_secret,
                auth_state.jwt_expiry_hours,
            )
            .unwrap();
            db.deactivate_user(inactive_user.id).await.unwrap();
            db.increment_token_version(revoked_user.id).await.unwrap();
            let app = build_test_router(db, auth_state, test_oidc_config());
            let body = json!({
                "id": "auth-rejection-device",
                "uuid": base64::encode("uuid"),
                "ab_ver": 0
            })
            .to_string();

            for (token, expected) in [
                (expired_token.as_str(), StatusCode::UNAUTHORIZED),
                (inactive_token.as_str(), StatusCode::UNAUTHORIZED),
                (revoked_token.as_str(), StatusCode::UNAUTHORIZED),
                (unknown_role_token.as_str(), StatusCode::FORBIDDEN),
            ] {
                let response = app
                    .clone()
                    .oneshot(post_request_with_optional_token(
                        "/api/heartbeat",
                        "application/json",
                        body.clone(),
                        Some(token),
                    ))
                    .await
                    .unwrap();
                assert_json_error(response, expected).await;
            }

            let cookie_only = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/heartbeat")
                        .header(header::CONTENT_TYPE, "application/json")
                        .header(header::COOKIE, format!("access_token={cookie_token}"))
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_json_error(cookie_only, StatusCode::UNAUTHORIZED).await;
            cleanup(&path);
        });
    }

    #[test]
    fn test_license_usage_requires_admin_and_returns_status_breakdown() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("license-usage");
            let db = Database::new(&path).await.unwrap();
            let password_hash = admin_init::hash_password("secret").unwrap();
            db.create_user("admin", &password_hash, None, "admin")
                .await
                .unwrap();
            db.create_user("ordinary", &password_hash, None, "user")
                .await
                .unwrap();
            db.insert_peer("usage-online", b"uuid-1", b"pk-1", "{}")
                .await
                .unwrap();
            db.insert_peer("usage-inactive", b"uuid-2", b"pk-2", "{}")
                .await
                .unwrap();
            db.set_device_inactive("usage-inactive").await.unwrap();
            let app = build_test_router(db, test_auth_state(), test_oidc_config());

            let unauthorized = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/api/license/usage")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

            let user_token = login_access_token(&app, "ordinary", "secret").await;
            let forbidden = app
                .clone()
                .oneshot(authenticated_request(
                    "GET",
                    "/api/license/usage",
                    &user_token,
                ))
                .await
                .unwrap();
            assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

            let admin_token = login_access_token(&app, "admin", "secret").await;
            let response = app
                .oneshot(authenticated_request(
                    "GET",
                    "/api/license/usage",
                    &admin_token,
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body: Value =
                serde_json::from_slice(&read_body(response.into_body()).await).unwrap();
            assert_eq!(body["online_devices"], 0);
            assert_eq!(body["offline_devices"], 1);
            assert_eq!(body["inactive_devices"], 1);
            assert_eq!(body["current_devices"], 1);
            assert!(body.get("expires_at").is_some());
            assert!(body.get("days_remaining").is_some());
            cleanup(&path);
        });
    }

    #[test]
    fn test_device_inactive_503_is_retryable_and_retry_resends_command() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("device-inactive-retry");
            let db = Database::new(&path).await.unwrap();
            let password_hash = admin_init::hash_password("secret").unwrap();
            db.create_user("admin", &password_hash, None, "admin")
                .await
                .unwrap();
            db.insert_peer("device-retry", b"uuid", b"pk", "{}")
                .await
                .unwrap();

            let (closed_tx, closed_rx) =
                tokio::sync::mpsc::channel(DEVICE_INVALIDATION_CHANNEL_CAPACITY);
            drop(closed_rx);
            let failed_app =
                build_router(db.clone(), test_auth_state(), test_oidc_config(), closed_tx);
            let token = login_access_token(&failed_app, "admin", "secret").await;
            let failed = failed_app
                .oneshot(authenticated_request(
                    "POST",
                    "/api/license/devices/device-retry/inactive",
                    &token,
                ))
                .await
                .unwrap();
            assert_eq!(failed.status(), StatusCode::SERVICE_UNAVAILABLE);
            let failed_body: Value =
                serde_json::from_slice(&read_body(failed.into_body()).await).unwrap();
            assert_eq!(failed_body["database_inactive_committed"], true);
            assert_eq!(failed_body["retryable"], true);
            assert!(db.is_device_inactive("device-retry").await.unwrap());

            let (tx, mut rx) = tokio::sync::mpsc::channel(DEVICE_INVALIDATION_CHANNEL_CAPACITY);
            let retry_app = build_router(db, test_auth_state(), test_oidc_config(), tx);
            let controller = tokio::spawn(async move {
                let command = rx.recv().await.unwrap();
                assert_eq!(command.device_id, "device-retry");
                command
                    .ack
                    .send(Ok(crate::peer::InvalidationResult::AlreadyAbsent))
                    .unwrap();
            });
            let retried = retry_app
                .oneshot(authenticated_request(
                    "POST",
                    "/api/license/devices/device-retry/inactive",
                    &token,
                ))
                .await
                .unwrap();
            controller.await.unwrap();
            assert_eq!(retried.status(), StatusCode::OK);
            cleanup(&path);
        });
    }

    #[test]
    fn test_device_inactive_ack_timeout_is_two_seconds() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("device-inactive-timeout");
            let db = Database::new(&path).await.unwrap();
            let password_hash = admin_init::hash_password("secret").unwrap();
            db.create_user("admin", &password_hash, None, "admin")
                .await
                .unwrap();
            db.insert_peer("device-timeout", b"uuid", b"pk", "{}")
                .await
                .unwrap();
            let (tx, mut rx) = tokio::sync::mpsc::channel(DEVICE_INVALIDATION_CHANNEL_CAPACITY);
            let app = build_router(db, test_auth_state(), test_oidc_config(), tx);
            let token = login_access_token(&app, "admin", "secret").await;
            let controller = tokio::spawn(async move {
                let command = rx.recv().await.unwrap();
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                drop(command);
            });
            let started = std::time::Instant::now();
            let response = app
                .oneshot(authenticated_request(
                    "POST",
                    "/api/license/devices/device-timeout/inactive",
                    &token,
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert!(started.elapsed() >= std::time::Duration::from_secs(2));
            assert!(started.elapsed() < std::time::Duration::from_secs(3));
            controller.abort();
            cleanup(&path);
        });
    }

    #[test]
    fn test_login_refresh_and_logout_flow() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("api-auth-flow");
            let db = Database::new(&path).await.unwrap();
            let password_hash = admin_init::hash_password("secret").unwrap();
            db.create_user("admin", &password_hash, None, "admin")
                .await
                .unwrap();

            let app = build_test_router(db, test_auth_state(), test_oidc_config());
            let login_response = app
                .clone()
                .oneshot(json_request(
                    "/api/auth/login",
                    json!({ "username": "admin", "password": "secret" }),
                ))
                .await
                .unwrap();
            assert_eq!(login_response.status(), StatusCode::OK);
            let login_body: Value =
                serde_json::from_slice(&read_body(login_response.into_body()).await).unwrap();
            let access_token = login_body["access_token"].as_str().unwrap().to_string();
            let refresh_token = login_body["refresh_token"].as_str().unwrap().to_string();

            let access_as_refresh_response = app
                .clone()
                .oneshot(json_request(
                    "/api/auth/refresh",
                    json!({ "refresh_token": access_token.clone() }),
                ))
                .await
                .unwrap();
            assert_eq!(
                access_as_refresh_response.status(),
                StatusCode::UNAUTHORIZED
            );

            let refresh_response = app
                .clone()
                .oneshot(json_request(
                    "/api/auth/refresh",
                    json!({ "refresh_token": refresh_token.clone() }),
                ))
                .await
                .unwrap();
            assert_eq!(refresh_response.status(), StatusCode::OK);

            let refresh_as_access_response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/api/users")
                        .header(header::AUTHORIZATION, format!("Bearer {}", refresh_token))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                refresh_as_access_response.status(),
                StatusCode::UNAUTHORIZED
            );

            let logout_response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/auth/logout")
                        .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(logout_response.status(), StatusCode::NO_CONTENT);

            let revoked_refresh_response = app
                .oneshot(json_request(
                    "/api/auth/refresh",
                    json!({ "refresh_token": refresh_token }),
                ))
                .await
                .unwrap();
            assert_eq!(revoked_refresh_response.status(), StatusCode::UNAUTHORIZED);
            cleanup(&path);
        });
    }

    #[test]
    fn test_refresh_with_cookie_and_empty_body() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("api-cookie-refresh");
            let db = Database::new(&path).await.unwrap();
            let password_hash = admin_init::hash_password("secret").unwrap();
            db.create_user("admin", &password_hash, None, "admin")
                .await
                .unwrap();

            let app = build_test_router(db, test_auth_state(), test_oidc_config());
            let cookie_header = login_cookie_header(&app).await;
            let response = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/auth/refresh")
                        .header(header::COOKIE, cookie_header)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::OK);
            let body: Value =
                serde_json::from_slice(&read_body(response.into_body()).await).unwrap();
            assert!(body["access_token"].as_str().is_some());
            cleanup(&path);
        });
    }

    #[test]
    fn test_refresh_cookie_csrf_missing_origin_returns_403() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (app, cookie_header, path) = app_with_cross_origin_cookie().await;
            let response = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/auth/refresh")
                        .header(header::COOKIE, cookie_header)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            cleanup(&path);
        });
    }

    #[test]
    fn test_refresh_cookie_csrf_allowed_origin_passes() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (app, cookie_header, path) = app_with_cross_origin_cookie().await;
            let response = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/auth/refresh")
                        .header(header::COOKIE, cookie_header)
                        .header(header::ORIGIN, "https://console.example.com")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::OK);
            cleanup(&path);
        });
    }

    #[test]
    fn test_refresh_cookie_csrf_invalid_origin_returns_403() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (app, cookie_header, path) = app_with_cross_origin_cookie().await;
            let response = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/auth/refresh")
                        .header(header::COOKIE, cookie_header)
                        .header(header::ORIGIN, "https://evil.example.com")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            cleanup(&path);
        });
    }

    #[test]
    fn test_cookie_csrf_missing_origin_returns_403() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (app, cookie_header, path) = app_with_cross_origin_cookie().await;
            let response = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/auth/logout")
                        .header(header::COOKIE, cookie_header)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            cleanup(&path);
        });
    }

    #[test]
    fn test_cookie_csrf_allowed_origin_passes() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (app, cookie_header, path) = app_with_cross_origin_cookie().await;
            let response = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/auth/logout")
                        .header(header::COOKIE, cookie_header)
                        .header(header::ORIGIN, "https://console.example.com")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            cleanup(&path);
        });
    }

    #[test]
    fn test_cookie_csrf_invalid_origin_returns_403() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (app, cookie_header, path) = app_with_cross_origin_cookie().await;
            let response = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/auth/logout")
                        .header(header::COOKIE, cookie_header)
                        .header(header::ORIGIN, "https://evil.example.com")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            cleanup(&path);
        });
    }

    #[test]
    fn test_oidc_login_not_configured() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("api-oidc-login-not-configured");
            let db = Database::new(&path).await.unwrap();
            let response = build_test_router(db, test_auth_state(), test_oidc_config())
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/api/auth/oidc/login")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            let body: Value =
                serde_json::from_slice(&read_body(response.into_body()).await).unwrap();
            assert_eq!(body, json!({ "error": "OIDC not configured" }));
            cleanup(&path);
        });
    }

    #[test]
    fn test_oidc_callback_not_configured_redirects() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("api-oidc-callback-not-configured");
            let db = Database::new(&path).await.unwrap();
            let oidc_config = OidcConfig {
                post_login_url: "https://console.example.com/dashboard".to_string(),
                ..OidcConfig::default()
            };
            let response = build_test_router(db, test_auth_state(), oidc_config)
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/api/auth/oidc/callback")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::FOUND);
            assert_eq!(
                response.headers().get(header::LOCATION).unwrap(),
                "https://console.example.com/dashboard?error=oidc_not_configured"
            );
            cleanup(&path);
        });
    }

    #[test]
    fn test_oidc_callback_missing_params() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("api-oidc-callback-missing-params");
            let db = Database::new(&path).await.unwrap();
            let response = build_test_router(db, test_auth_state(), test_configured_oidc_config())
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/api/auth/oidc/callback")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_oidc_redirect(&response, "invalid_request");
            cleanup(&path);
        });
    }

    #[test]
    fn test_oidc_callback_invalid_state() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("api-oidc-callback-invalid-state");
            let db = Database::new(&path).await.unwrap();
            let response = build_test_router(db, test_auth_state(), test_configured_oidc_config())
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/api/auth/oidc/callback?code=abc&state=missing")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_oidc_redirect(&response, "expired_session");
            cleanup(&path);
        });
    }

    #[test]
    fn test_oidc_callback_expired_state() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("api-oidc-callback-expired-state");
            let db = Database::new(&path).await.unwrap();
            let state = unique_name("expired-state");
            crate::auth::OIDC_SESSIONS.insert_expired(
                state.clone(),
                "verifier".to_string(),
                "nonce".to_string(),
            );
            let uri = format!("/api/auth/oidc/callback?code=abc&state={state}");
            let response = build_test_router(db, test_auth_state(), test_configured_oidc_config())
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(uri)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_oidc_redirect(&response, "expired_session");
            cleanup(&path);
        });
    }

    #[test]
    fn test_client_alias_header_only_login_current_user_and_logout() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("api-client-alias");
            let db = Database::new(&path).await.unwrap();
            let password_hash = admin_init::hash_password("secret").unwrap();
            let user = db
                .create_user("alias-user", &password_hash, None, "user")
                .await
                .unwrap();
            let app = build_test_router(db, test_auth_state(), test_oidc_config());

            let login = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/login")
                        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                        .body(Body::from(
                            json!({
                                "username": "alias-user",
                                "password": "secret",
                                "type": "account"
                            })
                            .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(login.status(), StatusCode::OK);
            let login_body: Value =
                serde_json::from_slice(&read_body(login.into_body()).await).unwrap();
            assert_eq!(login_body["user"]["id"], user.id);
            let token = login_body["access_token"].as_str().unwrap();

            let current = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/currentUser")
                        .header(header::AUTHORIZATION, format!("Bearer {token}"))
                        .header(header::COOKIE, "access_token=wrong-cookie")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(current.status(), StatusCode::OK);

            let logout = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/logout")
                        .header(header::AUTHORIZATION, format!("Bearer {token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(logout.status(), StatusCode::NO_CONTENT);

            let revoked = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/currentUser")
                        .header(header::AUTHORIZATION, format!("Bearer {token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(revoked.status(), StatusCode::UNAUTHORIZED);
            cleanup(&path);
        });
    }

    #[test]
    fn issue9_header_only_routes_reject_cookie_fallback_and_bind_bearer_identity() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            use crate::database::{DeviceUpdate, OwnerScope};

            let path = temp_db_path("api-header-only-matrix");
            let db = Database::new(&path).await.unwrap();
            let password_hash = admin_init::hash_password("secret").unwrap();
            let bearer_user = db
                .create_user("bearer-user", &password_hash, None, "user")
                .await
                .unwrap();
            db.create_user("cookie-user", &password_hash, None, "user")
                .await
                .unwrap();
            db.insert_peer("bearer-device", &[9_u8; 16], b"pk", "{}")
                .await
                .unwrap();
            db.update_managed_device(
                OwnerScope::All,
                "bearer-device",
                &DeviceUpdate {
                    owner_user_id: Some(Some(bearer_user.id)),
                    ..DeviceUpdate::default()
                },
            )
            .await
            .unwrap();

            let app = build_test_router(db, test_auth_state(), test_oidc_config());
            let bearer_token = login_access_token(&app, "bearer-user", "secret").await;
            let cookie_token = login_access_token(&app, "cookie-user", "secret").await;

            let cookie_only_routes = [
                ("GET", "/api/ab?page=1&page_size=50"),
                ("GET", "/api/ab/pending"),
                ("POST", "/api/ab/share/bearer-device"),
                (
                    "DELETE",
                    "/api/ab/share/bearer-device?to_username=cookie-user",
                ),
                ("POST", "/api/ab/accept/1"),
                ("POST", "/api/ab/reject/1"),
                ("POST", "/api/currentUser"),
                ("POST", "/api/logout"),
            ];
            for (method, uri) in cookie_only_routes {
                let response = app
                    .clone()
                    .oneshot(header_only_test_request(
                        method,
                        uri,
                        &[],
                        Some(&cookie_token),
                    ))
                    .await
                    .unwrap();
                assert_eq!(
                    response.status(),
                    StatusCode::UNAUTHORIZED,
                    "{method} {uri}"
                );
            }

            let invalid_authorization = [
                ("empty", vec!["Bearer ".to_owned()]),
                ("bad", vec!["Bearer not-a-jwt".to_owned()]),
                (
                    "duplicate",
                    vec![
                        format!("Bearer {bearer_token}"),
                        format!("Bearer {cookie_token}"),
                    ],
                ),
            ];
            for (method, uri) in [
                ("GET", "/api/ab?page=1&page_size=50"),
                ("POST", "/api/currentUser"),
                ("POST", "/api/logout"),
            ] {
                for (case, authorization) in &invalid_authorization {
                    let response = app
                        .clone()
                        .oneshot(header_only_test_request(
                            method,
                            uri,
                            authorization,
                            Some(&cookie_token),
                        ))
                        .await
                        .unwrap();
                    assert_eq!(
                        response.status(),
                        StatusCode::UNAUTHORIZED,
                        "{method} {uri}: {case}"
                    );
                }
            }

            let bearer_header = [format!("Bearer {bearer_token}")];
            let current = app
                .clone()
                .oneshot(header_only_test_request(
                    "POST",
                    "/api/currentUser",
                    &bearer_header,
                    Some(&cookie_token),
                ))
                .await
                .unwrap();
            assert_eq!(current.status(), StatusCode::OK);
            let current_body: Value =
                serde_json::from_slice(&read_body(current.into_body()).await).unwrap();
            assert_eq!(current_body["id"], bearer_user.id);

            let address_book = app
                .clone()
                .oneshot(header_only_test_request(
                    "GET",
                    "/api/ab?page=1&page_size=50",
                    &bearer_header,
                    Some(&cookie_token),
                ))
                .await
                .unwrap();
            assert_eq!(address_book.status(), StatusCode::OK);
            let address_book_body: Value =
                serde_json::from_slice(&read_body(address_book.into_body()).await).unwrap();
            assert_eq!(address_book_body["items"][0]["device_id"], "bearer-device");

            let logout = app
                .clone()
                .oneshot(header_only_test_request(
                    "POST",
                    "/api/logout",
                    &bearer_header,
                    Some(&cookie_token),
                ))
                .await
                .unwrap();
            assert_eq!(logout.status(), StatusCode::NO_CONTENT);

            let revoked_bearer = app
                .clone()
                .oneshot(authenticated_request(
                    "POST",
                    "/api/currentUser",
                    &bearer_token,
                ))
                .await
                .unwrap();
            assert_eq!(revoked_bearer.status(), StatusCode::UNAUTHORIZED);
            let cookie_user_still_current = app
                .oneshot(authenticated_request(
                    "POST",
                    "/api/currentUser",
                    &cookie_token,
                ))
                .await
                .unwrap();
            assert_eq!(cookie_user_still_current.status(), StatusCode::OK);
            cleanup(&path);
        });
    }

    #[test]
    fn test_address_book_and_sysinfo_routes_end_to_end() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            use crate::database::{DeviceUpdate, OwnerScope};

            let path = temp_db_path("api-address-book");
            let db = Database::new(&path).await.unwrap();
            let password_hash = admin_init::hash_password("secret").unwrap();
            let owner = db
                .create_user("owner", &password_hash, None, "user")
                .await
                .unwrap();
            db.create_user("recipient", &password_hash, None, "user")
                .await
                .unwrap();
            db.create_user("viewer", &password_hash, None, "viewer")
                .await
                .unwrap();
            let uuid = vec![7_u8; 16];
            db.insert_peer("device-1", &uuid, b"pk", "{}")
                .await
                .unwrap();
            db.update_managed_device(
                OwnerScope::All,
                "device-1",
                &DeviceUpdate {
                    owner_user_id: Some(Some(owner.id)),
                    ..DeviceUpdate::default()
                },
            )
            .await
            .unwrap();

            let app = build_test_router(db, test_auth_state(), test_oidc_config());
            let owner_token = login_access_token(&app, "owner", "secret").await;
            let recipient_token = login_access_token(&app, "recipient", "secret").await;
            let viewer_token = login_access_token(&app, "viewer", "secret").await;

            let viewer_share = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/ab/share/device-1")
                        .header(header::AUTHORIZATION, format!("Bearer {viewer_token}"))
                        .body(Body::from("{"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(viewer_share.status(), StatusCode::FORBIDDEN);
            for (method, uri) in [
                ("DELETE", "/api/ab/share/device-1?to_username"),
                ("POST", "/api/ab/accept/not-a-number"),
                ("POST", "/api/ab/reject/not-a-number"),
            ] {
                let viewer_malformed = app
                    .clone()
                    .oneshot(authenticated_request(method, uri, &viewer_token))
                    .await
                    .unwrap();
                assert_eq!(
                    viewer_malformed.status(),
                    StatusCode::FORBIDDEN,
                    "{method} {uri}"
                );
            }

            let full = app
                .clone()
                .oneshot(authenticated_request(
                    "GET",
                    "/api/ab?page=1&page_size=50",
                    &owner_token,
                ))
                .await
                .unwrap();
            assert_eq!(full.status(), StatusCode::OK);
            let full_body: Value =
                serde_json::from_slice(&read_body(full.into_body()).await).unwrap();
            assert_eq!(full_body["mode"], "full");
            assert_eq!(full_body["items"][0]["device_id"], "device-1");
            let owner_version = full_body["ab_ver"].as_i64().unwrap();

            let share = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/ab/share/device-1")
                        .header(header::AUTHORIZATION, format!("Bearer {owner_token}"))
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(
                            json!({
                                "to_username": "recipient",
                                "permission": "view_only"
                            })
                            .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(share.status(), StatusCode::CREATED);
            let share_body: Value =
                serde_json::from_slice(&read_body(share.into_body()).await).unwrap();
            let share_id = share_body["id"].as_i64().unwrap();

            let accept = app
                .clone()
                .oneshot(authenticated_request(
                    "POST",
                    &format!("/api/ab/accept/{share_id}"),
                    &recipient_token,
                ))
                .await
                .unwrap();
            assert_eq!(accept.status(), StatusCode::OK);

            let delta = app
                .clone()
                .oneshot(authenticated_request(
                    "GET",
                    "/api/ab?ab_ver=0&page_size=50",
                    &recipient_token,
                ))
                .await
                .unwrap();
            assert_eq!(delta.status(), StatusCode::OK);
            assert_eq!(
                delta
                    .headers()
                    .get(header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok()),
                Some("application/json; charset=utf-8")
            );
            let delta_body: Value =
                serde_json::from_slice(&read_body(delta.into_body()).await).unwrap();
            assert_eq!(delta_body["changes"][0]["item"]["source"], "shared");

            let sysinfo = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/sysinfo")
                        .header(header::AUTHORIZATION, format!("Bearer {owner_token}"))
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(
                            json!({
                                "id": "device-1",
                                "uuid": base64::encode(uuid),
                                "ab_ver": owner_version,
                                "address_book_json": true
                            })
                            .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(sysinfo.status(), StatusCode::NO_CONTENT);
            cleanup(&path);
        });
    }

    #[test]
    fn issue11_login_lockout_is_atomic_and_audited() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("api-issue11-lockout");
            let db = Database::new(&path).await.unwrap();
            let password_hash = admin_init::hash_password("correct-password").unwrap();
            db.create_user("locked-user", &password_hash, None, "user")
                .await
                .unwrap();
            let app = build_test_router(db.clone(), test_auth_state(), test_oidc_config());

            for attempt in 1..=5 {
                let response = app
                    .clone()
                    .oneshot(json_request(
                        "/api/auth/login",
                        json!({ "username": "locked-user", "password": "wrong-password" }),
                    ))
                    .await
                    .unwrap();
                if attempt < 5 {
                    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
                } else {
                    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
                    assert!(response.headers().get(header::RETRY_AFTER).is_some());
                }
            }

            let locked = db
                .find_user_by_username("locked-user")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(locked.failed_login_count, 5);
            assert!(locked.locked_until.is_some());

            let response = app
                .clone()
                .oneshot(json_request(
                    "/api/auth/login",
                    json!({ "username": "locked-user", "password": "correct-password" }),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

            let mut locked_events = 0;
            for _ in 0..40 {
                let (_, total) = db
                    .list_audit_logs(&crate::audit::AuditLogFilter {
                        action: Some("auth.login.locked".to_string()),
                        page: 1,
                        page_size: 50,
                        ..crate::audit::AuditLogFilter::default()
                    })
                    .await
                    .unwrap();
                locked_events = total;
                if locked_events >= 2 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            assert!(locked_events >= 2);
            drop(app);
            drop(db);
            cleanup(&path);
        });
    }

    #[test]
    fn issue11_security_policy_and_audit_api_work_end_to_end() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("api-issue11-policy-audit");
            let db = Database::new(&path).await.unwrap();
            let password_hash = admin_init::hash_password("secret").unwrap();
            db.create_user("admin", &password_hash, None, "admin")
                .await
                .unwrap();
            db.create_user("ordinary", &password_hash, None, "user")
                .await
                .unwrap();
            let app = build_test_router(db.clone(), test_auth_state(), test_oidc_config());
            let admin_token = login_access_token(&app, "admin", "secret").await;
            let ordinary_token = login_access_token(&app, "ordinary", "secret").await;

            let forbidden = app
                .clone()
                .oneshot(authenticated_request(
                    "GET",
                    "/api/audit-logs",
                    &ordinary_token,
                ))
                .await
                .unwrap();
            assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

            let policy = json!({
                "password_min_length": 12,
                "password_require_number": true,
                "password_require_symbol": true,
                "login_max_failures": 5,
                "login_lock_minutes": 15,
                "session_timeout_minutes": 1,
                "allowed_admin_cidrs": ["127.0.0.1/32"],
                "audit_retention_days": 180
            });
            let update = app
                .clone()
                .oneshot(authenticated_json_request(
                    "PUT",
                    "/api/security/policies",
                    &admin_token,
                    policy.clone(),
                ))
                .await
                .unwrap();
            assert_eq!(update.status(), StatusCode::OK);

            let get = app
                .clone()
                .oneshot(authenticated_request(
                    "GET",
                    "/api/security/policies",
                    &admin_token,
                ))
                .await
                .unwrap();
            assert_eq!(get.status(), StatusCode::OK);
            let current: Value = serde_json::from_slice(&read_body(get.into_body()).await).unwrap();
            assert_eq!(current, policy);

            let refreshed_token = login_access_token(&app, "admin", "secret").await;
            let claims = crate::auth::jwt::verify_token(&refreshed_token, "test-secret").unwrap();
            assert!((55..=60).contains(&(claims.exp - claims.iat)));

            let mut excluded_policy = policy.clone();
            excluded_policy["allowed_admin_cidrs"] = json!(["10.0.0.0/8"]);
            let self_lockout = app
                .clone()
                .oneshot(authenticated_json_request(
                    "PUT",
                    "/api/security/policies",
                    &admin_token,
                    excluded_policy,
                ))
                .await
                .unwrap();
            assert_eq!(self_lockout.status(), StatusCode::BAD_REQUEST);

            let weak = app
                .clone()
                .oneshot(authenticated_json_request(
                    "POST",
                    "/api/users",
                    &admin_token,
                    json!({ "username": "weak-user", "password": "weak", "role": "user" }),
                ))
                .await
                .unwrap();
            assert_eq!(weak.status(), StatusCode::BAD_REQUEST);

            let strong_password = "Strong-pass-1";
            let created = app
                .clone()
                .oneshot(authenticated_json_request(
                    "POST",
                    "/api/users",
                    &admin_token,
                    json!({
                        "username": "strong-user",
                        "password": strong_password,
                        "role": "user"
                    }),
                ))
                .await
                .unwrap();
            assert_eq!(created.status(), StatusCode::CREATED);

            let invalid_license = app
                .clone()
                .oneshot(authenticated_json_request(
                    "POST",
                    "/api/license/upload",
                    &admin_token,
                    json!({ "license_key": "not-a-valid-license" }),
                ))
                .await
                .unwrap();
            assert_eq!(invalid_license.status(), StatusCode::BAD_REQUEST);

            for _ in 0..40 {
                let (_, users_total) = db
                    .list_audit_logs(&crate::audit::AuditLogFilter {
                        action: Some("user.create".to_string()),
                        page: 1,
                        page_size: 50,
                        ..crate::audit::AuditLogFilter::default()
                    })
                    .await
                    .unwrap();
                let (_, license_total) = db
                    .list_audit_logs(&crate::audit::AuditLogFilter {
                        action: Some("license.upload.failure".to_string()),
                        page: 1,
                        page_size: 50,
                        ..crate::audit::AuditLogFilter::default()
                    })
                    .await
                    .unwrap();
                if users_total > 0 && license_total > 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            let audit_response = app
                .clone()
                .oneshot(authenticated_request(
                    "GET",
                    "/api/audit-logs?action=user.create&page_size=50",
                    &admin_token,
                ))
                .await
                .unwrap();
            assert_eq!(audit_response.status(), StatusCode::OK);
            let audit_body = read_body(audit_response.into_body()).await;
            let audit_json: Value = serde_json::from_slice(&audit_body).unwrap();
            assert!(audit_json["total"].as_i64().unwrap() >= 1);
            assert!(!String::from_utf8(audit_body)
                .unwrap()
                .contains(strong_password));

            let invalid_page_size = app
                .clone()
                .oneshot(authenticated_request(
                    "GET",
                    "/api/audit-logs?page_size=201",
                    &admin_token,
                ))
                .await
                .unwrap();
            assert_eq!(invalid_page_size.status(), StatusCode::BAD_REQUEST);
            let (_, license_failures) = db
                .list_audit_logs(&crate::audit::AuditLogFilter {
                    action: Some("license.upload.failure".to_string()),
                    page: 1,
                    page_size: 50,
                    ..crate::audit::AuditLogFilter::default()
                })
                .await
                .unwrap();
            assert_eq!(license_failures, 1);
            drop(app);
            drop(db);
            cleanup(&path);
        });
    }

    #[test]
    fn issue11_admin_cidr_policy_rejects_login_from_disallowed_ip() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("api-issue11-admin-cidr");
            let db = Database::new(&path).await.unwrap();
            let password_hash = admin_init::hash_password("secret").unwrap();
            db.create_user("admin", &password_hash, None, "admin")
                .await
                .unwrap();
            let (tx, _rx) = tokio::sync::mpsc::channel(DEVICE_INVALIDATION_CHANNEL_CAPACITY);
            let security = SecurityPolicyState::new(SecurityConfig {
                allowed_admin_cidrs: vec!["10.0.0.0/8".to_string()],
                ..SecurityConfig::default()
            })
            .unwrap();
            let app = build_router_with_states(
                db,
                test_auth_state(),
                test_oidc_config(),
                tx,
                middleware::ApiProtectionState::new(ApiRateLimitConfig::default()),
                security,
            );
            let response = app
                .oneshot(json_request(
                    "/api/auth/login",
                    json!({ "username": "admin", "password": "secret" }),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            cleanup(&path);
        });
    }

    fn build_test_router_with_config(
        db: Database,
        auth_state: AuthState,
        config: ApiRateLimitConfig,
    ) -> Router {
        let (tx, _rx) = tokio::sync::mpsc::channel(DEVICE_INVALIDATION_CHANNEL_CAPACITY);
        build_router_with_protection(
            db,
            auth_state,
            test_oidc_config(),
            tx,
            middleware::ApiProtectionState::new(config),
        )
    }

    fn post_request_with_optional_token(
        uri: &str,
        content_type: &str,
        body: impl Into<Body>,
        token: Option<&str>,
    ) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri(uri)
            .header(header::CONTENT_TYPE, content_type);
        if let Some(token) = token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        builder.body(body.into()).unwrap()
    }

    fn authenticated_json_request(
        method: &str,
        uri: &str,
        token: &str,
        value: Value,
    ) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(value.to_string()))
            .unwrap()
    }

    fn post_sized_request_with_optional_token(
        uri: &str,
        content_type: &str,
        body: Vec<u8>,
        token: Option<&str>,
    ) -> Request<Body> {
        let body_len = body.len();
        let mut builder = Request::builder()
            .method("POST")
            .uri(uri)
            .header(header::CONTENT_TYPE, content_type)
            .header(header::CONTENT_LENGTH, body_len);
        if let Some(token) = token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        builder.body(Body::from(body)).unwrap()
    }

    fn slow_streaming_body() -> (
        Body,
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let (mut sender, body) = Body::channel();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let feeder = tokio::spawn(async move {
            sender
                .send_data(Bytes::from_static(b"{"))
                .await
                .expect("测试路由必须读取第一段请求体");
            sender
                .send_data(Bytes::from_static(b" "))
                .await
                .expect("测试路由必须继续读取流式请求体");
            let _ = entered_tx.send(());
            let _ = release_rx.await;
        });
        (body, entered_rx, release_tx, feeder)
    }

    fn assert_content_type(response: &axum::response::Response, expected: &str) {
        let actual = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .split(';')
            .next()
            .unwrap_or_default()
            .trim();
        assert_eq!(actual, expected);
    }

    async fn assert_text_response(
        response: axum::response::Response,
        status: StatusCode,
        expected_body: &str,
    ) {
        assert_eq!(response.status(), status);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/plain; charset=utf-8")
        );
        assert_eq!(
            read_body(response.into_body()).await,
            expected_body.as_bytes()
        );
    }

    async fn read_body<B>(mut body: B) -> Vec<u8>
    where
        B: HttpBody<Data = Bytes> + Unpin,
        B::Error: Debug,
    {
        let mut bytes = Vec::new();
        while let Some(chunk) = body.data().await {
            bytes.extend_from_slice(&chunk.unwrap());
        }
        bytes
    }

    async fn assert_json_error(response: axum::response::Response, status: StatusCode) {
        assert_eq!(response.status(), status);
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        assert_eq!(
            content_type.split(';').next().unwrap_or_default(),
            "application/json"
        );
        let body: Value = serde_json::from_slice(&read_body(response.into_body()).await).unwrap();
        assert!(body.get("error").and_then(Value::as_str).is_some());
    }

    fn test_auth_state() -> AuthState {
        AuthState {
            jwt_secret: "test-secret".to_string(),
            jwt_expiry_hours: 24,
            refresh_expiry_days: 7,
        }
    }

    fn test_oidc_config() -> OidcConfig {
        OidcConfig::default()
    }

    fn test_cross_origin_oidc_config() -> OidcConfig {
        OidcConfig {
            allowed_origins: vec!["https://console.example.com".to_string()],
            ..OidcConfig::default()
        }
    }

    fn test_configured_oidc_config() -> OidcConfig {
        OidcConfig {
            enabled: true,
            issuer_url: "https://issuer.example.com".to_string(),
            client_id: "rustdesk-server".to_string(),
            client_secret: "secret".to_string(),
            redirect_uri: "https://server.example.com/api/auth/oidc/callback".to_string(),
            post_login_url: "https://console.example.com/dashboard".to_string(),
            allowed_origins: Vec::new(),
        }
    }

    fn assert_oidc_redirect(response: &axum::response::Response, error: &str) {
        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            &format!("https://console.example.com/dashboard?error={error}")
        );
    }

    async fn app_with_cross_origin_cookie() -> (Router, String, String) {
        let path = temp_db_path("api-cookie-csrf");
        let db = Database::new(&path).await.unwrap();
        let password_hash = admin_init::hash_password("secret").unwrap();
        db.create_user("admin", &password_hash, None, "admin")
            .await
            .unwrap();
        let app = build_test_router(db, test_auth_state(), test_cross_origin_oidc_config());
        let cookie_header = login_cookie_header(&app).await;
        (app, cookie_header, path)
    }

    async fn login_cookie_header(app: &Router) -> String {
        let login_response = app
            .clone()
            .oneshot(json_request(
                "/api/auth/login",
                json!({ "username": "admin", "password": "secret" }),
            ))
            .await
            .unwrap();
        assert_eq!(login_response.status(), StatusCode::OK);
        login_response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|value| {
                value
                    .to_str()
                    .unwrap()
                    .split(';')
                    .next()
                    .unwrap()
                    .to_string()
            })
            .collect::<Vec<_>>()
            .join("; ")
    }

    fn json_request(uri: &str, value: Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(value.to_string()))
            .unwrap()
    }

    fn authenticated_request(method: &str, uri: &str, token: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    }

    fn header_only_test_request(
        method: &str,
        uri: &str,
        authorization: &[String],
        cookie_token: Option<&str>,
    ) -> Request<Body> {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap();
        for value in authorization {
            request
                .headers_mut()
                .append(header::AUTHORIZATION, HeaderValue::from_str(value).unwrap());
        }
        if let Some(token) = cookie_token {
            request.headers_mut().insert(
                header::COOKIE,
                HeaderValue::from_str(&format!("access_token={token}")).unwrap(),
            );
        }
        request
    }

    async fn login_access_token(app: &Router, username: &str, password: &str) -> String {
        let response = app
            .clone()
            .oneshot(json_request(
                "/api/auth/login",
                json!({ "username": username, "password": password }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = serde_json::from_slice(&read_body(response.into_body()).await).unwrap();
        body["access_token"].as_str().unwrap().to_string()
    }

    fn temp_db_path(name: &str) -> String {
        std::env::temp_dir()
            .join(format!(
                "{}.sqlite3",
                unique_name(&format!("rustdesk-{name}"))
            ))
            .to_string_lossy()
            .to_string()
    }

    fn unique_name(prefix: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("{}-{}-{}", prefix, std::process::id(), nanos)
    }

    fn cleanup(path: &str) {
        std::fs::remove_file(path).ok();
        std::fs::remove_file(format!("{path}-shm")).ok();
        std::fs::remove_file(format!("{path}-wal")).ok();
        std::fs::remove_file(format!("{path}.migration.lock")).ok();
    }
}
