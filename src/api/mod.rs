pub mod admin_init;
pub mod auth;
pub mod health;
pub mod license;
pub mod middleware;
pub mod oidc;
pub mod users;
pub mod version;

use crate::{
    auth::AuthState, config::OidcConfig, database::Database, peer::DeviceInvalidationSender,
};
use axum::{
    http::StatusCode,
    routing::{any, get, post},
    Extension, Json, Router,
};
use hbb_common::log;
use serde_json::{json, Value};
use std::{net::SocketAddr, sync::mpsc::Sender};
use tower::ServiceBuilder;

pub fn build_router(
    db: Database,
    auth_state: AuthState,
    oidc_config: OidcConfig,
    device_control_tx: DeviceInvalidationSender,
) -> Router {
    let protected_router = Router::new()
        .route("/api/auth/logout", post(auth::handle_logout))
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
        .layer(
            ServiceBuilder::new()
                .layer(Extension(db.clone()))
                .layer(Extension(device_control_tx.clone()))
                .layer(Extension(auth_state.clone()))
                .layer(Extension(oidc_config.clone()))
                .layer(axum::middleware::from_fn(middleware::auth_layer)),
        );

    Router::new()
        .route("/api/auth/login", post(auth::handle_login))
        .route("/api/auth/refresh", post(auth::handle_refresh))
        .route("/api/auth/oidc/login", get(oidc::handle_oidc_login))
        .route("/api/auth/oidc/callback", get(oidc::handle_oidc_callback))
        .route("/api/health", get(health::handle_health))
        .route("/api/version", get(version::handle_version))
        .merge(protected_router)
        .layer(
            ServiceBuilder::new()
                .layer(Extension(db))
                .layer(Extension(device_control_tx))
                .layer(Extension(auth_state))
                .layer(Extension(oidc_config.clone())),
        )
        .fallback(any(handle_404))
        .layer(middleware::rate_limit_layer())
        .layer(axum::middleware::from_fn(middleware::request_logger))
        .layer(middleware::cors_middleware(&oidc_config))
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
        if let Err(err) = admin_init::create_initial_admin(&db).await {
            let message = format!("API server failed to initialize admin user: {}", err);
            let _ = ready_tx.send(Err(message.clone()));
            eprintln!("Fatal: {}", message);
            std::process::exit(1);
        }
        crate::license::init_license_state();
        if let Err(err) = crate::license::load_license_from_database(&db).await {
            log::warn!("许可证加载失败，Pro 模式新连接将被拒绝: {}", err);
        }

        let app = build_router(db, auth_state, oidc_config, device_control_tx);
        log::info!("API server binding to {}", addr);
        match axum::Server::try_bind(&addr) {
            Ok(server) => {
                let _ = ready_tx.send(Ok(()));
                log::info!("API server listening on {}", addr);
                if let Err(err) = server.serve(app.into_make_service()).await {
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

async fn handle_404() -> (StatusCode, Json<Value>) {
    (StatusCode::NOT_FOUND, Json(json!({ "error": "not found" })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{Body, Bytes, HttpBody},
        http::{header, Request},
    };
    use std::{
        fmt::Debug,
        time::{SystemTime, UNIX_EPOCH},
    };
    use tower::ServiceExt;

    fn build_test_router(db: Database, auth_state: AuthState, oidc_config: OidcConfig) -> Router {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
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

            let (closed_tx, closed_rx) = tokio::sync::mpsc::unbounded_channel();
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

            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
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
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
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
    }
}
