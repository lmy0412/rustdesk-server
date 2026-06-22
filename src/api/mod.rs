pub mod admin_init;
pub mod auth;
pub mod health;
pub mod middleware;
pub mod users;
pub mod version;

use crate::{auth::AuthState, database::Database};
use axum::{
    http::StatusCode,
    routing::{any, get, post},
    Extension, Json, Router,
};
use hbb_common::log;
use serde_json::{json, Value};
use std::{net::SocketAddr, sync::mpsc::Sender};
use tower::ServiceBuilder;

pub fn build_router(db: Database, auth_state: AuthState) -> Router {
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
        .layer(
            ServiceBuilder::new()
                .layer(Extension(db.clone()))
                .layer(Extension(auth_state.clone()))
                .layer(axum::middleware::from_fn(middleware::auth_layer)),
        );

    Router::new()
        .route("/api/auth/login", post(auth::handle_login))
        .route("/api/auth/refresh", post(auth::handle_refresh))
        .route("/api/health", get(health::handle_health))
        .route("/api/version", get(version::handle_version))
        .merge(protected_router)
        .layer(
            ServiceBuilder::new()
                .layer(Extension(db))
                .layer(Extension(auth_state)),
        )
        .fallback(any(handle_404))
        .layer(middleware::rate_limit_layer())
        .layer(axum::middleware::from_fn(middleware::request_logger))
        .layer(middleware::cors_middleware())
}

pub fn api_server_forever(
    addr: SocketAddr,
    ready_tx: Sender<Result<(), String>>,
    db_url: String,
    auth_state: AuthState,
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

        let app = build_router(db, auth_state);
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

    #[test]
    fn test_build_router() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("api-build-router");
            let db = Database::new(&path).await.unwrap();
            let _app = build_router(db, test_auth_state());
            cleanup(&path);
        });
    }

    #[test]
    fn test_health_route_is_public() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("api-health");
            let db = Database::new(&path).await.unwrap();
            let response = build_router(db, test_auth_state())
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
            let response = build_router(db, test_auth_state())
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
    fn test_login_refresh_and_logout_flow() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("api-auth-flow");
            let db = Database::new(&path).await.unwrap();
            let password_hash = admin_init::hash_password("secret").unwrap();
            db.create_user("admin", &password_hash, None, "admin")
                .await
                .unwrap();

            let app = build_router(db, test_auth_state());
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

    fn json_request(uri: &str, value: Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(value.to_string()))
            .unwrap()
    }

    fn temp_db_path(name: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir()
            .join(format!("rustdesk-{name}-{nanos}.sqlite3"))
            .to_string_lossy()
            .to_string()
    }

    fn cleanup(path: &str) {
        std::fs::remove_file(path).ok();
        std::fs::remove_file(format!("{path}-shm")).ok();
        std::fs::remove_file(format!("{path}-wal")).ok();
    }
}
