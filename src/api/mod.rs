pub mod health;
pub mod middleware;
pub mod version;

use axum::{
    http::StatusCode,
    routing::{any, get},
    Json, Router,
};
use hbb_common::log;
use serde_json::{json, Value};
use std::{net::SocketAddr, sync::mpsc::Sender};

pub fn build_router() -> Router {
    Router::new()
        .route("/api/health", get(health::handle_health))
        .route("/api/version", get(version::handle_version))
        .fallback(any(handle_404))
        .layer(middleware::rate_limit_layer())
        .layer(axum::middleware::from_fn(middleware::jwt_placeholder))
        .layer(axum::middleware::from_fn(middleware::request_logger))
        .layer(middleware::cors_middleware())
}

pub fn api_server_forever(addr: SocketAddr, ready_tx: Sender<Result<(), String>>) {
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
        let app = build_router();
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
        http::Request,
    };
    use std::fmt::Debug;
    use tower::ServiceExt;

    #[test]
    fn test_build_router() {
        let _app = build_router();
    }

    #[test]
    fn test_404_json() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let response = build_router()
                .oneshot(
                    Request::builder()
                        .uri("/nonexistent")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            let body = read_body(response.into_body()).await;
            let value: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(value, json!({ "error": "not found" }));
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
}
