use axum::{http::Request, middleware::Next, response::Response};
use hbb_common::log;
use std::time::Instant;
use tower::layer::util::Identity;
use tower_http::cors::{Any, CorsLayer};

pub async fn request_logger<B>(request: Request<B>, next: Next<B>) -> Response {
    let method = request.method().clone();
    let path = request
        .uri()
        .path_and_query()
        .map(|v| v.as_str().to_string())
        .unwrap_or_else(|| request.uri().path().to_string());
    let start = Instant::now();

    let response = next.run(request).await;
    let status = response.status();
    let line = format!(
        "{} {} {} {}ms",
        method,
        path,
        status.as_u16(),
        start.elapsed().as_millis()
    );
    if log::log_enabled!(log::Level::Info) {
        log::info!("{}", line);
    } else {
        println!("{}", line);
    }
    response
}

pub fn cors_middleware() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any)
}

/// Issue #3 中不启用真实限流；后续可在这里替换为实际 RateLimitLayer。
pub fn rate_limit_layer() -> Identity {
    Identity::new()
}

/// TODO(#4): 后续在这里解析并校验 Authorization 里的 JWT。
pub async fn jwt_placeholder<B>(request: Request<B>, next: Next<B>) -> Response {
    next.run(request).await
}
