use crate::{
    auth::jwt::{verify_token, AuthState, CurrentUser, JwtError},
    database::Database,
};
use axum::{
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
    Json,
};
use hbb_common::log;
use lru::LruCache;
use once_cell::sync::Lazy;
use serde_json::{json, Value};
use std::{num::NonZeroUsize, sync::Mutex, time::Instant};
use tower::layer::util::Identity;
use tower_http::cors::{Any, CorsLayer};

static TOKEN_VERSION_DENY_CACHE: Lazy<Mutex<LruCache<(i64, i64), ()>>> =
    Lazy::new(|| Mutex::new(LruCache::new(NonZeroUsize::new(1000).unwrap())));
static LAST_CACHE_CLEAR: Lazy<Mutex<Instant>> = Lazy::new(|| Mutex::new(Instant::now()));

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

pub async fn auth_layer<B>(
    mut request: Request<B>,
    next: Next<B>,
) -> Result<Response, (StatusCode, Json<Value>)> {
    let path = request.uri().path();
    if is_public_path(path) {
        return Ok(next.run(request).await);
    }

    clear_rejection_cache_if_needed();

    let db = request
        .extensions()
        .get::<Database>()
        .cloned()
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "db not available" })),
            )
        })?;
    let auth_state = request
        .extensions()
        .get::<AuthState>()
        .cloned()
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "auth_state not available" })),
            )
        })?;

    let token = extract_bearer_token(&request)?;
    let claims = verify_token(token, &auth_state.jwt_secret).map_err(jwt_error_response)?;

    if is_token_cached_rejected(claims.sub, claims.token_ver) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "token revoked" })),
        ));
    }

    let user = match db.find_user_by_id(claims.sub).await {
        Ok(Some(user)) if user.is_active && user.token_version == claims.token_ver => user,
        Ok(Some(user)) => {
            cache_token_rejection(claims.sub, claims.token_ver);
            let error = if user.is_active {
                "token revoked"
            } else {
                "account disabled"
            };
            return Err((StatusCode::UNAUTHORIZED, Json(json!({ "error": error }))));
        }
        Ok(None) => {
            cache_token_rejection(claims.sub, claims.token_ver);
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "invalid token user" })),
            ));
        }
        Err(_) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "token version check failed" })),
            ));
        }
    };

    request.extensions_mut().insert(CurrentUser {
        id: user.id,
        username: user.username,
        role: user.role,
    });

    Ok(next.run(request).await)
}

pub fn cache_token_rejection(user_id: i64, token_ver: i64) {
    let mut cache = TOKEN_VERSION_DENY_CACHE.lock().unwrap();
    cache.put((user_id, token_ver), ());
}

pub fn is_token_cached_rejected(user_id: i64, token_ver: i64) -> bool {
    let cache = TOKEN_VERSION_DENY_CACHE.lock().unwrap();
    cache.contains(&(user_id, token_ver))
}

pub fn invalidate_token_cache(user_id: i64) {
    let mut cache = TOKEN_VERSION_DENY_CACHE.lock().unwrap();
    let keys_to_remove: Vec<(i64, i64)> = cache
        .iter()
        .filter_map(|(&(uid, tv), _)| {
            if uid == user_id {
                Some((uid, tv))
            } else {
                None
            }
        })
        .collect();
    for key in keys_to_remove {
        cache.pop(&key);
    }
}

fn clear_rejection_cache_if_needed() {
    let mut last_clear = LAST_CACHE_CLEAR.lock().unwrap();
    if last_clear.elapsed().as_secs() >= 30 {
        let mut cache = TOKEN_VERSION_DENY_CACHE.lock().unwrap();
        cache.clear();
        *last_clear = Instant::now();
    }
}

fn is_public_path(path: &str) -> bool {
    matches!(
        path,
        "/api/auth/login" | "/api/auth/refresh" | "/api/health" | "/api/version"
    )
}

fn extract_bearer_token<B>(request: &Request<B>) -> Result<&str, (StatusCode, Json<Value>)> {
    let value = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "missing authorization header" })),
            )
        })?
        .to_str()
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "invalid authorization header" })),
            )
        })?;

    value.strip_prefix("Bearer ").ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "invalid authorization format" })),
        )
    })
}

fn jwt_error_response(err: JwtError) -> (StatusCode, Json<Value>) {
    match err {
        JwtError::Expired => (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "token expired" })),
        ),
        _ => (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "invalid token" })),
        ),
    }
}
