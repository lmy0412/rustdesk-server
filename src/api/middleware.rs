use crate::{
    auth::{
        jwt::{verify_token, AuthState, CurrentUser, JwtError},
        ACCESS_TOKEN_COOKIE,
    },
    config::OidcConfig,
    database::Database,
};
use axum::{
    http::{header, HeaderMap, HeaderValue, Method, Request, StatusCode, Uri},
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
use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin, Any, CorsLayer};

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

pub fn cors_middleware(oidc_config: &OidcConfig) -> CorsLayer {
    if oidc_config.allowed_origins.is_empty() {
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any)
    } else {
        let origins = oidc_config
            .allowed_origins
            .iter()
            .map(|origin| {
                HeaderValue::from_str(origin).expect("allowed_origins 已在配置加载阶段校验")
            })
            .collect::<Vec<_>>();
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(origins))
            .allow_methods(AllowMethods::mirror_request())
            .allow_headers(AllowHeaders::mirror_request())
            .allow_credentials(true)
    }
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
    let oidc_config = request
        .extensions()
        .get::<OidcConfig>()
        .cloned()
        .unwrap_or_default();

    let (token, from_cookie) = extract_token(&request)?;
    if from_cookie && requires_cross_origin_cookie_check(&request, &oidc_config) {
        validate_cookie_request_origin(&request, &oidc_config)?;
    }
    let claims = verify_token(&token, &auth_state.jwt_secret).map_err(jwt_error_response)?;

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
        "/api/auth/login"
            | "/api/auth/refresh"
            | "/api/auth/oidc/login"
            | "/api/auth/oidc/callback"
            | "/api/health"
            | "/api/version"
    )
}

fn extract_token<B>(request: &Request<B>) -> Result<(String, bool), (StatusCode, Json<Value>)> {
    if let Some(token) = extract_bearer_token(request)? {
        return Ok((token.to_string(), false));
    }
    if let Some(token) = extract_cookie_token(request) {
        return Ok((token, true));
    }
    Err((
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": "missing authorization header" })),
    ))
}

fn extract_bearer_token<B>(
    request: &Request<B>,
) -> Result<Option<&str>, (StatusCode, Json<Value>)> {
    let Some(value) = request.headers().get(header::AUTHORIZATION) else {
        return Ok(None);
    };
    let value = value.to_str().map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "invalid authorization header" })),
        )
    })?;

    value.strip_prefix("Bearer ").map(Some).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "invalid authorization format" })),
        )
    })
}

fn extract_cookie_token<B>(request: &Request<B>) -> Option<String> {
    let value = request.headers().get(header::COOKIE)?.to_str().ok()?;
    value.split(';').find_map(|part| {
        let (name, value) = part.trim().split_once('=')?;
        if name == ACCESS_TOKEN_COOKIE {
            Some(value.to_string())
        } else {
            None
        }
    })
}

fn requires_cross_origin_cookie_check<B>(request: &Request<B>, config: &OidcConfig) -> bool {
    !config.allowed_origins.is_empty()
        && matches!(
            *request.method(),
            Method::POST | Method::PUT | Method::PATCH | Method::DELETE
        )
}

fn validate_cookie_request_origin<B>(
    request: &Request<B>,
    config: &OidcConfig,
) -> Result<(), (StatusCode, Json<Value>)> {
    validate_cookie_request_origin_headers(request.headers(), config)
}

pub fn validate_cookie_request_origin_headers(
    headers: &HeaderMap,
    config: &OidcConfig,
) -> Result<(), (StatusCode, Json<Value>)> {
    if headers
        .get(header::ORIGIN)
        .and_then(|origin| origin.to_str().ok())
        .filter(|origin| is_allowed_origin(origin, &config.allowed_origins))
        .is_some()
    {
        return Ok(());
    }
    if headers
        .get(header::REFERER)
        .and_then(|referer| referer.to_str().ok())
        .and_then(origin_from_referer)
        .filter(|origin| is_allowed_origin(origin, &config.allowed_origins))
        .is_some()
    {
        return Ok(());
    }
    Err((
        StatusCode::FORBIDDEN,
        Json(json!({ "error": "cross-origin cookie request rejected" })),
    ))
}

fn is_allowed_origin(origin: &str, allowed_origins: &[String]) -> bool {
    let normalized = origin.trim().trim_end_matches('/');
    allowed_origins
        .iter()
        .any(|allowed| allowed.trim().trim_end_matches('/') == normalized)
}

fn origin_from_referer(referer: &str) -> Option<String> {
    let uri: Uri = referer.parse().ok()?;
    let scheme = uri.scheme_str()?;
    let authority = uri.authority()?;
    Some(format!("{}://{}", scheme, authority))
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
