use crate::{
    api::access::ApiError,
    audit::{AuditEvent, AuditService},
    auth::{
        jwt::{verify_token, AuthState, CurrentUser, JwtError},
        ACCESS_TOKEN_COOKIE,
    },
    config::{ApiRateLimitConfig, OidcConfig},
    database::Database,
    security::SecurityPolicyState,
};
use axum::{
    extract::{connect_info::ConnectInfo, MatchedPath},
    http::{header, HeaderMap, HeaderValue, Method, Request, StatusCode, Uri},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use hbb_common::log;
use lru::LruCache;
use once_cell::sync::Lazy;
use serde_json::{json, Value};
use std::{
    hash::{Hash, Hasher},
    net::{IpAddr, SocketAddr},
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tower::layer::util::Identity;
use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin, Any, CorsLayer};

type TokenVersionDenyCache = Mutex<LruCache<(u64, i64, i64), ()>>;

static TOKEN_VERSION_DENY_CACHE: Lazy<TokenVersionDenyCache> =
    Lazy::new(|| Mutex::new(LruCache::new(NonZeroUsize::new(1000).unwrap())));
static LAST_CACHE_CLEAR: Lazy<Mutex<Instant>> = Lazy::new(|| Mutex::new(Instant::now()));

#[derive(Clone)]
pub struct ApiProtectionState {
    config: ApiRateLimitConfig,
    shared: Arc<Semaphore>,
    telemetry: Arc<Semaphore>,
    auth: Arc<Semaphore>,
    other: Arc<Semaphore>,
    argon2: Arc<Semaphore>,
    telemetry_peers: Arc<Mutex<LruCache<IpAddr, TokenBucket>>>,
    auth_peers: Arc<Mutex<LruCache<IpAddr, TokenBucket>>>,
    devices: Arc<Mutex<LruCache<String, TokenBucket>>>,
    actors: Arc<Mutex<LruCache<i64, TokenBucket>>>,
}

impl ApiProtectionState {
    pub fn new(config: ApiRateLimitConfig) -> Self {
        Self {
            shared: Arc::new(Semaphore::new(config.max_in_flight)),
            telemetry: Arc::new(Semaphore::new(config.telemetry_max_in_flight)),
            auth: Arc::new(Semaphore::new(config.auth_max_in_flight)),
            other: Arc::new(Semaphore::new(
                config.max_in_flight - config.telemetry_max_in_flight - config.auth_max_in_flight,
            )),
            argon2: Arc::new(Semaphore::new(config.argon2_max_in_flight)),
            telemetry_peers: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(config.peer_lru_capacity)
                    .expect("api_rate_limit 已在配置加载阶段校验"),
            ))),
            auth_peers: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(config.peer_lru_capacity)
                    .expect("api_rate_limit 已在配置加载阶段校验"),
            ))),
            devices: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(config.device_lru_capacity)
                    .expect("api_rate_limit 已在配置加载阶段校验"),
            ))),
            actors: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(config.actor_lru_capacity)
                    .expect("api_rate_limit 已在配置加载阶段校验"),
            ))),
            config,
        }
    }

    pub fn request_timeout(&self) -> Duration {
        Duration::from_millis(self.config.request_timeout_ms)
    }

    pub async fn acquire_argon2(&self) -> Result<OwnedSemaphorePermit, ApiError> {
        self.argon2
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| ApiError::service_unavailable("authentication worker unavailable"))
    }

    pub fn check_device(&self, management_generation: &str) -> Result<(), ApiError> {
        check_bucket(
            &self.devices,
            management_generation.to_string(),
            self.config.device_capacity,
            self.config.device_refill_per_minute,
        )
    }

    pub fn check_address_book_actor(&self, actor_id: i64) -> Result<(), ApiError> {
        check_bucket(
            &self.actors,
            actor_id,
            self.config.address_book_actor_capacity,
            self.config.address_book_actor_refill_per_minute,
        )
    }

    fn check_auth_peer(&self, peer: IpAddr) -> Result<(), ApiError> {
        check_bucket(
            &self.auth_peers,
            peer,
            self.config.auth_peer_capacity,
            self.config.auth_peer_refill_per_minute,
        )
    }

    fn check_telemetry_peer(&self, peer: IpAddr) -> Result<(), ApiError> {
        check_bucket(
            &self.telemetry_peers,
            peer,
            self.config.telemetry_peer_capacity,
            self.config.telemetry_peer_refill_per_minute,
        )
    }

    #[cfg(test)]
    pub(crate) fn occupy_all_other_for_test(&self) -> Vec<OwnedSemaphorePermit> {
        (0..self.other.available_permits())
            .map(|_| {
                self.other
                    .clone()
                    .try_acquire_owned()
                    .expect("测试应能占满 ordinary API 隔舱")
            })
            .collect()
    }
}

#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    updated_at: Instant,
}

impl TokenBucket {
    fn new_at(capacity: u64, now: Instant) -> Self {
        Self {
            tokens: capacity as f64,
            updated_at: now,
        }
    }

    fn take_at(&mut self, capacity: u64, refill_per_minute: u64, now: Instant) -> bool {
        let refill = now
            .checked_duration_since(self.updated_at)
            .unwrap_or_default()
            .as_secs_f64()
            * refill_per_minute as f64
            / 60.0;
        self.tokens = (self.tokens + refill).min(capacity as f64);
        self.updated_at = self.updated_at.max(now);
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}

fn check_bucket<K>(
    cache: &Mutex<LruCache<K, TokenBucket>>,
    key: K,
    capacity: u64,
    refill_per_minute: u64,
) -> Result<(), ApiError>
where
    K: Eq + Hash,
{
    let mut cache = cache
        .lock()
        .map_err(|_| ApiError::service_unavailable("rate limiter unavailable"))?;
    check_bucket_locked(&mut cache, key, capacity, refill_per_minute, Instant::now())
}

#[cfg(test)]
fn check_bucket_at<K>(
    cache: &Mutex<LruCache<K, TokenBucket>>,
    key: K,
    capacity: u64,
    refill_per_minute: u64,
    now: Instant,
) -> Result<(), ApiError>
where
    K: Eq + Hash,
{
    let mut cache = cache
        .lock()
        .map_err(|_| ApiError::service_unavailable("rate limiter unavailable"))?;
    check_bucket_locked(&mut cache, key, capacity, refill_per_minute, now)
}

fn check_bucket_locked<K>(
    cache: &mut LruCache<K, TokenBucket>,
    key: K,
    capacity: u64,
    refill_per_minute: u64,
    now: Instant,
) -> Result<(), ApiError>
where
    K: Eq + Hash,
{
    let allowed = if let Some(bucket) = cache.get_mut(&key) {
        bucket.take_at(capacity, refill_per_minute, now)
    } else {
        let mut bucket = TokenBucket::new_at(capacity, now);
        let allowed = bucket.take_at(capacity, refill_per_minute, now);
        cache.put(key, bucket);
        allowed
    };
    if allowed {
        Ok(())
    } else {
        Err(
            ApiError::new(StatusCode::TOO_MANY_REQUESTS, "request rate limit exceeded")
                .retry_after(1),
        )
    }
}

pub async fn request_logger<B>(request: Request<B>, next: Next<B>) -> Response {
    let method = request.method().clone();
    let path = request
        .extensions()
        .get::<MatchedPath>()
        .map(|path| path.as_str().to_string())
        .unwrap_or_else(|| "<unmatched>".to_string());
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

pub async fn protect_auth_endpoint<B>(
    request: Request<B>,
    next: Next<B>,
) -> Result<Response, ApiError> {
    let state = protection_state(&request)?;
    let peer = peer_ip(&request)?;
    let _auth_permit = try_acquire(&state.auth, "authentication capacity exhausted")?;
    let _shared_permit = try_acquire(&state.shared, "API capacity exhausted")?;
    state.check_auth_peer(peer)?;
    run_with_timeout(state.request_timeout(), request, next).await
}

pub async fn protect_telemetry_endpoint<B>(
    request: Request<B>,
    next: Next<B>,
) -> Result<Response, ApiError> {
    let state = protection_state(&request)?;
    let peer = peer_ip(&request)?;
    let _telemetry_permit = try_acquire(&state.telemetry, "telemetry capacity exhausted")?;
    let _shared_permit = try_acquire(&state.shared, "API capacity exhausted")?;
    state.check_telemetry_peer(peer)?;
    run_with_timeout(state.request_timeout(), request, next).await
}

pub async fn protect_shared_endpoint<B>(
    request: Request<B>,
    next: Next<B>,
) -> Result<Response, ApiError> {
    let state = protection_state(&request)?;
    let _other_permit = try_acquire(&state.other, "API endpoint capacity exhausted")?;
    let _shared_permit = try_acquire(&state.shared, "API capacity exhausted")?;
    run_with_timeout(state.request_timeout(), request, next).await
}

pub async fn normalize_api_error_response<B>(request: Request<B>, next: Next<B>) -> Response {
    let response = next.run(request).await;
    let status = response.status();
    if !(status.is_client_error() || status.is_server_error())
        || response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.split(';').next().unwrap_or_default().trim())
            .is_some_and(|mime| mime.eq_ignore_ascii_case("application/json"))
    {
        return response;
    }

    let message = match status {
        StatusCode::BAD_REQUEST => "invalid request",
        StatusCode::UNAUTHORIZED => "authentication required",
        StatusCode::FORBIDDEN => "request forbidden",
        StatusCode::NOT_FOUND => "resource not found",
        StatusCode::METHOD_NOT_ALLOWED => "method not allowed",
        StatusCode::CONFLICT => "request conflicts with current state",
        StatusCode::PAYLOAD_TOO_LARGE => "request body exceeds the configured limit",
        StatusCode::UNSUPPORTED_MEDIA_TYPE => "unsupported media type",
        StatusCode::TOO_MANY_REQUESTS => "too many requests",
        StatusCode::SERVICE_UNAVAILABLE => "service unavailable",
        _ if status.is_server_error() => "internal server error",
        _ => "request rejected",
    };
    let mut normalized = ApiError::new(status, message).into_response();
    for (name, value) in response.headers() {
        if name != header::CONTENT_TYPE
            && name != header::CONTENT_LENGTH
            && name != header::CONTENT_ENCODING
            && name != header::CONTENT_RANGE
            && name != header::TRANSFER_ENCODING
        {
            normalized.headers_mut().append(name.clone(), value.clone());
        }
    }
    normalized
}

fn protection_state<B>(request: &Request<B>) -> Result<ApiProtectionState, ApiError> {
    request
        .extensions()
        .get::<ApiProtectionState>()
        .cloned()
        .ok_or_else(|| ApiError::internal("API protection state unavailable"))
}

fn peer_ip<B>(request: &Request<B>) -> Result<IpAddr, ApiError> {
    request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|value| value.0.ip())
        .ok_or_else(|| {
            ApiError::service_unavailable("peer address unavailable; request rejected")
                .retry_after(1)
        })
}

fn try_acquire(
    semaphore: &Arc<Semaphore>,
    message: &'static str,
) -> Result<OwnedSemaphorePermit, ApiError> {
    semaphore
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::service_unavailable(message).retry_after(1))
}

async fn run_with_timeout<B>(
    timeout: Duration,
    request: Request<B>,
    next: Next<B>,
) -> Result<Response, ApiError> {
    tokio::time::timeout(timeout, next.run(request))
        .await
        .map_err(|_| ApiError::service_unavailable("request timed out").retry_after(1))
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
    let security = request
        .extensions()
        .get::<SecurityPolicyState>()
        .cloned()
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "security policy not available" })),
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
    let issued_at = i64::try_from(claims.iat).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "invalid token" })),
        )
    })?;
    security
        .validate_session_issued_at(issued_at)
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "session expired" })),
            )
        })?;
    let cache_scope = token_cache_scope(&auth_state.jwt_secret, db.auth_cache_scope());

    if is_token_cached_rejected(cache_scope, claims.sub, claims.token_ver) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "token revoked" })),
        ));
    }

    let user = match db.find_user_by_id(claims.sub).await {
        Ok(Some(user)) if user.is_active && user.token_version == claims.token_ver => user,
        Ok(Some(user)) => {
            cache_token_rejection(cache_scope, claims.sub, claims.token_ver);
            let error = if user.is_active {
                "token revoked"
            } else {
                "account disabled"
            };
            return Err((StatusCode::UNAUTHORIZED, Json(json!({ "error": error }))));
        }
        Ok(None) => {
            cache_token_rejection(cache_scope, claims.sub, claims.token_ver);
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

    if user.role == "admin" {
        let peer = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|peer| peer.0.ip())
            .ok_or_else(|| {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({ "error": "peer address unavailable; request rejected" })),
                )
            })?;
        let allowed = security.admin_ip_allowed(peer).map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "administrator IP policy check failed" })),
            )
        })?;
        if !allowed {
            if let Some(audit) = request.extensions().get::<AuditService>() {
                audit.record(
                    AuditEvent::new("auth.session.ip_denied")
                        .actor(user.id)
                        .target("user", user.id.to_string())
                        .ip(peer)
                        .detail(json!({"reason": "admin_ip_not_allowed"})),
                );
            }
            return Err((
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "administrator IP is not allowed" })),
            ));
        }
    }

    request.extensions_mut().insert(CurrentUser {
        id: user.id,
        username: user.username,
        role: user.role,
    });

    Ok(next.run(request).await)
}

pub fn token_cache_scope(jwt_secret: &str, database_scope: u64) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    jwt_secret.hash(&mut hasher);
    database_scope.hash(&mut hasher);
    hasher.finish()
}

pub fn cache_token_rejection(scope: u64, user_id: i64, token_ver: i64) {
    let mut cache = TOKEN_VERSION_DENY_CACHE.lock().unwrap();
    cache.put((scope, user_id, token_ver), ());
}

pub fn is_token_cached_rejected(scope: u64, user_id: i64, token_ver: i64) -> bool {
    let cache = TOKEN_VERSION_DENY_CACHE.lock().unwrap();
    cache.contains(&(scope, user_id, token_ver))
}

pub fn invalidate_token_cache(user_id: i64) {
    let mut cache = TOKEN_VERSION_DENY_CACHE.lock().unwrap();
    let keys_to_remove: Vec<(u64, i64, i64)> = cache
        .iter()
        .filter_map(|(&(scope, uid, tv), _)| {
            if uid == user_id {
                Some((scope, uid, tv))
            } else {
                None
            }
        })
        .collect();
    for key in keys_to_remove {
        cache.pop(&key);
    }
}

#[cfg(test)]
pub fn clear_token_rejection_cache() {
    TOKEN_VERSION_DENY_CACHE.lock().unwrap().clear();
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

#[cfg(test)]
mod tests {
    use super::{check_bucket_at, token_cache_scope, try_acquire, ApiProtectionState, TokenBucket};
    use crate::config::ApiRateLimitConfig;
    use axum::{
        http::{header, StatusCode},
        response::IntoResponse,
    };
    use std::{
        net::{IpAddr, Ipv4Addr},
        time::{Duration, Instant},
    };

    #[test]
    fn token_rejection_cache_is_partitioned_by_database_instance() {
        assert_ne!(
            token_cache_scope("same-secret", 1),
            token_cache_scope("same-secret", 2)
        );
    }

    #[test]
    fn token_bucket_ignores_reverse_time_without_panicking_or_refilling() {
        let start = Instant::now();
        let later = start + Duration::from_secs(30);
        let mut bucket = TokenBucket::new_at(10, start);

        assert!(bucket.take_at(10, 60, later));
        assert_eq!(bucket.tokens, 9.0);
        assert_eq!(bucket.updated_at, later);

        assert!(bucket.take_at(10, 60, start));
        assert_eq!(bucket.tokens, 8.0);
        assert_eq!(bucket.updated_at, later);
    }

    #[test]
    fn ordinary_endpoints_cannot_consume_reserved_capacity() {
        let state = ApiProtectionState::new(ApiRateLimitConfig::default());
        let ordinary_capacity = state.config.max_in_flight
            - state.config.telemetry_max_in_flight
            - state.config.auth_max_in_flight;
        let ordinary_permits = (0..ordinary_capacity)
            .map(|_| state.other.try_acquire().unwrap())
            .collect::<Vec<_>>();

        assert!(state.other.try_acquire().is_err());
        assert_eq!(
            state.auth.available_permits(),
            state.config.auth_max_in_flight
        );
        assert_eq!(
            state.telemetry.available_permits(),
            state.config.telemetry_max_in_flight
        );
        drop(ordinary_permits);
    }

    #[test]
    fn default_buckets_sustain_ten_minutes_of_synchronized_service_traffic() {
        for information_changes_each_tick in [false, true] {
            let state = ApiProtectionState::new(ApiRateLimitConfig::default());
            let start = Instant::now();
            let peer = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

            for tick in 0..=200_u64 {
                let now = start + Duration::from_secs(tick * 3);
                let information_revision = if information_changes_each_tick {
                    tick
                } else {
                    0
                };
                std::hint::black_box(information_revision);
                for device in 0..300_u64 {
                    let generation = format!("{device:032x}");
                    // 每个 service tick 同步发送 heartbeat 和 sysinfo。信息是否变化
                    // 不应改变限流状态机，因此两种场景都跑完整十分钟。
                    for _ in 0..2 {
                        assert!(check_bucket_at(
                            &state.telemetry_peers,
                            peer,
                            state.config.telemetry_peer_capacity,
                            state.config.telemetry_peer_refill_per_minute,
                            now,
                        )
                        .is_ok());
                        assert!(check_bucket_at(
                            &state.devices,
                            generation.clone(),
                            state.config.device_capacity,
                            state.config.device_refill_per_minute,
                            now,
                        )
                        .is_ok());
                    }
                }
            }

            assert_eq!(state.telemetry_peers.lock().unwrap().len(), 1);
            assert_eq!(state.devices.lock().unwrap().len(), 300);
            // Flutter 的独立 /api/ab 探测走 ordinary 隔舱，不触碰 telemetry
            // peer/device bucket；占用并释放 ordinary permit 后两者数量保持不变。
            let permit = state.other.clone().try_acquire_owned().unwrap();
            drop(permit);
            assert_eq!(state.telemetry_peers.lock().unwrap().len(), 1);
            assert_eq!(state.devices.lock().unwrap().len(), 300);
        }
    }

    #[test]
    fn synchronized_default_compartments_fit_three_hundred_dual_requests() {
        let state = ApiProtectionState::new(ApiRateLimitConfig::default());
        let telemetry = (0..600)
            .map(|_| state.telemetry.clone().try_acquire_owned().unwrap())
            .collect::<Vec<_>>();
        let shared = (0..600)
            .map(|_| state.shared.clone().try_acquire_owned().unwrap())
            .collect::<Vec<_>>();

        assert_eq!(
            state.telemetry.available_permits(),
            state.config.telemetry_max_in_flight - 600
        );
        assert_eq!(
            state.shared.available_permits(),
            state.config.max_in_flight - 600
        );
        drop((telemetry, shared));
    }

    #[test]
    fn reserved_and_ordinary_compartments_exactly_partition_shared_capacity() {
        let state = ApiProtectionState::new(ApiRateLimitConfig::default());
        let telemetry = (0..state.config.telemetry_max_in_flight)
            .map(|_| state.telemetry.clone().try_acquire_owned().unwrap())
            .collect::<Vec<_>>();
        let auth = (0..state.config.auth_max_in_flight)
            .map(|_| state.auth.clone().try_acquire_owned().unwrap())
            .collect::<Vec<_>>();
        let ordinary = (0..state.other.available_permits())
            .map(|_| state.other.clone().try_acquire_owned().unwrap())
            .collect::<Vec<_>>();
        let shared = (0..state.config.max_in_flight)
            .map(|_| state.shared.clone().try_acquire_owned().unwrap())
            .collect::<Vec<_>>();

        assert!(state.telemetry.clone().try_acquire_owned().is_err());
        assert!(state.auth.clone().try_acquire_owned().is_err());
        assert!(state.other.clone().try_acquire_owned().is_err());
        assert!(state.shared.clone().try_acquire_owned().is_err());
        assert_eq!(
            telemetry.len() + auth.len() + ordinary.len(),
            state.config.max_in_flight
        );
        drop((telemetry, auth, ordinary, shared));
    }

    #[test]
    fn failed_shared_acquisition_releases_the_endpoint_compartment() {
        let state = ApiProtectionState::new(ApiRateLimitConfig::default());
        let shared = (0..state.config.max_in_flight)
            .map(|_| state.shared.clone().try_acquire_owned().unwrap())
            .collect::<Vec<_>>();

        let telemetry_result = (|| {
            let _endpoint = try_acquire(&state.telemetry, "telemetry")?;
            let _shared = try_acquire(&state.shared, "shared")?;
            Ok::<_, crate::api::access::ApiError>(())
        })();
        assert!(telemetry_result.is_err());
        assert_eq!(
            state.telemetry.available_permits(),
            state.config.telemetry_max_in_flight
        );

        let auth_result = (|| {
            let _endpoint = try_acquire(&state.auth, "auth")?;
            let _shared = try_acquire(&state.shared, "shared")?;
            Ok::<_, crate::api::access::ApiError>(())
        })();
        assert!(auth_result.is_err());
        assert_eq!(
            state.auth.available_permits(),
            state.config.auth_max_in_flight
        );

        let ordinary_capacity = state.other.available_permits();
        let ordinary_result = (|| {
            let _endpoint = try_acquire(&state.other, "ordinary")?;
            let _shared = try_acquire(&state.shared, "shared")?;
            Ok::<_, crate::api::access::ApiError>(())
        })();
        assert!(ordinary_result.is_err());
        assert_eq!(state.other.available_permits(), ordinary_capacity);
        drop(shared);
    }

    #[test]
    fn sustained_overload_is_rejected_and_refill_recovers_deterministically() {
        let state = ApiProtectionState::new(ApiRateLimitConfig::default());
        let start = Instant::now();
        let peer = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9));
        let mut peer_rejected_at = None;

        for tick in 0..=800_u64 {
            let now = start + Duration::from_secs(tick * 3);
            for _ in 0..1_000 {
                if check_bucket_at(
                    &state.telemetry_peers,
                    peer,
                    state.config.telemetry_peer_capacity,
                    state.config.telemetry_peer_refill_per_minute,
                    now,
                )
                .is_err()
                {
                    peer_rejected_at = Some(now);
                    break;
                }
            }
            if peer_rejected_at.is_some() {
                break;
            }
        }
        let rejected_at = peer_rejected_at.expect("500 台持续双请求最终必须耗尽 peer bucket");
        assert!(check_bucket_at(
            &state.telemetry_peers,
            peer,
            state.config.telemetry_peer_capacity,
            state.config.telemetry_peer_refill_per_minute,
            rejected_at + Duration::from_millis(4),
        )
        .is_ok());

        let generation = "f".repeat(32);
        for _ in 0..state.config.device_capacity {
            assert!(check_bucket_at(
                &state.devices,
                generation.clone(),
                state.config.device_capacity,
                state.config.device_refill_per_minute,
                start,
            )
            .is_ok());
        }
        assert!(check_bucket_at(
            &state.devices,
            generation.clone(),
            state.config.device_capacity,
            state.config.device_refill_per_minute,
            start,
        )
        .is_err());
        assert!(check_bucket_at(
            &state.devices,
            generation,
            state.config.device_capacity,
            state.config.device_refill_per_minute,
            start + Duration::from_secs(1),
        )
        .is_ok());
    }

    #[test]
    fn address_book_actor_rejects_the_thirty_first_mutation_and_refills() {
        let state = ApiProtectionState::new(ApiRateLimitConfig::default());
        let now = Instant::now();
        for _ in 0..state.config.address_book_actor_capacity {
            assert!(check_bucket_at(
                &state.actors,
                42,
                state.config.address_book_actor_capacity,
                state.config.address_book_actor_refill_per_minute,
                now,
            )
            .is_ok());
        }
        let rejection = check_bucket_at(
            &state.actors,
            42,
            state.config.address_book_actor_capacity,
            state.config.address_book_actor_refill_per_minute,
            now,
        )
        .unwrap_err()
        .into_response();
        assert_eq!(rejection.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            rejection
                .headers()
                .get(header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok()),
            Some("1")
        );
        assert!(check_bucket_at(
            &state.actors,
            42,
            state.config.address_book_actor_capacity,
            state.config.address_book_actor_refill_per_minute,
            now + Duration::from_secs(4),
        )
        .is_ok());
    }

    #[test]
    fn device_bucket_is_scoped_to_management_generation_not_external_id() {
        let state = ApiProtectionState::new(ApiRateLimitConfig::default());
        let now = Instant::now();
        let old_generation = "a".repeat(32);
        let new_generation = "b".repeat(32);

        for _ in 0..state.config.device_capacity {
            assert!(check_bucket_at(
                &state.devices,
                old_generation.clone(),
                state.config.device_capacity,
                state.config.device_refill_per_minute,
                now,
            )
            .is_ok());
        }
        assert!(check_bucket_at(
            &state.devices,
            old_generation,
            state.config.device_capacity,
            state.config.device_refill_per_minute,
            now,
        )
        .is_err());
        assert!(check_bucket_at(
            &state.devices,
            new_generation,
            state.config.device_capacity,
            state.config.device_refill_per_minute,
            now,
        )
        .is_ok());
        assert_eq!(state.devices.lock().unwrap().len(), 2);
    }

    #[test]
    fn all_rate_limit_lrus_remain_bounded_and_evict_oldest_entries() {
        let config = ApiRateLimitConfig {
            peer_lru_capacity: 3,
            device_lru_capacity: 3,
            actor_lru_capacity: 3,
            ..ApiRateLimitConfig::default()
        };
        let state = ApiProtectionState::new(config);
        let now = Instant::now();

        for value in 1..=4_u8 {
            let peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, value));
            assert!(check_bucket_at(
                &state.telemetry_peers,
                peer,
                state.config.telemetry_peer_capacity,
                state.config.telemetry_peer_refill_per_minute,
                now,
            )
            .is_ok());
            assert!(check_bucket_at(
                &state.auth_peers,
                peer,
                state.config.auth_peer_capacity,
                state.config.auth_peer_refill_per_minute,
                now,
            )
            .is_ok());
            assert!(check_bucket_at(
                &state.devices,
                format!("{value:032x}"),
                state.config.device_capacity,
                state.config.device_refill_per_minute,
                now,
            )
            .is_ok());
            assert!(check_bucket_at(
                &state.actors,
                i64::from(value),
                state.config.address_book_actor_capacity,
                state.config.address_book_actor_refill_per_minute,
                now,
            )
            .is_ok());
        }

        assert_eq!(state.telemetry_peers.lock().unwrap().len(), 3);
        assert_eq!(state.auth_peers.lock().unwrap().len(), 3);
        assert_eq!(state.devices.lock().unwrap().len(), 3);
        assert_eq!(state.actors.lock().unwrap().len(), 3);
        assert!(!state
            .telemetry_peers
            .lock()
            .unwrap()
            .contains(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
        assert!(!state
            .auth_peers
            .lock()
            .unwrap()
            .contains(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
        assert!(!state
            .devices
            .lock()
            .unwrap()
            .contains(&format!("{:032x}", 1)));
        assert!(!state.actors.lock().unwrap().contains(&1));
    }

    #[test]
    fn auth_flood_cannot_consume_telemetry_bucket_or_reserved_permits() {
        let state = ApiProtectionState::new(ApiRateLimitConfig::default());
        let now = Instant::now();
        let peer = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 99));

        for _ in 0..state.config.auth_peer_capacity {
            assert!(check_bucket_at(
                &state.auth_peers,
                peer,
                state.config.auth_peer_capacity,
                state.config.auth_peer_refill_per_minute,
                now,
            )
            .is_ok());
        }
        assert!(check_bucket_at(
            &state.auth_peers,
            peer,
            state.config.auth_peer_capacity,
            state.config.auth_peer_refill_per_minute,
            now,
        )
        .is_err());
        assert!(check_bucket_at(
            &state.telemetry_peers,
            peer,
            state.config.telemetry_peer_capacity,
            state.config.telemetry_peer_refill_per_minute,
            now,
        )
        .is_ok());

        let auth_permits = (0..state.config.auth_max_in_flight)
            .map(|_| state.auth.clone().try_acquire_owned().unwrap())
            .collect::<Vec<_>>();
        let shared_for_auth = (0..state.config.auth_max_in_flight)
            .map(|_| state.shared.clone().try_acquire_owned().unwrap())
            .collect::<Vec<_>>();
        let argon2_permits = (0..state.config.argon2_max_in_flight)
            .map(|_| state.argon2.clone().try_acquire_owned().unwrap())
            .collect::<Vec<_>>();
        assert!(state.auth.clone().try_acquire_owned().is_err());
        assert!(state.argon2.clone().try_acquire_owned().is_err());

        let telemetry_permit = state.telemetry.clone().try_acquire_owned().unwrap();
        let telemetry_shared_permit = state.shared.clone().try_acquire_owned().unwrap();
        drop((
            telemetry_permit,
            telemetry_shared_permit,
            auth_permits,
            shared_for_auth,
            argon2_permits,
        ));
        assert_eq!(
            state.auth.available_permits(),
            state.config.auth_max_in_flight
        );
        assert_eq!(
            state.telemetry.available_permits(),
            state.config.telemetry_max_in_flight
        );
        assert_eq!(state.shared.available_permits(), state.config.max_in_flight);
        assert_eq!(
            state.argon2.available_permits(),
            state.config.argon2_max_in_flight
        );
    }

    #[test]
    fn cancelled_or_timed_out_work_releases_compartment_permits() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let state = ApiProtectionState::new(ApiRateLimitConfig::default());
            let telemetry_timeout = tokio::time::timeout(Duration::from_millis(1), {
                let state = state.clone();
                async move {
                    let _telemetry = state.telemetry.clone().acquire_owned().await.unwrap();
                    let _shared = state.shared.clone().acquire_owned().await.unwrap();
                    std::future::pending::<()>().await;
                }
            })
            .await;
            assert!(telemetry_timeout.is_err());
            let auth_timeout = tokio::time::timeout(Duration::from_millis(1), {
                let state = state.clone();
                async move {
                    let _auth = state.auth.clone().acquire_owned().await.unwrap();
                    let _shared = state.shared.clone().acquire_owned().await.unwrap();
                    let _argon2 = state.argon2.clone().acquire_owned().await.unwrap();
                    std::future::pending::<()>().await;
                }
            })
            .await;
            assert!(auth_timeout.is_err());
            let ordinary_timeout = tokio::time::timeout(Duration::from_millis(1), {
                let state = state.clone();
                async move {
                    let _ordinary = state.other.clone().acquire_owned().await.unwrap();
                    let _shared = state.shared.clone().acquire_owned().await.unwrap();
                    std::future::pending::<()>().await;
                }
            })
            .await;
            assert!(ordinary_timeout.is_err());
            assert_eq!(
                state.telemetry.available_permits(),
                state.config.telemetry_max_in_flight
            );
            assert_eq!(
                state.auth.available_permits(),
                state.config.auth_max_in_flight
            );
            assert_eq!(
                state.other.available_permits(),
                state.config.max_in_flight
                    - state.config.telemetry_max_in_flight
                    - state.config.auth_max_in_flight
            );
            assert_eq!(
                state.argon2.available_permits(),
                state.config.argon2_max_in_flight
            );
            assert_eq!(state.shared.available_permits(), state.config.max_in_flight);
        });
    }
}
