use crate::{
    api::{
        access::ApiError,
        auth_service::{
            revoke_all_user_tokens, sign_access_token, verify_password_and_load_active_user,
        },
        middleware::{
            cache_token_rejection, is_token_cached_rejected, token_cache_scope, ApiProtectionState,
        },
    },
    audit::{AuditEvent, AuditService},
    auth::jwt::{verify_token, AuthState, CurrentUser},
    database::Database,
    models::user::{validate_safe_user_id, User},
    security::SecurityPolicyState,
};
use axum::{
    body::Bytes,
    extract::{connect_info::ConnectInfo, Extension},
    http::{header, HeaderMap, Request, StatusCode},
    middleware::Next,
    response::Response,
    Json,
};
use serde_derive::{Deserialize, Serialize};
use serde_json::json;
use serde_json::Value;
use std::net::SocketAddr;

const MAX_DEVICE_ID_SCALARS: usize = 100;
const MAX_UUID_BYTES: usize = 64;
const MAX_DEVICE_INFO_BYTES: usize = 16 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientLoginRequest {
    username: String,
    password: String,
    #[serde(rename = "type")]
    login_type: Option<String>,
    id: Option<String>,
    uuid: Option<String>,
    #[serde(rename = "autoLogin")]
    auto_login: Option<bool>,
    #[serde(rename = "deviceInfo")]
    device_info: Option<Value>,
    #[serde(rename = "verificationCode")]
    verification_code: Option<Value>,
    #[serde(rename = "tfaCode")]
    tfa_code: Option<Value>,
    secret: Option<Value>,
}

impl std::fmt::Debug for ClientLoginRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClientLoginRequest")
            .field("username", &"<redacted>")
            .field("password", &"<redacted>")
            .field("login_type_present", &self.login_type.is_some())
            .field("id_present", &self.id.is_some())
            .field("uuid", &self.uuid.as_ref().map(|_| "<redacted>"))
            .field("auto_login", &self.auto_login)
            .field("device_info_present", &self.device_info.is_some())
            .field(
                "verification_code_present",
                &self.verification_code.is_some(),
            )
            .field("tfa_code_present", &self.tfa_code.is_some())
            .field("secret_present", &self.secret.is_some())
            .finish()
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientIdentityRequest {
    id: Option<String>,
    uuid: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ClientUserDto {
    pub id: i64,
    pub name: String,
    pub display_name: String,
    pub avatar: String,
    pub email: String,
    pub note: String,
    pub status: i32,
    pub is_admin: bool,
    pub verifier: String,
}

impl TryFrom<User> for ClientUserDto {
    type Error = ApiError;

    fn try_from(user: User) -> Result<Self, Self::Error> {
        validate_safe_user_id(user.id).map_err(|_| ApiError::internal("invalid user id"))?;
        Ok(Self {
            id: user.id,
            name: user.username.clone(),
            display_name: user.username,
            avatar: String::new(),
            email: user.email.unwrap_or_default(),
            note: String::new(),
            status: 1,
            is_admin: user.role == "admin",
            verifier: String::new(),
        })
    }
}

#[derive(Serialize)]
pub struct ClientLoginResponse {
    #[serde(rename = "type")]
    response_type: &'static str,
    access_token: String,
    user: ClientUserDto,
}

impl std::fmt::Debug for ClientLoginResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClientLoginResponse")
            .field("response_type", &self.response_type)
            .field("access_token", &"<redacted>")
            .field("user", &self.user)
            .finish()
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_client_login(
    Extension(db): Extension<Database>,
    Extension(auth_state): Extension<AuthState>,
    Extension(protection): Extension<ApiProtectionState>,
    Extension(security): Extension<SecurityPolicyState>,
    Extension(audit): Extension<AuditService>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<ClientLoginResponse>, ApiError> {
    require_json_or_text(&headers)?;
    let value = parse_json_value(&body)?;
    validate_client_login_json(&value)?;
    let payload: ClientLoginRequest = serde_json::from_value(value)
        .map_err(|_| ApiError::bad_request("invalid JSON request body"))?;
    validate_login_request(&payload)?;

    let user = verify_password_and_load_active_user(
        &db,
        &protection,
        &security,
        &audit,
        peer.ip(),
        &payload.username,
        &payload.password,
    )
    .await?;
    let (access_token, _) = sign_access_token(&user, &auth_state, &security)?;
    audit.record(
        AuditEvent::new("auth.login.success")
            .actor(user.id)
            .target("user", user.id.to_string())
            .ip(peer.ip())
            .detail(json!({"method": "client_password"})),
    );
    let user = ClientUserDto::try_from(user)?;
    Ok(Json(ClientLoginResponse {
        response_type: "access_token",
        access_token,
        user,
    }))
}

pub async fn handle_current_user(
    Extension(db): Extension<Database>,
    Extension(current): Extension<CurrentUser>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<ClientUserDto>, ApiError> {
    parse_optional_identity(&headers, &body)?;
    let user = db
        .find_user_by_id(current.id)
        .await
        .map_err(|_| ApiError::internal("user lookup failed"))?
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "invalid token user"))?;
    Ok(Json(ClientUserDto::try_from(user)?))
}

pub async fn handle_client_logout(
    Extension(db): Extension<Database>,
    Extension(current): Extension<CurrentUser>,
    Extension(audit): Extension<AuditService>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    parse_optional_identity(&headers, &body)?;
    revoke_all_user_tokens(&db, current.id).await?;
    audit.record(
        AuditEvent::new("auth.logout")
            .actor(current.id)
            .target("user", current.id.to_string())
            .ip(peer.ip())
            .detail(json!({"client": true})),
    );
    Ok(StatusCode::NO_CONTENT)
}

pub async fn header_only_auth_layer<B>(
    mut request: Request<B>,
    next: Next<B>,
) -> Result<Response, ApiError> {
    let current = authenticate_explicit_header(&request)
        .await?
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "missing authorization header"))?;
    request.extensions_mut().insert(current);
    Ok(next.run(request).await)
}

pub async fn optional_header_auth_layer<B>(
    mut request: Request<B>,
    next: Next<B>,
) -> Result<Response, ApiError> {
    if let Some(current) = authenticate_explicit_header(&request).await? {
        request.extensions_mut().insert(current);
    }
    Ok(next.run(request).await)
}

async fn authenticate_explicit_header<B>(
    request: &Request<B>,
) -> Result<Option<CurrentUser>, ApiError> {
    let Some(token) = extract_single_bearer(request.headers())? else {
        return Ok(None);
    };
    let db = request
        .extensions()
        .get::<Database>()
        .cloned()
        .ok_or_else(|| ApiError::internal("db not available"))?;
    let auth_state = request
        .extensions()
        .get::<AuthState>()
        .cloned()
        .ok_or_else(|| ApiError::internal("auth state not available"))?;
    let security = request
        .extensions()
        .get::<SecurityPolicyState>()
        .cloned()
        .ok_or_else(|| ApiError::internal("security policy not available"))?;
    let claims = verify_token(token, &auth_state.jwt_secret)
        .map_err(|_| ApiError::new(StatusCode::UNAUTHORIZED, "invalid token"))?;
    let issued_at = i64::try_from(claims.iat)
        .map_err(|_| ApiError::new(StatusCode::UNAUTHORIZED, "invalid token"))?;
    security
        .validate_session_issued_at(issued_at)
        .map_err(|_| ApiError::new(StatusCode::UNAUTHORIZED, "session expired"))?;
    let cache_scope = token_cache_scope(&auth_state.jwt_secret, db.auth_cache_scope());
    if is_token_cached_rejected(cache_scope, claims.sub, claims.token_ver) {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "token revoked"));
    }

    let user = db
        .find_user_by_id(claims.sub)
        .await
        .map_err(|_| ApiError::internal("token version check failed"))?
        .ok_or_else(|| {
            cache_token_rejection(cache_scope, claims.sub, claims.token_ver);
            ApiError::new(StatusCode::UNAUTHORIZED, "invalid token user")
        })?;
    if !user.is_active || user.token_version != claims.token_ver {
        cache_token_rejection(cache_scope, claims.sub, claims.token_ver);
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            if user.is_active {
                "token revoked"
            } else {
                "account disabled"
            },
        ));
    }
    match user.role.as_str() {
        "admin" | "user" | "viewer" => {}
        _ => return Err(ApiError::forbidden("unknown role is not permitted")),
    }
    if user.role == "admin" {
        let peer = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|peer| peer.0.ip())
            .ok_or_else(|| {
                ApiError::service_unavailable("peer address unavailable; request rejected")
            })?;
        if !security
            .admin_ip_allowed(peer)
            .map_err(|_| ApiError::internal("administrator IP policy check failed"))?
        {
            if let Some(audit) = request.extensions().get::<AuditService>() {
                audit.record(
                    AuditEvent::new("auth.session.ip_denied")
                        .actor(user.id)
                        .target("user", user.id.to_string())
                        .ip(peer)
                        .detail(json!({"reason": "admin_ip_not_allowed"})),
                );
            }
            return Err(ApiError::forbidden("administrator IP is not allowed"));
        }
    }
    validate_safe_user_id(user.id).map_err(|_| ApiError::internal("invalid user id"))?;
    Ok(Some(CurrentUser {
        id: user.id,
        username: user.username,
        role: user.role,
    }))
}

fn extract_single_bearer(headers: &HeaderMap) -> Result<Option<&str>, ApiError> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "multiple authorization headers are not allowed",
        ));
    }
    let value = value
        .to_str()
        .map_err(|_| ApiError::new(StatusCode::UNAUTHORIZED, "invalid authorization header"))?;
    let token = value
        .strip_prefix("Bearer ")
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "invalid authorization format"))?;
    if token.is_empty()
        || token.trim() != token
        || token
            .bytes()
            .any(|byte| byte == b',' || byte.is_ascii_whitespace())
    {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "invalid authorization format",
        ));
    }
    Ok(Some(token))
}

fn validate_login_request(payload: &ClientLoginRequest) -> Result<(), ApiError> {
    if payload.login_type.as_deref().unwrap_or("account") != "account" {
        return Err(ApiError::bad_request("unsupported login type"));
    }
    if payload.verification_code.is_some() || payload.tfa_code.is_some() || payload.secret.is_some()
    {
        return Err(ApiError::bad_request(
            "verification and TFA login are not supported",
        ));
    }
    validate_identity_pair(payload.id.as_deref(), payload.uuid.as_deref())?;
    if let Some(device_info) = payload.device_info.as_ref() {
        if !device_info.is_object() {
            return Err(ApiError::bad_request("deviceInfo must be an object"));
        }
        if serde_json::to_vec(device_info)
            .map_err(|_| ApiError::bad_request("invalid deviceInfo"))?
            .len()
            > MAX_DEVICE_INFO_BYTES
        {
            return Err(ApiError::bad_request("deviceInfo exceeds 16 KiB"));
        }
    }
    let _ = payload.auto_login;
    Ok(())
}

fn parse_optional_identity(headers: &HeaderMap, body: &[u8]) -> Result<(), ApiError> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(());
    }
    require_json_or_text(headers)?;
    let value = parse_json_value(body)?;
    let object = value
        .as_object()
        .ok_or_else(|| ApiError::bad_request("invalid JSON request body"))?;
    for name in ["id", "uuid"] {
        if object.get(name).is_some_and(|value| !value.is_string()) {
            return Err(ApiError::bad_request("invalid identity field type"));
        }
    }
    let payload: ClientIdentityRequest = serde_json::from_value(value)
        .map_err(|_| ApiError::bad_request("invalid JSON request body"))?;
    validate_identity_pair(payload.id.as_deref(), payload.uuid.as_deref())
}

pub fn validate_identity_pair(id: Option<&str>, uuid: Option<&str>) -> Result<(), ApiError> {
    match (id, uuid) {
        (None, None) => Ok(()),
        (Some(id), Some(uuid)) => {
            let id_len = id.chars().count();
            if !(1..=MAX_DEVICE_ID_SCALARS).contains(&id_len) || id.chars().any(char::is_control) {
                return Err(ApiError::bad_request("invalid device id"));
            }
            let decoded =
                base64::decode(uuid).map_err(|_| ApiError::bad_request("invalid device uuid"))?;
            if decoded.is_empty() || decoded.len() > MAX_UUID_BYTES {
                return Err(ApiError::bad_request("invalid device uuid"));
            }
            Ok(())
        }
        _ => Err(ApiError::bad_request(
            "id and uuid must be provided together",
        )),
    }
}

pub fn decode_uuid(uuid: &str) -> Result<Vec<u8>, ApiError> {
    validate_identity_pair(Some("validated-device"), Some(uuid))?;
    base64::decode(uuid).map_err(|_| ApiError::bad_request("invalid device uuid"))
}

fn require_json_or_text(headers: &HeaderMap) -> Result<(), ApiError> {
    let value = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "Content-Type must be application/json or text/plain",
            )
        })?;
    let mime = value.split(';').next().unwrap_or_default().trim();
    if mime.eq_ignore_ascii_case("application/json") || mime.eq_ignore_ascii_case("text/plain") {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Content-Type must be application/json or text/plain",
        ))
    }
}

fn parse_json<T>(body: &[u8]) -> Result<T, ApiError>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_slice(body).map_err(|_| ApiError::bad_request("invalid JSON request body"))
}

fn parse_json_value(body: &[u8]) -> Result<Value, ApiError> {
    parse_json(body)
}

fn validate_client_login_json(value: &Value) -> Result<(), ApiError> {
    let object = value
        .as_object()
        .ok_or_else(|| ApiError::bad_request("invalid JSON request body"))?;
    if ["verificationCode", "tfaCode", "secret"]
        .iter()
        .any(|name| object.contains_key(*name))
    {
        return Err(ApiError::bad_request(
            "verification and TFA login are not supported",
        ));
    }
    for name in ["type", "id", "uuid"] {
        if object.get(name).is_some_and(|value| !value.is_string()) {
            return Err(ApiError::bad_request("invalid login field type"));
        }
    }
    if object
        .get("autoLogin")
        .is_some_and(|value| !value.is_boolean())
    {
        return Err(ApiError::bad_request("autoLogin must be a boolean"));
    }
    if object
        .get("deviceInfo")
        .is_some_and(|value| !value.is_object())
    {
        return Err(ApiError::bad_request("deviceInfo must be an object"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_requires_a_valid_pair() {
        assert!(validate_identity_pair(None, None).is_ok());
        assert!(validate_identity_pair(Some("device"), None).is_err());
        assert!(validate_identity_pair(Some("device"), Some(&base64::encode([1_u8; 16]))).is_ok());
        assert!(validate_identity_pair(Some("bad\nid"), Some(&base64::encode([1_u8]))).is_err());
    }

    #[test]
    fn duplicate_or_empty_bearer_is_rejected() {
        let mut headers = HeaderMap::new();
        headers.append(header::AUTHORIZATION, "Bearer first".parse().unwrap());
        headers.append(header::AUTHORIZATION, "Bearer second".parse().unwrap());
        assert!(extract_single_bearer(&headers).is_err());

        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer ".parse().unwrap());
        assert!(extract_single_bearer(&headers).is_err());
    }

    #[test]
    fn client_auth_debug_output_redacts_credentials() {
        let password = "sentinel-client-password";
        let token = "sentinel-client-token";
        let device_info_secret = "sentinel-device-info-secret";
        let login_type_secret = "sentinel-login-type-secret";
        let request = ClientLoginRequest {
            username: "alice".to_owned(),
            password: password.to_owned(),
            login_type: Some(login_type_secret.to_owned()),
            id: None,
            uuid: None,
            auto_login: None,
            device_info: Some(serde_json::json!({
                "nested": {
                    "token": device_info_secret
                }
            })),
            verification_code: None,
            tfa_code: None,
            secret: None,
        };
        let response = ClientLoginResponse {
            response_type: "access_token",
            access_token: token.to_owned(),
            user: ClientUserDto {
                id: 1,
                name: "alice".to_owned(),
                display_name: "Alice".to_owned(),
                avatar: String::new(),
                email: String::new(),
                note: String::new(),
                status: 1,
                is_admin: false,
                verifier: String::new(),
            },
        };

        assert!(!format!("{request:?}").contains(password));
        assert!(!format!("{request:?}").contains(device_info_secret));
        assert!(!format!("{request:?}").contains(login_type_secret));
        assert!(!format!("{response:?}").contains(token));
    }

    #[test]
    fn optional_login_and_identity_fields_reject_json_null() {
        for field in [
            r#""type":null"#,
            r#""autoLogin":null"#,
            r#""deviceInfo":null"#,
            r#""verificationCode":null"#,
            r#""tfaCode":null"#,
            r#""secret":null"#,
            r#""id":null,"uuid":null"#,
        ] {
            let value: Value = serde_json::from_str(&format!(
                r#"{{"username":"alice","password":"secret",{field}}}"#
            ))
            .unwrap();
            assert!(validate_client_login_json(&value).is_err(), "{field}");
        }

        let headers =
            HeaderMap::from_iter([(header::CONTENT_TYPE, "application/json".parse().unwrap())]);
        assert!(parse_optional_identity(&headers, br#"{"id":null,"uuid":null}"#).is_err());
    }
}
