use crate::{
    api::middleware::{invalidate_token_cache, validate_cookie_request_origin_headers},
    auth::{
        access_token_cookie, clear_access_token_cookie, clear_refresh_token_cookie,
        jwt::{sign_refresh_token, sign_token, verify_refresh_token, AuthState, CurrentUser},
        refresh_token_cookie, REFRESH_TOKEN_COOKIE,
    },
    config::OidcConfig,
    database::Database,
    models::user::{LoginRequest, LoginResponse, RefreshRequest, RefreshResponse},
};
use argon2::{
    password_hash::{PasswordHash, PasswordVerifier},
    Argon2,
};
use axum::{
    extract::Extension,
    http::{HeaderMap, StatusCode},
    Json,
};
use axum_extra::extract::cookie::CookieJar;
use serde_json::{json, Value};

type ApiError = (StatusCode, Json<Value>);

pub async fn handle_login(
    Extension(db): Extension<Database>,
    Extension(auth_state): Extension<AuthState>,
    Extension(oidc_config): Extension<OidcConfig>,
    jar: CookieJar,
    Json(payload): Json<LoginRequest>,
) -> Result<(CookieJar, Json<LoginResponse>), ApiError> {
    let user = db
        .find_user_by_username(&payload.username)
        .await
        .map_err(|_| internal_error("user lookup failed"))?
        .ok_or_else(invalid_credentials)?;

    if !user.is_active {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "account disabled" })),
        ));
    }
    if !verify_password(&payload.password, &user.password_hash) {
        return Err(invalid_credentials());
    }

    let access_token = sign_token(&user, &auth_state.jwt_secret, auth_state.jwt_expiry_hours)
        .map_err(|_| internal_error("token sign failed"))?;
    let refresh_token = sign_refresh_token(
        &user,
        &auth_state.jwt_secret,
        auth_state.refresh_expiry_days,
    )
    .map_err(|_| internal_error("refresh token sign failed"))?;

    let jar = jar
        .add(access_token_cookie(
            access_token.clone(),
            &oidc_config,
            auth_state.jwt_expiry_hours,
        ))
        .add(refresh_token_cookie(
            refresh_token.clone(),
            &oidc_config,
            auth_state.refresh_expiry_days,
        ));

    Ok((
        jar,
        Json(LoginResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: auth_state.jwt_expiry_hours * 3600,
            refresh_token,
        }),
    ))
}

pub async fn handle_refresh(
    Extension(db): Extension<Database>,
    Extension(auth_state): Extension<AuthState>,
    Extension(oidc_config): Extension<OidcConfig>,
    headers: HeaderMap,
    jar: CookieJar,
    payload: Option<Json<RefreshRequest>>,
) -> Result<(CookieJar, Json<RefreshResponse>), ApiError> {
    let cookie_refresh_token = jar
        .get(REFRESH_TOKEN_COOKIE)
        .map(|cookie| cookie.value().to_string());
    if cookie_refresh_token.is_some() && !oidc_config.allowed_origins.is_empty() {
        validate_cookie_request_origin_headers(&headers, &oidc_config)?;
    }
    let refresh_token = cookie_refresh_token
        .or_else(|| payload.map(|Json(payload)| payload.refresh_token))
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "missing refresh token" })),
            )
        })?;

    let (user_id, token_ver) = verify_refresh_token(&refresh_token, &auth_state.jwt_secret)
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "invalid refresh token" })),
            )
        })?;

    let user = db
        .find_user_by_id(user_id)
        .await
        .map_err(|_| internal_error("user lookup failed"))?
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "invalid refresh token user" })),
            )
        })?;

    if !user.is_active || user.token_version != token_ver {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "token revoked" })),
        ));
    }

    let access_token = sign_token(&user, &auth_state.jwt_secret, auth_state.jwt_expiry_hours)
        .map_err(|_| internal_error("token sign failed"))?;
    let jar = jar.add(access_token_cookie(
        access_token.clone(),
        &oidc_config,
        auth_state.jwt_expiry_hours,
    ));

    Ok((
        jar,
        Json(RefreshResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: auth_state.jwt_expiry_hours * 3600,
        }),
    ))
}

pub async fn handle_logout(
    Extension(db): Extension<Database>,
    Extension(current): Extension<CurrentUser>,
    Extension(oidc_config): Extension<OidcConfig>,
    jar: CookieJar,
) -> Result<(CookieJar, StatusCode), ApiError> {
    db.increment_token_version(current.id)
        .await
        .map_err(|_| internal_error("logout failed"))?;
    invalidate_token_cache(current.id);
    let jar = jar
        .add(clear_access_token_cookie(&oidc_config))
        .add(clear_refresh_token_cookie(&oidc_config));
    Ok((jar, StatusCode::NO_CONTENT))
}

fn verify_password(password: &str, password_hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(password_hash) {
        Ok(hash) => hash,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

fn invalid_credentials() -> ApiError {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": "invalid username or password" })),
    )
}

fn internal_error(message: &str) -> ApiError {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": message })),
    )
}
