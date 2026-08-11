use crate::{
    api::{
        access::ApiError,
        auth_service::{
            revoke_all_user_tokens, sign_access_token, verify_password_and_load_active_user,
        },
        middleware::{validate_cookie_request_origin_headers, ApiProtectionState},
    },
    auth::{
        access_token_cookie, clear_access_token_cookie, clear_refresh_token_cookie,
        jwt::{sign_refresh_token, verify_refresh_token, AuthState, CurrentUser},
        refresh_token_cookie, REFRESH_TOKEN_COOKIE,
    },
    config::OidcConfig,
    database::Database,
    models::user::{LoginRequest, LoginResponse, RefreshRequest, RefreshResponse},
};
use axum::{
    body::Bytes,
    extract::Extension,
    http::{header, HeaderMap, StatusCode},
    Json,
};
use axum_extra::extract::cookie::CookieJar;

pub async fn handle_login(
    Extension(db): Extension<Database>,
    Extension(auth_state): Extension<AuthState>,
    Extension(oidc_config): Extension<OidcConfig>,
    Extension(protection): Extension<ApiProtectionState>,
    jar: CookieJar,
    Json(payload): Json<LoginRequest>,
) -> Result<(CookieJar, Json<LoginResponse>), ApiError> {
    let user = verify_password_and_load_active_user(
        &db,
        &protection,
        &payload.username,
        &payload.password,
    )
    .await?;

    let access_token = sign_access_token(&user, &auth_state)?;
    let refresh_token = sign_refresh_token(
        &user,
        &auth_state.jwt_secret,
        auth_state.refresh_expiry_days,
    )
    .map_err(|_| ApiError::internal("refresh token sign failed"))?;

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
    body: Bytes,
) -> Result<(CookieJar, Json<RefreshResponse>), ApiError> {
    let payload = if body.is_empty() {
        None
    } else {
        require_json_content_type(&headers)?;
        Some(
            serde_json::from_slice::<RefreshRequest>(&body)
                .map_err(|_| ApiError::bad_request("invalid JSON request body"))?,
        )
    };
    let cookie_refresh_token = jar
        .get(REFRESH_TOKEN_COOKIE)
        .map(|cookie| cookie.value().to_string());
    if cookie_refresh_token.is_some() && !oidc_config.allowed_origins.is_empty() {
        validate_cookie_request_origin_headers(&headers, &oidc_config)
            .map_err(|(status, Json(body))| ApiError::with_body(status, body))?;
    }
    let refresh_token = cookie_refresh_token
        .or_else(|| payload.map(|payload| payload.refresh_token))
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "missing refresh token"))?;

    let (user_id, token_ver) = verify_refresh_token(&refresh_token, &auth_state.jwt_secret)
        .map_err(|_| ApiError::new(StatusCode::UNAUTHORIZED, "invalid refresh token"))?;

    let user = db
        .find_user_by_id(user_id)
        .await
        .map_err(|_| ApiError::internal("user lookup failed"))?
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "invalid refresh token user"))?;

    if !user.is_active || user.token_version != token_ver {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "token revoked"));
    }

    let access_token = sign_access_token(&user, &auth_state)?;
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
    body: Bytes,
) -> Result<(CookieJar, StatusCode), ApiError> {
    // 即使注销不使用请求体，也必须完整消费，确保大小限制与总超时生效。
    let _ = body;
    revoke_all_user_tokens(&db, current.id).await?;
    let jar = jar
        .add(clear_access_token_cookie(&oidc_config))
        .add(clear_refresh_token_cookie(&oidc_config));
    Ok((jar, StatusCode::NO_CONTENT))
}

fn require_json_content_type(headers: &HeaderMap) -> Result<(), ApiError> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(';').next().unwrap_or_default().trim());
    if content_type.is_some_and(|mime| mime.eq_ignore_ascii_case("application/json")) {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Content-Type must be application/json",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;

    #[test]
    fn refresh_body_requires_json_content_type() {
        let mut headers = HeaderMap::new();
        assert_eq!(
            require_json_content_type(&headers)
                .unwrap_err()
                .into_response()
                .status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );

        headers.insert(header::CONTENT_TYPE, "text/plain".parse().unwrap());
        assert_eq!(
            require_json_content_type(&headers)
                .unwrap_err()
                .into_response()
                .status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );

        headers.insert(
            header::CONTENT_TYPE,
            "application/json; charset=utf-8".parse().unwrap(),
        );
        assert!(require_json_content_type(&headers).is_ok());
    }
}
