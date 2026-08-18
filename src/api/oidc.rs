use crate::{
    api::auth_service::sign_access_token,
    audit::{AuditEvent, AuditService},
    auth::{
        access_token_cookie,
        jwt::{sign_refresh_token, AuthState},
        oidc_http::oidc_http_client,
        refresh_token_cookie, OIDC_SESSIONS,
    },
    config::OidcConfig,
    database::Database,
    models::user::{validate_username, User},
    security::SecurityPolicyState,
};
use axum::{
    extract::{connect_info::ConnectInfo, Extension, Query},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use axum_extra::extract::cookie::CookieJar;
use hbb_common::log;
use openidconnect::{
    core::{CoreAuthenticationFlow, CoreClient, CoreClientAuthMethod, CoreProviderMetadata},
    AuthType, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};
use serde_derive::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::SocketAddr;

type ApiError = (StatusCode, Json<Value>);

#[derive(Debug, Serialize)]
pub struct OidcLoginResponse {
    pub authorization_url: String,
}

#[derive(Deserialize)]
pub struct OidcCallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

pub async fn handle_oidc_login(
    Extension(oidc_config): Extension<OidcConfig>,
) -> Result<Json<OidcLoginResponse>, ApiError> {
    if !oidc_config.is_configured() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "OIDC not configured" })),
        ));
    }

    let client = build_oidc_client(&oidc_config).await.map_err(|err| {
        log::error!("OIDC discovery failed: {}", err);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "Failed to connect to OIDC provider" })),
        )
    })?;
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (auth_url, csrf_state, nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    OIDC_SESSIONS.insert(
        csrf_state.secret().to_string(),
        pkce_verifier.secret().to_string(),
        nonce.secret().to_string(),
    );

    Ok(Json(OidcLoginResponse {
        authorization_url: auth_url.to_string(),
    }))
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_oidc_callback(
    Extension(db): Extension<Database>,
    Extension(auth_state): Extension<AuthState>,
    Extension(oidc_config): Extension<OidcConfig>,
    Extension(security): Extension<SecurityPolicyState>,
    Extension(audit): Extension<AuditService>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    jar: CookieJar,
    Query(query): Query<OidcCallbackQuery>,
) -> Response {
    if !oidc_config.is_configured() {
        return redirect_error_or_json(&oidc_config, "oidc_not_configured");
    }
    if query.error.is_some() {
        // Provider error/code/state 均来自回调查询，不得原样进入日志。
        log::warn!("OIDC provider returned an error");
        return redirect_error(&oidc_config, "invalid_request");
    }

    let Some(code) = query.code else {
        return redirect_error(&oidc_config, "invalid_request");
    };
    let Some(state) = query.state else {
        return redirect_error(&oidc_config, "invalid_request");
    };
    let Some(session) = OIDC_SESSIONS.take(&state) else {
        return redirect_error(&oidc_config, "expired_session");
    };

    let client = match build_oidc_client(&oidc_config).await {
        Ok(client) => client,
        Err(_) => {
            log::error!("OIDC discovery during callback failed");
            return redirect_error(&oidc_config, "token_exchange_failed");
        }
    };

    let token_response = match client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(PkceCodeVerifier::new(session.pkce_verifier))
        .request_async(oidc_http_client)
        .await
    {
        Ok(response) => response,
        Err(_) => {
            log::error!("OIDC token exchange failed");
            return redirect_error(&oidc_config, "token_exchange_failed");
        }
    };

    let Some(id_token) = token_response.id_token() else {
        log::error!("OIDC token response does not contain id_token");
        return redirect_error(&oidc_config, "id_token_invalid");
    };
    let nonce = Nonce::new(session.nonce);
    let claims = match id_token.claims(&client.id_token_verifier(), &nonce) {
        Ok(claims) => claims,
        Err(_) => {
            log::error!("OIDC id_token validation failed");
            return redirect_error(&oidc_config, "id_token_invalid");
        }
    };

    let subject = claims.subject().as_str().to_string();
    let email = claims.email().map(|email| email.as_str().to_string());
    let email_verified = claims.email_verified().unwrap_or(false);
    let verified_email = verified_email(email.as_deref(), email_verified);
    let preferred_username = claims
        .preferred_username()
        .map(|username| username.as_str().to_string());

    let user = match resolve_oidc_user(
        &db,
        &oidc_config.issuer_url,
        &subject,
        verified_email,
        preferred_username.as_deref(),
    )
    .await
    {
        Ok(user) => user,
        Err(OidcUserError::DuplicateEmail) => {
            return redirect_error(&oidc_config, "duplicate_email");
        }
        Err(err) => {
            log::error!("OIDC user resolve failed: {:?}", err);
            return redirect_error(&oidc_config, "user_creation_failed");
        }
    };

    if !user.is_active {
        audit.record(
            AuditEvent::new("auth.login.failure")
                .actor(user.id)
                .target("user", user.id.to_string())
                .ip(peer.ip())
                .detail(json!({"method": "oidc", "reason": "account_disabled"})),
        );
        return redirect_error(&oidc_config, "account_disabled");
    }
    if user.role == "admin" {
        match security.admin_ip_allowed(peer.ip()) {
            Ok(true) => {}
            Ok(false) => {
                audit.record(
                    AuditEvent::new("auth.login.ip_denied")
                        .actor(user.id)
                        .target("user", user.id.to_string())
                        .ip(peer.ip())
                        .detail(json!({"method": "oidc", "reason": "admin_ip_not_allowed"})),
                );
                return redirect_error(&oidc_config, "admin_ip_not_allowed");
            }
            Err(_) => return redirect_error(&oidc_config, "internal_error"),
        }
    }

    let (access_token, access_lifetime) = match sign_access_token(&user, &auth_state, &security) {
        Ok(token) => token,
        Err(_) => {
            log::error!("OIDC access token sign failed");
            return redirect_error(&oidc_config, "internal_error");
        }
    };
    let refresh_token = match sign_refresh_token(
        &user,
        &auth_state.jwt_secret,
        auth_state.refresh_expiry_days,
    ) {
        Ok(token) => token,
        Err(err) => {
            log::error!("OIDC refresh token sign failed: {}", err);
            return redirect_error(&oidc_config, "internal_error");
        }
    };

    let jar = jar
        .add(access_token_cookie(
            access_token,
            &oidc_config,
            access_lifetime,
        ))
        .add(refresh_token_cookie(
            refresh_token,
            &oidc_config,
            auth_state.refresh_expiry_days,
        ));
    audit.record(
        AuditEvent::new("auth.login.success")
            .actor(user.id)
            .target("user", user.id.to_string())
            .ip(peer.ip())
            .detail(json!({"method": "oidc"})),
    );
    redirect_with_jar(jar, &oidc_config.post_login_url)
}

async fn build_oidc_client(oidc_config: &OidcConfig) -> Result<CoreClient, String> {
    let provider_metadata = CoreProviderMetadata::discover_async(
        IssuerUrl::new(oidc_config.issuer_url.clone()).map_err(|err| err.to_string())?,
        oidc_http_client,
    )
    .await
    .map_err(|err| err.to_string())?;
    let auth_methods = provider_metadata
        .token_endpoint_auth_methods_supported()
        .cloned()
        .unwrap_or_default();
    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(oidc_config.client_id.clone()),
        Some(ClientSecret::new(oidc_config.client_secret.clone())),
    )
    .set_redirect_uri(
        RedirectUrl::new(oidc_config.redirect_uri.clone()).map_err(|err| err.to_string())?,
    );

    let client = if auth_methods.contains(&CoreClientAuthMethod::ClientSecretBasic) {
        client.set_auth_type(AuthType::BasicAuth)
    } else if auth_methods.contains(&CoreClientAuthMethod::ClientSecretPost) {
        client.set_auth_type(AuthType::RequestBody)
    } else {
        if !auth_methods.is_empty() {
            log::warn!(
                "OIDC provider token auth methods unsupported: {:?}",
                auth_methods
            );
        }
        client
    };
    Ok(client)
}

#[derive(Debug)]
enum OidcUserError {
    DuplicateEmail,
    Database,
}

async fn resolve_oidc_user(
    db: &Database,
    provider: &str,
    subject: &str,
    email: Option<&str>,
    preferred_username: Option<&str>,
) -> Result<User, OidcUserError> {
    if let Some(user) = db
        .find_user_by_oauth(provider, subject)
        .await
        .map_err(|_| OidcUserError::Database)?
    {
        return db
            .update_last_login(user.id)
            .await
            .map_err(|_| OidcUserError::Database);
    }

    if let Some(email) = email {
        let users = db
            .find_users_by_email(email)
            .await
            .map_err(|_| OidcUserError::Database)?;
        match users.len() {
            0 => {}
            1 => {
                return db
                    .link_user_to_oidc(users[0].id, provider, subject)
                    .await
                    .map_err(|_| OidcUserError::Database);
            }
            _ => return Err(OidcUserError::DuplicateEmail),
        }
    }

    let username = unique_oidc_username(db, preferred_username, email, subject).await?;
    db.create_oidc_user(&username, email, provider, subject)
        .await
        .map_err(|_| OidcUserError::Database)
}

async fn unique_oidc_username(
    db: &Database,
    preferred_username: Option<&str>,
    email: Option<&str>,
    subject: &str,
) -> Result<String, OidcUserError> {
    let base = preferred_username
        .filter(|value| !value.trim().is_empty())
        .or_else(|| email.and_then(|value| value.split('@').next()))
        .map(sanitize_username)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| format!("oidc-{}", sanitize_username(subject)));

    for index in 0..1000 {
        let candidate = if index == 0 {
            base.clone()
        } else {
            format!("{}-{}", base, index)
        };
        let exists = db
            .find_user_by_username(&candidate)
            .await
            .map_err(|_| OidcUserError::Database)?
            .is_some();
        if !exists {
            validate_username(&candidate).map_err(|_| OidcUserError::Database)?;
            return Ok(candidate);
        }
    }
    Err(OidcUserError::Database)
}

fn sanitize_username(value: &str) -> String {
    let username: String = value
        .chars()
        .filter_map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                Some(ch)
            } else {
                None
            }
        })
        .take(80)
        .collect();
    if username.is_empty() {
        "oidc-user".to_string()
    } else {
        username
    }
}

fn verified_email(email: Option<&str>, email_verified: bool) -> Option<&str> {
    if email_verified {
        email
    } else {
        None
    }
}

fn redirect_error_or_json(config: &OidcConfig, error: &str) -> Response {
    if config.post_login_url.trim().is_empty() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": error })),
        )
            .into_response();
    }
    redirect_error(config, error)
}

fn redirect_error(config: &OidcConfig, error: &str) -> Response {
    let separator = if config.post_login_url.contains('?') {
        "&"
    } else {
        "?"
    };
    let url = format!("{}{}error={}", config.post_login_url, separator, error);
    (StatusCode::FOUND, [(header::LOCATION, url)]).into_response()
}

fn redirect_with_jar(jar: CookieJar, url: &str) -> Response {
    (
        jar,
        (StatusCode::FOUND, [(header::LOCATION, url.to_string())]),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unverified_email_is_not_persisted_candidate() {
        assert_eq!(verified_email(Some("alice@example.com"), false), None);
    }

    #[test]
    fn test_verified_email_is_persisted_candidate() {
        assert_eq!(
            verified_email(Some("alice@example.com"), true),
            Some("alice@example.com")
        );
    }
}
