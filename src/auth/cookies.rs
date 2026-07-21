use crate::config::OidcConfig;
use axum_extra::extract::cookie::{Cookie, SameSite};
use cookie::time::Duration;

pub const ACCESS_TOKEN_COOKIE: &str = "access_token";
pub const REFRESH_TOKEN_COOKIE: &str = "refresh_token";

pub fn cookie_same_site(config: &OidcConfig) -> SameSite {
    if config.allowed_origins.is_empty() {
        SameSite::Lax
    } else {
        SameSite::None
    }
}

pub fn access_token_cookie(
    token: String,
    config: &OidcConfig,
    expiry_hours: i64,
) -> Cookie<'static> {
    Cookie::build(ACCESS_TOKEN_COOKIE, token)
        .http_only(true)
        .secure(true)
        .same_site(cookie_same_site(config))
        .path("/")
        .max_age(Duration::hours(expiry_hours))
        .finish()
}

pub fn refresh_token_cookie(
    token: String,
    config: &OidcConfig,
    expiry_days: i64,
) -> Cookie<'static> {
    Cookie::build(REFRESH_TOKEN_COOKIE, token)
        .http_only(true)
        .secure(true)
        .same_site(cookie_same_site(config))
        .path("/api/auth/refresh")
        .max_age(Duration::days(expiry_days))
        .finish()
}

pub fn clear_access_token_cookie(config: &OidcConfig) -> Cookie<'static> {
    Cookie::build(ACCESS_TOKEN_COOKIE, "")
        .http_only(true)
        .secure(true)
        .same_site(cookie_same_site(config))
        .path("/")
        .max_age(Duration::seconds(0))
        .finish()
}

pub fn clear_refresh_token_cookie(config: &OidcConfig) -> Cookie<'static> {
    Cookie::build(REFRESH_TOKEN_COOKIE, "")
        .http_only(true)
        .secure(true)
        .same_site(cookie_same_site(config))
        .path("/api/auth/refresh")
        .max_age(Duration::seconds(0))
        .finish()
}
