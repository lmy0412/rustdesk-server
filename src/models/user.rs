use chrono::NaiveDateTime;
use serde_derive::{Deserialize, Serialize};
use std::fmt;

pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
pub const MAX_USERNAME_SCALARS: usize = 100;
pub const MAX_PLAIN_PASSWORD_BYTES: usize = 1024;

#[derive(Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: i64,
    pub username: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub email: Option<String>,
    pub role: String,
    pub is_active: bool,
    #[serde(skip_serializing)]
    pub token_version: i64,
    #[serde(skip_serializing)]
    pub failed_login_count: i64,
    #[serde(skip_serializing)]
    pub locked_until: Option<NaiveDateTime>,
    #[serde(skip_serializing)]
    pub oauth_provider: Option<String>,
    #[serde(skip_serializing)]
    pub oauth_subject: Option<String>,
    pub last_login_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UserSummary {
    pub id: i64,
    pub username: String,
    pub email: Option<String>,
    pub role: String,
    pub is_active: bool,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

impl From<User> for UserSummary {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role,
            is_active: user.is_active,
            created_at: user.created_at,
            updated_at: user.updated_at,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

impl fmt::Debug for User {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("User")
            .field("id", &self.id)
            .field("username", &self.username)
            .field("password_hash", &"<redacted>")
            .field("email", &self.email)
            .field("role", &self.role)
            .field("is_active", &self.is_active)
            .field("token_version", &self.token_version)
            .field("failed_login_count", &self.failed_login_count)
            .field("locked_until", &self.locked_until)
            .field("oauth_provider", &self.oauth_provider)
            .field("oauth_subject", &self.oauth_subject)
            .field("last_login_at", &self.last_login_at)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

impl fmt::Debug for LoginRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoginRequest")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token: String,
}

impl fmt::Debug for LoginResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoginResponse")
            .field("access_token", &"<redacted>")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("refresh_token", &"<redacted>")
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

impl fmt::Debug for RefreshRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RefreshRequest")
            .field("refresh_token", &"<redacted>")
            .finish()
    }
}

#[derive(Serialize)]
pub struct RefreshResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

impl fmt::Debug for RefreshResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RefreshResponse")
            .field("access_token", &"<redacted>")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    pub email: Option<String>,
    #[serde(default = "default_role")]
    pub role: String,
}

impl fmt::Debug for CreateUserRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreateUserRequest")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("email", &self.email)
            .field("role", &self.role)
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateUserRequest {
    pub email: Option<String>,
    pub role: Option<String>,
    pub is_active: Option<bool>,
    pub password: Option<String>,
    pub force_logout: Option<bool>,
}

impl fmt::Debug for UpdateUserRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UpdateUserRequest")
            .field("email", &self.email)
            .field("role", &self.role)
            .field("is_active", &self.is_active)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("force_logout", &self.force_logout)
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangePasswordRequest {
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminInitInfo {
    pub username: String,
}

impl fmt::Debug for ChangePasswordRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChangePasswordRequest")
            .field("password", &"<redacted>")
            .finish()
    }
}

fn default_role() -> String {
    "user".to_string()
}

pub fn validate_username(username: &str) -> Result<(), &'static str> {
    let count = username.chars().count();
    if !(1..=MAX_USERNAME_SCALARS).contains(&count) {
        return Err("username must contain 1 to 100 Unicode characters");
    }
    if username.chars().any(char::is_control) {
        return Err("username must not contain control characters");
    }
    Ok(())
}

pub fn validate_plain_password(password: &str) -> Result<(), &'static str> {
    if !(1..=MAX_PLAIN_PASSWORD_BYTES).contains(&password.len()) {
        return Err("password must contain 1 to 1024 UTF-8 bytes");
    }
    Ok(())
}

pub fn validate_safe_user_id(id: i64) -> Result<(), &'static str> {
    if !(1..=MAX_SAFE_INTEGER).contains(&id) {
        return Err("user id is outside the JSON safe integer range");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_validation_uses_unicode_scalars_without_trimming() {
        assert!(validate_username("a").is_ok());
        assert!(validate_username(&"用".repeat(100)).is_ok());
        assert!(validate_username("").is_err());
        assert!(validate_username(&"a".repeat(101)).is_err());
        assert!(validate_username("a\nb").is_err());
        assert!(validate_username(" alice ").is_ok());
    }

    #[test]
    fn password_validation_uses_utf8_bytes_without_trimming() {
        assert!(validate_plain_password(" ").is_ok());
        assert!(validate_plain_password(&"a".repeat(1024)).is_ok());
        assert!(validate_plain_password("").is_err());
        assert!(validate_plain_password(&"界".repeat(342)).is_err());
    }

    #[test]
    fn authentication_dtos_redact_secrets_from_debug_output() {
        let password = "sentinel-password";
        let token = "sentinel-access-token";
        let refresh = "sentinel-refresh-token";
        let login = format!(
            "{:?}",
            LoginRequest {
                username: "alice".to_owned(),
                password: password.to_owned(),
            }
        );
        let response = format!(
            "{:?}",
            LoginResponse {
                access_token: token.to_owned(),
                token_type: "Bearer".to_owned(),
                expires_in: 3600,
                refresh_token: refresh.to_owned(),
            }
        );

        assert!(!login.contains(password));
        assert!(!response.contains(token));
        assert!(!response.contains(refresh));
        assert!(login.contains("<redacted>"));
        assert!(response.contains("<redacted>"));
    }
}
