use figment::{
    providers::{Env, Format, Serialized, Toml},
    Figment,
};
use hbb_common::config::{RELAY_PORT, RENDEZVOUS_PORT};
use once_cell::sync::OnceCell;
use serde_derive::{Deserialize, Serialize};
use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

// ==========================
// Default value functions
// ==========================

fn default_id_server() -> String {
    format!("0.0.0.0:{}", RENDEZVOUS_PORT)
}
fn default_relay_server() -> String {
    format!("0.0.0.0:{}", RELAY_PORT)
}
fn default_api_server() -> String {
    "0.0.0.0:21114".to_string()
}
fn default_jwt_secret() -> String {
    uuid::Uuid::new_v4().to_string()
}
fn default_jwt_expiry_hours() -> i64 {
    24
}
fn default_refresh_expiry_days() -> i64 {
    7
}
fn default_password_min_length() -> usize {
    12
}
fn default_login_max_failures() -> u32 {
    5
}
fn default_login_lock_minutes() -> u32 {
    15
}
fn default_session_timeout_minutes() -> u32 {
    1440
}
fn default_audit_retention_days() -> u32 {
    180
}
fn default_key_file() -> String {
    "/var/lib/rustdesk/id_ed25519".to_string()
}
fn default_db_path() -> String {
    #[cfg(all(windows, not(debug_assertions)))]
    {
        let mut db = "db_v2.sqlite3".to_owned();
        if let Some(path) = hbb_common::config::Config::icon_path().parent() {
            db = format!("{}\\{}", path.to_str().unwrap_or("."), db);
        }
        db
    }
    #[cfg(all(windows, debug_assertions))]
    {
        "db_v2.sqlite3".to_string()
    }
    #[cfg(not(windows))]
    {
        "./db_v2.sqlite3".to_string()
    }
}
fn default_rendezvous_servers() -> Vec<String> {
    Vec::new()
}
fn default_key() -> String {
    "-".to_string()
}
fn default_max_single_bandwidth() -> u64 {
    128
}
fn default_max_total_bandwidth() -> u64 {
    1024
}
fn default_limit_speed() -> u64 {
    32
}
fn default_downgrade_threshold() -> f64 {
    0.66
}
fn default_downgrade_start_check() -> u64 {
    1800
}
fn default_api_max_in_flight() -> usize {
    1024
}
fn default_telemetry_max_in_flight() -> usize {
    768
}
fn default_auth_max_in_flight() -> usize {
    64
}
fn default_argon2_max_in_flight() -> usize {
    8
}
fn default_api_request_timeout_ms() -> u64 {
    10_000
}
fn default_telemetry_peer_capacity() -> u64 {
    36_000
}
fn default_telemetry_peer_refill_per_minute() -> u64 {
    18_000
}
fn default_auth_peer_capacity() -> u64 {
    60
}
fn default_auth_peer_refill_per_minute() -> u64 {
    30
}
fn default_device_capacity() -> u64 {
    120
}
fn default_device_refill_per_minute() -> u64 {
    60
}
fn default_address_book_actor_capacity() -> u64 {
    30
}
fn default_address_book_actor_refill_per_minute() -> u64 {
    15
}
fn default_peer_lru_capacity() -> usize {
    10_000
}
fn default_device_lru_capacity() -> usize {
    100_000
}
fn default_actor_lru_capacity() -> usize {
    100_000
}

// ==========================
// Config structs
// ==========================

/// SMTP configuration (Pro feature)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SmtpConfig {
    #[serde(default)]
    pub host: String,
    #[serde(default = "default_smtp_port")]
    pub port: u16,
    #[serde(default)]
    pub username: String,
    /// Sensitive field: will be masked in logs
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub from: String,
}

fn default_smtp_port() -> u16 {
    587
}

impl Default for SmtpConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: default_smtp_port(),
            username: String::new(),
            password: String::new(),
            from: String::new(),
        }
    }
}

/// OIDC configuration (Pro feature)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OidcConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub issuer_url: String,
    #[serde(default)]
    pub client_id: String,
    /// Sensitive field: will be masked in logs
    #[serde(default)]
    pub client_secret: String,
    #[serde(default)]
    pub redirect_uri: String,
    #[serde(default)]
    pub post_login_url: String,
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            issuer_url: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            redirect_uri: String::new(),
            post_login_url: String::new(),
            allowed_origins: Vec::new(),
        }
    }
}

impl OidcConfig {
    pub fn is_configured(&self) -> bool {
        self.enabled
            && !self.issuer_url.trim().is_empty()
            && !self.client_id.trim().is_empty()
            && !self.client_secret.trim().is_empty()
            && !self.redirect_uri.trim().is_empty()
            && !self.post_login_url.trim().is_empty()
    }
}

/// 企业安全策略。配置文件提供初始值，Web API 更新后由数据库值覆盖。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityConfig {
    #[serde(default = "default_password_min_length")]
    pub password_min_length: usize,
    #[serde(default = "default_true")]
    pub password_require_number: bool,
    #[serde(default = "default_true")]
    pub password_require_symbol: bool,
    #[serde(default = "default_login_max_failures")]
    pub login_max_failures: u32,
    #[serde(default = "default_login_lock_minutes")]
    pub login_lock_minutes: u32,
    #[serde(default = "default_session_timeout_minutes")]
    pub session_timeout_minutes: u32,
    #[serde(default)]
    pub allowed_admin_cidrs: Vec<String>,
    #[serde(default = "default_audit_retention_days")]
    pub audit_retention_days: u32,
}

fn default_true() -> bool {
    true
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            password_min_length: default_password_min_length(),
            password_require_number: true,
            password_require_symbol: true,
            login_max_failures: default_login_max_failures(),
            login_lock_minutes: default_login_lock_minutes(),
            session_timeout_minutes: default_session_timeout_minutes(),
            allowed_admin_cidrs: Vec::new(),
            audit_retention_days: default_audit_retention_days(),
        }
    }
}

/// Pro feature configuration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_web_port")]
    pub web_port: u16,
    #[serde(default = "default_tls_cert")]
    pub tls_cert: String,
    #[serde(default = "default_tls_key")]
    pub tls_key: String,
    /// 敏感字段：日志输出时必须脱敏。
    #[serde(default = "default_jwt_secret")]
    pub jwt_secret: String,
    #[serde(default = "default_jwt_expiry_hours")]
    pub jwt_expiry_hours: i64,
    #[serde(default = "default_refresh_expiry_days")]
    pub refresh_expiry_days: i64,
    #[serde(default)]
    pub oidc: OidcConfig,
    #[serde(default)]
    pub smtp: SmtpConfig,
    #[serde(default)]
    pub security: SecurityConfig,
}

fn default_web_port() -> u16 {
    8443
}
fn default_tls_cert() -> String {
    "/etc/rustdesk/cert.pem".to_string()
}
fn default_tls_key() -> String {
    "/etc/rustdesk/key.pem".to_string()
}

impl Default for ProConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            web_port: default_web_port(),
            tls_cert: default_tls_cert(),
            tls_key: default_tls_key(),
            jwt_secret: default_jwt_secret(),
            jwt_expiry_hours: default_jwt_expiry_hours(),
            refresh_expiry_days: default_refresh_expiry_days(),
            oidc: OidcConfig::default(),
            smtp: SmtpConfig::default(),
            security: SecurityConfig::default(),
        }
    }
}

/// Relay server configuration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RelayConfig {
    #[serde(default)]
    pub servers: Vec<String>,
    #[serde(default)]
    pub rmem: usize,
    #[serde(default = "default_max_single_bandwidth")]
    pub max_single_bandwidth: u64,
    #[serde(default = "default_max_total_bandwidth")]
    pub max_total_bandwidth: u64,
    #[serde(default = "default_limit_speed")]
    pub limit_speed: u64,
    #[serde(default = "default_downgrade_threshold")]
    pub downgrade_threshold: f64,
    #[serde(default = "default_downgrade_start_check")]
    pub downgrade_start_check: u64,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            rmem: 0,
            max_single_bandwidth: default_max_single_bandwidth(),
            max_total_bandwidth: default_max_total_bandwidth(),
            limit_speed: default_limit_speed(),
            downgrade_threshold: default_downgrade_threshold(),
            downgrade_start_check: default_downgrade_start_check(),
        }
    }
}

/// Rendezvous (ID) server configuration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RendezvousConfig {
    #[serde(default = "default_rendezvous_servers")]
    pub servers: Vec<String>,
    #[serde(default)]
    pub software_url: String,
    #[serde(default)]
    pub serial: i32,
    #[serde(default)]
    pub mask: String,
}

impl Default for RendezvousConfig {
    fn default() -> Self {
        Self {
            servers: default_rendezvous_servers(),
            software_url: String::new(),
            serial: 0,
            mask: String::new(),
        }
    }
}

/// Server listen addresses and core configuration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_id_server")]
    pub id_server: String,
    #[serde(default = "default_relay_server")]
    pub relay_server: String,
    #[serde(default = "default_api_server")]
    pub api_server: String,
    /// Sensitive field: will be masked in logs
    #[serde(default = "default_key")]
    pub key: String,
    #[serde(default = "default_key_file")]
    pub key_file: String,
    #[serde(default = "default_db_path")]
    pub db_path: String,
    /// 可选数据库 URL。为空时继续使用 db_path，以保持 OSS/SQLite 配置兼容。
    #[serde(default)]
    pub database_url: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            id_server: default_id_server(),
            relay_server: default_relay_server(),
            api_server: default_api_server(),
            key: default_key(),
            key_file: default_key_file(),
            db_path: default_db_path(),
            database_url: String::new(),
        }
    }
}

/// API 入口的资源保护配置。全部字段为冷配置，修改后必须重启进程。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiRateLimitConfig {
    #[serde(default = "default_api_max_in_flight")]
    pub max_in_flight: usize,
    #[serde(default = "default_telemetry_max_in_flight")]
    pub telemetry_max_in_flight: usize,
    #[serde(default = "default_auth_max_in_flight")]
    pub auth_max_in_flight: usize,
    #[serde(default = "default_argon2_max_in_flight")]
    pub argon2_max_in_flight: usize,
    #[serde(default = "default_api_request_timeout_ms")]
    pub request_timeout_ms: u64,
    #[serde(default = "default_telemetry_peer_capacity")]
    pub telemetry_peer_capacity: u64,
    #[serde(default = "default_telemetry_peer_refill_per_minute")]
    pub telemetry_peer_refill_per_minute: u64,
    #[serde(default = "default_auth_peer_capacity")]
    pub auth_peer_capacity: u64,
    #[serde(default = "default_auth_peer_refill_per_minute")]
    pub auth_peer_refill_per_minute: u64,
    #[serde(default = "default_device_capacity")]
    pub device_capacity: u64,
    #[serde(default = "default_device_refill_per_minute")]
    pub device_refill_per_minute: u64,
    #[serde(default = "default_address_book_actor_capacity")]
    pub address_book_actor_capacity: u64,
    #[serde(default = "default_address_book_actor_refill_per_minute")]
    pub address_book_actor_refill_per_minute: u64,
    #[serde(default = "default_peer_lru_capacity")]
    pub peer_lru_capacity: usize,
    #[serde(default = "default_device_lru_capacity")]
    pub device_lru_capacity: usize,
    #[serde(default = "default_actor_lru_capacity")]
    pub actor_lru_capacity: usize,
}

impl Default for ApiRateLimitConfig {
    fn default() -> Self {
        Self {
            max_in_flight: default_api_max_in_flight(),
            telemetry_max_in_flight: default_telemetry_max_in_flight(),
            auth_max_in_flight: default_auth_max_in_flight(),
            argon2_max_in_flight: default_argon2_max_in_flight(),
            request_timeout_ms: default_api_request_timeout_ms(),
            telemetry_peer_capacity: default_telemetry_peer_capacity(),
            telemetry_peer_refill_per_minute: default_telemetry_peer_refill_per_minute(),
            auth_peer_capacity: default_auth_peer_capacity(),
            auth_peer_refill_per_minute: default_auth_peer_refill_per_minute(),
            device_capacity: default_device_capacity(),
            device_refill_per_minute: default_device_refill_per_minute(),
            address_book_actor_capacity: default_address_book_actor_capacity(),
            address_book_actor_refill_per_minute: default_address_book_actor_refill_per_minute(),
            peer_lru_capacity: default_peer_lru_capacity(),
            device_lru_capacity: default_device_lru_capacity(),
            actor_lru_capacity: default_actor_lru_capacity(),
        }
    }
}

/// Top-level application configuration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub rendezvous: RendezvousConfig,
    #[serde(default)]
    pub relay: RelayConfig,
    #[serde(default)]
    pub pro: ProConfig,
    #[serde(default)]
    pub api_rate_limit: ApiRateLimitConfig,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            rendezvous: RendezvousConfig::default(),
            relay: RelayConfig::default(),
            pro: ProConfig::default(),
            api_rate_limit: ApiRateLimitConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigTarget {
    Hbbs,
    Hbbr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReloadStrategy {
    Hot,
    Cold,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReloadResult {
    pub changed_fields: Vec<String>,
    pub hot_applied: usize,
    pub cold: usize,
}

#[derive(Debug, Clone, Default, Serialize)]
struct AppConfigPatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    server: Option<ServerConfigPatch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rendezvous: Option<RendezvousConfigPatch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    relay: Option<RelayConfigPatch>,
}

#[derive(Debug, Clone, Default, Serialize)]
struct ServerConfigPatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    id_server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    relay_server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
struct RendezvousConfigPatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    servers: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    software_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    serial: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mask: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
struct RelayConfigPatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    servers: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rmem: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_single_bandwidth: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_total_bandwidth: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    limit_speed: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    downgrade_threshold: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    downgrade_start_check: Option<u64>,
}

#[derive(Debug, Clone)]
struct ReloadContext {
    target: ConfigTarget,
    config_path: Option<PathBuf>,
    explicit_config: bool,
    cli_patch: AppConfigPatch,
}

static GLOBAL_CONFIG: OnceCell<Arc<RwLock<AppConfig>>> = OnceCell::new();
static GLOBAL_RELOAD_CONTEXT: OnceCell<ReloadContext> = OnceCell::new();

// ==========================
// Sensitive field masking
// ==========================

/// Mask sensitive string values for log safety.
/// Returns "***" if non-empty, "<not set>" if empty.
pub(crate) fn mask_sensitive(s: &str) -> &str {
    if s.is_empty() {
        "<not set>"
    } else {
        "***"
    }
}

// ==========================
// Display trait (safe logging)
// ==========================

impl fmt::Display for SmtpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SmtpConfig {{ host: {}, port: {}, username: {}, password: {}, from: {} }}",
            self.host,
            self.port,
            self.username,
            mask_sensitive(&self.password),
            self.from
        )
    }
}

impl fmt::Display for OidcConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "OidcConfig {{ enabled: {}, issuer_url: {}, client_id: {}, client_secret: {}, redirect_uri: {}, post_login_url: {}, allowed_origins: {:?} }}",
            self.enabled,
            self.issuer_url,
            self.client_id,
            mask_sensitive(&self.client_secret),
            self.redirect_uri,
            self.post_login_url,
            self.allowed_origins
        )
    }
}

impl fmt::Display for ProConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ProConfig {{ enabled: {}, web_port: {}, tls_cert: {}, tls_key: {}, jwt_secret: {}, jwt_expiry_hours: {}, refresh_expiry_days: {}, oidc: {}, smtp: {}, security: {} }}",
            self.enabled,
            self.web_port,
            self.tls_cert,
            self.tls_key,
            mask_sensitive(&self.jwt_secret),
            self.jwt_expiry_hours,
            self.refresh_expiry_days,
            self.oidc,
            self.smtp,
            self.security
        )
    }
}

impl fmt::Display for SecurityConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SecurityConfig {{ password_min_length: {}, password_require_number: {}, password_require_symbol: {}, login_max_failures: {}, login_lock_minutes: {}, session_timeout_minutes: {}, allowed_admin_cidrs: {:?}, audit_retention_days: {} }}",
            self.password_min_length,
            self.password_require_number,
            self.password_require_symbol,
            self.login_max_failures,
            self.login_lock_minutes,
            self.session_timeout_minutes,
            self.allowed_admin_cidrs,
            self.audit_retention_days,
        )
    }
}

impl fmt::Display for RelayConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RelayConfig {{ servers: {:?}, rmem: {}, max_single_bandwidth: {}Mb/s, max_total_bandwidth: {}Mb/s, limit_speed: {}Mb/s, downgrade_threshold: {}, downgrade_start_check: {}ms }}",
            self.servers,
            self.rmem,
            self.max_single_bandwidth,
            self.max_total_bandwidth,
            self.limit_speed,
            self.downgrade_threshold,
            self.downgrade_start_check
        )
    }
}

impl fmt::Display for RendezvousConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RendezvousConfig {{ servers: {:?}, software_url: {}, serial: {}, mask: {} }}",
            self.servers, self.software_url, self.serial, self.mask
        )
    }
}

impl fmt::Display for ServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ServerConfig {{ id_server: {}, relay_server: {}, api_server: {}, key: {}, key_file: {}, db_path: {}, database_url: {} }}",
            self.id_server,
            self.relay_server,
            self.api_server,
            mask_sensitive(&self.key),
            self.key_file,
            self.db_path,
            mask_database_url(&self.database_url)
        )
    }
}

fn mask_database_url(value: &str) -> String {
    let Some((scheme, remainder)) = value.split_once("://") else {
        return value.to_string();
    };
    let masked = if let Some((credentials, location)) = remainder.rsplit_once('@') {
        let username = credentials
            .split_once(':')
            .map(|(name, _)| name)
            .unwrap_or(credentials);
        format!("{scheme}://{username}:***@{location}")
    } else {
        format!("{scheme}://{remainder}")
    };
    let Some((base, query)) = masked.split_once('?') else {
        return masked;
    };
    let query = query
        .split('&')
        .map(|part| match part.split_once('=') {
            Some((key, _)) if key.eq_ignore_ascii_case("password") => format!("{key}=***"),
            _ => part.to_string(),
        })
        .collect::<Vec<_>>()
        .join("&");
    format!("{base}?{query}")
}

impl fmt::Display for ApiRateLimitConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ApiRateLimitConfig {{ max_in_flight: {}, telemetry_max_in_flight: {}, auth_max_in_flight: {}, argon2_max_in_flight: {}, request_timeout_ms: {}, telemetry_peer: {}/{}, auth_peer: {}/{}, device: {}/{}, address_book_actor: {}/{}, peer_lru_capacity: {}, device_lru_capacity: {}, actor_lru_capacity: {} }}",
            self.max_in_flight,
            self.telemetry_max_in_flight,
            self.auth_max_in_flight,
            self.argon2_max_in_flight,
            self.request_timeout_ms,
            self.telemetry_peer_capacity,
            self.telemetry_peer_refill_per_minute,
            self.auth_peer_capacity,
            self.auth_peer_refill_per_minute,
            self.device_capacity,
            self.device_refill_per_minute,
            self.address_book_actor_capacity,
            self.address_book_actor_refill_per_minute,
            self.peer_lru_capacity,
            self.device_lru_capacity,
            self.actor_lru_capacity,
        )
    }
}

impl fmt::Display for AppConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}", self.server)?;
        writeln!(f, "{}", self.rendezvous)?;
        writeln!(f, "{}", self.relay)?;
        writeln!(f, "{}", self.pro)?;
        write!(f, "{}", self.api_rate_limit)
    }
}

// ==========================
// Port extraction helpers
// ==========================

impl AppConfig {
    pub fn load_with_cli_args(
        matches: &clap::ArgMatches<'_>,
        target: ConfigTarget,
    ) -> Result<Self, String> {
        let context = ReloadContext::from_matches(matches, target)?;
        let cfg = load_with_context(&context)?;
        set_global_config(cfg.clone(), context);
        Ok(cfg)
    }

    pub fn load_from_path(path: Option<&Path>, target: ConfigTarget) -> Result<Self, String> {
        let context = ReloadContext {
            target,
            config_path: path.map(Path::to_path_buf),
            explicit_config: path.is_some(),
            cli_patch: AppConfigPatch::default(),
        };
        load_with_context(&context)
    }

    pub fn sync_to_legacy_env(&self) {
        std::env::set_var("RENDEZVOUS-SERVERS", self.rendezvous.servers.join(","));
        std::env::set_var("SOFTWARE-URL", &self.rendezvous.software_url);
        std::env::set_var("RELAY-SERVERS", self.relay.servers.join(","));
        std::env::set_var("RMEM", self.relay.rmem.to_string());
        std::env::set_var("MASK", &self.rendezvous.mask);
        std::env::set_var("SERIAL", self.rendezvous.serial.to_string());
        std::env::set_var("KEY", &self.server.key);

        std::env::set_var(
            "TOTAL_BANDWIDTH",
            self.relay.max_total_bandwidth.to_string(),
        );
        std::env::set_var(
            "SINGLE_BANDWIDTH",
            self.relay.max_single_bandwidth.to_string(),
        );
        std::env::set_var("LIMIT_SPEED", self.relay.limit_speed.to_string());
        std::env::set_var(
            "DOWNGRADE_THRESHOLD",
            self.relay.downgrade_threshold.to_string(),
        );
        std::env::set_var(
            "DOWNGRADE_START_CHECK",
            self.relay.downgrade_start_check.to_string(),
        );
        std::env::set_var("PORT_FOR_API", self.id_server_port().to_string());
    }

    pub fn reload_from(
        &self,
        path: Option<&Path>,
        target: ConfigTarget,
    ) -> Result<(Self, ReloadResult), String> {
        let context = ReloadContext {
            target,
            config_path: path.map(Path::to_path_buf),
            explicit_config: path.is_some(),
            cli_patch: AppConfigPatch::default(),
        };
        let new_config = load_with_context(&context)?;
        let result = self.diff_reload(&new_config);
        Ok((new_config, result))
    }

    fn diff_reload(&self, new_config: &Self) -> ReloadResult {
        let changed_fields = diff_fields(self, new_config);
        ReloadResult {
            hot_applied: 0,
            cold: changed_fields.len(),
            changed_fields,
        }
    }

    /// Extract port number from server.id_server ("addr:port" format).
    pub fn id_server_port(&self) -> i32 {
        self.server
            .id_server
            .rsplit_once(':')
            .and_then(|(_, p)| p.parse().ok())
            .unwrap_or(RENDEZVOUS_PORT)
    }

    /// Extract port number from server.relay_server ("addr:port" format).
    pub fn relay_server_port(&self) -> i32 {
        self.server
            .relay_server
            .rsplit_once(':')
            .and_then(|(_, p)| p.parse().ok())
            .unwrap_or(RELAY_PORT)
    }

    /// Extract listen address from server.api_server.
    pub fn api_server_addr(&self) -> Result<SocketAddr, String> {
        self.server
            .api_server
            .parse::<SocketAddr>()
            .map_err(|e| format!("invalid api_server '{}': {}", self.server.api_server, e))
    }

    /// 返回 API、设备状态查询和迁移共同使用的数据库定位符。
    pub fn database_url(&self) -> &str {
        if self.server.database_url.trim().is_empty() {
            &self.server.db_path
        } else {
            &self.server.database_url
        }
    }

    /// Update the port portion of server.id_server.
    pub fn set_id_server_port(&mut self, port: i32) {
        if let Some(addr) = self.server.id_server.rsplit_once(':') {
            self.server.id_server = format!("{}:{}", addr.0, port);
        }
    }

    /// Update the port portion of server.relay_server.
    pub fn set_relay_server_port(&mut self, port: i32) {
        if let Some(addr) = self.server.relay_server.rsplit_once(':') {
            self.server.relay_server = format!("{}:{}", addr.0, port);
        }
    }
}

impl ReloadContext {
    fn from_matches(matches: &clap::ArgMatches<'_>, target: ConfigTarget) -> Result<Self, String> {
        Ok(Self {
            target,
            config_path: matches.value_of("config").map(PathBuf::from),
            explicit_config: matches.value_of("config").is_some(),
            cli_patch: cli_patch_from_matches(matches, target)?,
        })
    }
}

pub fn global_config() -> Option<Arc<RwLock<AppConfig>>> {
    GLOBAL_CONFIG.get().cloned()
}

pub fn reload_global_config() -> Result<ReloadResult, String> {
    let state = GLOBAL_CONFIG
        .get()
        .ok_or_else(|| "全局配置尚未初始化，无法重载".to_string())?;
    let context = GLOBAL_RELOAD_CONTEXT
        .get()
        .ok_or_else(|| "配置重载上下文尚未初始化，无法重载".to_string())?;
    let old_config = state
        .read()
        .map_err(|_| "读取全局配置锁失败".to_string())?
        .clone();
    let new_config = load_with_context(context)?;
    let result = old_config.diff_reload(&new_config);
    if result.cold > 0 {
        return Ok(result);
    }
    {
        let mut guard = state
            .write()
            .map_err(|_| "写入全局配置锁失败".to_string())?;
        *guard = new_config.clone();
    }
    new_config.sync_to_legacy_env();
    Ok(result)
}

fn set_global_config(config: AppConfig, context: ReloadContext) -> Arc<RwLock<AppConfig>> {
    let state = Arc::new(RwLock::new(config));
    let _ = GLOBAL_CONFIG.set(state.clone());
    let _ = GLOBAL_RELOAD_CONTEXT.set(context);
    state
}

fn load_with_context(context: &ReloadContext) -> Result<AppConfig, String> {
    let mut figment = Figment::from(Serialized::defaults(AppConfig::default()))
        .merge(Serialized::defaults(legacy_env_patch(context.target)?))
        .merge(Env::prefixed("RUSTDESK_").split("__"))
        .merge(Serialized::defaults(rustdesk_env_vec_patch()?));

    let config_path = resolve_config_path(context)?;
    if let Some(path) = &config_path {
        figment = figment.merge(Toml::file(path));
    }

    let mut cfg: AppConfig = figment
        .merge(Serialized::defaults(context.cli_patch.clone()))
        .extract()
        .map_err(|err| format!("{:#}", err))?;

    apply_target_compatibility(&mut cfg, context, config_path.as_deref())?;
    validate_config(&cfg)?;
    Ok(cfg)
}

fn resolve_config_path(context: &ReloadContext) -> Result<Option<PathBuf>, String> {
    if let Some(path) = &context.config_path {
        if !path.exists() {
            return Err(format!("config file not found: {}", path.display()));
        }
        reject_ini_config(path)?;
        return Ok(Some(path.clone()));
    }

    let path = PathBuf::from("config.toml");
    if path.exists() {
        reject_ini_config(&path)?;
        Ok(Some(path))
    } else {
        if !context.explicit_config {
            hbb_common::log::info!("no config.toml found, using defaults");
        }
        Ok(None)
    }
}

fn reject_ini_config(path: &Path) -> Result<(), String> {
    let is_ini_extension = path
        .extension()
        .and_then(|x| x.to_str())
        .map(|x| x.eq_ignore_ascii_case("ini"))
        .unwrap_or(false);
    if is_ini_extension {
        return Err(format!(
            "INI format is no longer supported, use TOML format: {}",
            path.display()
        ));
    }

    let content = std::fs::read_to_string(path)
        .map_err(|err| format!("failed to read config file {}: {}", path.display(), err))?;
    let has_section = content
        .lines()
        .map(str::trim)
        .any(|line| line.starts_with('[') && line.ends_with(']'));
    let has_legacy_key = content.lines().map(str::trim).any(|line| {
        let key = line.split('=').next().unwrap_or_default().trim();
        matches!(
            key,
            "port"
                | "key"
                | "serial"
                | "rendezvous-servers"
                | "software-url"
                | "relay-servers"
                | "rmem"
                | "mask"
        )
    });
    if !has_section && has_legacy_key {
        return Err(format!(
            "INI format is no longer supported, use TOML format: {}",
            path.display()
        ));
    }
    Ok(())
}

fn legacy_env_patch(target: ConfigTarget) -> Result<AppConfigPatch, String> {
    let mut patch = AppConfigPatch::default();

    if let Some(port) = env_any(&["PORT"]) {
        warn_deprecated_env(
            "PORT",
            match target {
                ConfigTarget::Hbbs => "RUSTDESK_SERVER__ID_SERVER",
                ConfigTarget::Hbbr => "RUSTDESK_SERVER__RELAY_SERVER",
            },
        );
        let port = parse_port("PORT", &port)?;
        match target {
            ConfigTarget::Hbbs => {
                patch.server_mut().id_server = Some(addr_with_port(default_id_server(), port))
            }
            ConfigTarget::Hbbr => {
                if port >= u16::MAX as i32 {
                    return Err(format!("invalid port for PORT: {}", port));
                }
                patch.server_mut().relay_server =
                    Some(addr_with_port(default_relay_server(), port + 1));
            }
        }
    }

    if let Some(key) = env_any(&["KEY"]) {
        warn_deprecated_env("KEY", "RUSTDESK_SERVER__KEY");
        patch.server_mut().key = Some(key);
    }
    if let Some(value) = env_any(&["RENDEZVOUS-SERVERS", "RENDEZVOUS_SERVERS"]) {
        warn_deprecated_env("RENDEZVOUS-SERVERS", "RUSTDESK_RENDEZVOUS__SERVERS");
        patch.rendezvous_mut().servers = Some(split_list(&value));
    }
    if let Some(value) = env_any(&["SOFTWARE-URL", "SOFTWARE_URL"]) {
        warn_deprecated_env("SOFTWARE-URL", "RUSTDESK_RENDEZVOUS__SOFTWARE_URL");
        patch.rendezvous_mut().software_url = Some(value);
    }
    if let Some(value) = env_any(&["SERIAL"]) {
        warn_deprecated_env("SERIAL", "RUSTDESK_RENDEZVOUS__SERIAL");
        patch.rendezvous_mut().serial = Some(parse_i32("SERIAL", &value)?);
    }
    if let Some(value) = env_any(&["MASK"]) {
        warn_deprecated_env("MASK", "RUSTDESK_RENDEZVOUS__MASK");
        patch.rendezvous_mut().mask = Some(value);
    }
    if let Some(value) = env_any(&["RELAY-SERVERS", "RELAY_SERVERS"]) {
        warn_deprecated_env("RELAY-SERVERS", "RUSTDESK_RELAY__SERVERS");
        patch.relay_mut().servers = Some(split_list(&value));
    }
    if let Some(value) = env_any(&["RMEM"]) {
        warn_deprecated_env("RMEM", "RUSTDESK_RELAY__RMEM");
        patch.relay_mut().rmem = Some(parse_usize("RMEM", &value)?);
    }

    if let Some(value) = env_any(&["TOTAL_BANDWIDTH"]) {
        warn_deprecated_env("TOTAL_BANDWIDTH", "RUSTDESK_RELAY__MAX_TOTAL_BANDWIDTH");
        patch.relay_mut().max_total_bandwidth = Some(parse_u64("TOTAL_BANDWIDTH", &value)?);
    }
    if let Some(value) = env_any(&["SINGLE_BANDWIDTH"]) {
        warn_deprecated_env("SINGLE_BANDWIDTH", "RUSTDESK_RELAY__MAX_SINGLE_BANDWIDTH");
        patch.relay_mut().max_single_bandwidth = Some(parse_u64("SINGLE_BANDWIDTH", &value)?);
    }
    if let Some(value) = env_any(&["LIMIT_SPEED"]) {
        warn_deprecated_env("LIMIT_SPEED", "RUSTDESK_RELAY__LIMIT_SPEED");
        patch.relay_mut().limit_speed = Some(parse_u64("LIMIT_SPEED", &value)?);
    }
    if let Some(value) = env_any(&["DOWNGRADE_THRESHOLD"]) {
        warn_deprecated_env("DOWNGRADE_THRESHOLD", "RUSTDESK_RELAY__DOWNGRADE_THRESHOLD");
        patch.relay_mut().downgrade_threshold = Some(parse_f64("DOWNGRADE_THRESHOLD", &value)?);
    }
    if let Some(value) = env_any(&["DOWNGRADE_START_CHECK"]) {
        warn_deprecated_env(
            "DOWNGRADE_START_CHECK",
            "RUSTDESK_RELAY__DOWNGRADE_START_CHECK",
        );
        patch.relay_mut().downgrade_start_check = Some(parse_u64("DOWNGRADE_START_CHECK", &value)?);
    }

    Ok(patch)
}

fn rustdesk_env_vec_patch() -> Result<AppConfigPatch, String> {
    let mut patch = AppConfigPatch::default();
    if let Ok(value) = std::env::var("RUSTDESK_RENDEZVOUS__SERVERS") {
        if !value.trim_start().starts_with('[') {
            patch.rendezvous_mut().servers = Some(split_list(&value));
        }
    }
    if let Ok(value) = std::env::var("RUSTDESK_RELAY__SERVERS") {
        if !value.trim_start().starts_with('[') {
            patch.relay_mut().servers = Some(split_list(&value));
        }
    }
    Ok(patch)
}

fn cli_patch_from_matches(
    matches: &clap::ArgMatches<'_>,
    target: ConfigTarget,
) -> Result<AppConfigPatch, String> {
    let mut patch = AppConfigPatch::default();

    if matches.occurrences_of("port") > 0 {
        let value = matches
            .value_of("port")
            .ok_or_else(|| "--port requires a value".to_string())?;
        let port = parse_port("--port", value)?;
        match target {
            ConfigTarget::Hbbs => {
                patch.server_mut().id_server = Some(addr_with_port(default_id_server(), port))
            }
            ConfigTarget::Hbbr => {
                patch.server_mut().relay_server = Some(addr_with_port(default_relay_server(), port))
            }
        }
    }
    if matches.occurrences_of("key") > 0 {
        if let Some(value) = matches.value_of("key") {
            patch.server_mut().key = Some(value.to_string());
        }
    }
    if matches.occurrences_of("serial") > 0 {
        let value = matches
            .value_of("serial")
            .ok_or_else(|| "--serial requires a value".to_string())?;
        patch.rendezvous_mut().serial = Some(parse_i32("--serial", value)?);
    }
    if matches.occurrences_of("rendezvous-servers") > 0 {
        if let Some(value) = matches.value_of("rendezvous-servers") {
            patch.rendezvous_mut().servers = Some(split_list(value));
        }
    }
    if matches.occurrences_of("software-url") > 0 {
        if let Some(value) = matches.value_of("software-url") {
            patch.rendezvous_mut().software_url = Some(value.to_string());
        }
    }
    if matches.occurrences_of("relay-servers") > 0 {
        if let Some(value) = matches.value_of("relay-servers") {
            patch.relay_mut().servers = Some(split_list(value));
        }
    }
    if matches.occurrences_of("rmem") > 0 {
        let value = matches
            .value_of("rmem")
            .ok_or_else(|| "--rmem requires a value".to_string())?;
        patch.relay_mut().rmem = Some(parse_usize("--rmem", value)?);
    }
    if matches.occurrences_of("mask") > 0 {
        if let Some(value) = matches.value_of("mask") {
            patch.rendezvous_mut().mask = Some(value.to_string());
        }
    }

    Ok(patch)
}

fn apply_target_compatibility(
    cfg: &mut AppConfig,
    context: &ReloadContext,
    config_path: Option<&Path>,
) -> Result<(), String> {
    if context.target == ConfigTarget::Hbbr {
        if !has_explicit_server_key(context, config_path) {
            cfg.server.key.clear();
        }
        apply_hbbr_id_server_fallback(cfg)?;
    }
    Ok(())
}

fn apply_hbbr_id_server_fallback(cfg: &mut AppConfig) -> Result<(), String> {
    if cfg.server.relay_server != default_relay_server()
        || cfg.server.id_server == default_id_server()
    {
        return Ok(());
    }
    let relay_port = checked_listen_port("server.id_server", &cfg.server.id_server)? + 1;
    cfg.set_relay_server_port(relay_port);
    Ok(())
}

fn has_explicit_server_key(context: &ReloadContext, config_path: Option<&Path>) -> bool {
    context
        .cli_patch
        .server
        .as_ref()
        .and_then(|server| server.key.as_ref())
        .is_some()
        || env_any(&["KEY", "RUSTDESK_SERVER__KEY"]).is_some()
        || config_path.map(config_has_server_key).unwrap_or(false)
}

impl AppConfigPatch {
    fn server_mut(&mut self) -> &mut ServerConfigPatch {
        self.server.get_or_insert_with(ServerConfigPatch::default)
    }

    fn rendezvous_mut(&mut self) -> &mut RendezvousConfigPatch {
        self.rendezvous
            .get_or_insert_with(RendezvousConfigPatch::default)
    }

    fn relay_mut(&mut self) -> &mut RelayConfigPatch {
        self.relay.get_or_insert_with(RelayConfigPatch::default)
    }
}

fn env_any(names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| std::env::var(name).ok())
}

fn warn_deprecated_env(old: &str, new: &str) {
    hbb_common::log::warn!("env var {} is deprecated, use {} instead", old, new);
}

fn parse_i32(name: &str, value: &str) -> Result<i32, String> {
    value
        .parse()
        .map_err(|_| format!("invalid value for env var {}: {}", name, value))
}

fn parse_port(name: &str, value: &str) -> Result<i32, String> {
    let port: u16 = value
        .parse()
        .map_err(|_| format!("invalid port for {}: {}", name, value))?;
    if port == 0 {
        return Err(format!("invalid port for {}: {}", name, value));
    }
    Ok(port as i32)
}

fn parse_usize(name: &str, value: &str) -> Result<usize, String> {
    value
        .parse()
        .map_err(|_| format!("invalid value for env var {}: {}", name, value))
}

fn parse_u64(name: &str, value: &str) -> Result<u64, String> {
    value
        .parse()
        .map_err(|_| format!("invalid value for env var {}: {}", name, value))
}

fn parse_f64(name: &str, value: &str) -> Result<f64, String> {
    value
        .parse()
        .map_err(|_| format!("invalid value for env var {}: {}", name, value))
}

fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn addr_with_port(default_addr: String, port: i32) -> String {
    default_addr
        .rsplit_once(':')
        .map(|(addr, _)| format!("{}:{}", addr, port))
        .unwrap_or_else(|| format!("0.0.0.0:{}", port))
}

fn validate_config(cfg: &AppConfig) -> Result<(), String> {
    checked_listen_port("server.id_server", &cfg.server.id_server)?;
    checked_listen_port("server.relay_server", &cfg.server.relay_server)?;
    checked_listen_port("server.api_server", &cfg.server.api_server)?;
    if !cfg.server.database_url.trim().is_empty()
        && !cfg.server.database_url.starts_with("postgres://")
        && !cfg.server.database_url.starts_with("postgresql://")
        && !cfg.server.database_url.starts_with("sqlite:")
    {
        return Err(
            "server.database_url must use postgres://, postgresql:// or sqlite: scheme".to_string(),
        );
    }
    if cfg.pro.jwt_secret.trim().len() < 32 {
        return Err("pro.jwt_secret must be at least 32 characters".to_string());
    }
    if cfg.pro.jwt_expiry_hours <= 0 {
        return Err("pro.jwt_expiry_hours must be positive".to_string());
    }
    if cfg.pro.refresh_expiry_days <= 0 {
        return Err("pro.refresh_expiry_days must be positive".to_string());
    }
    validate_allowed_origins(&cfg.pro.oidc.allowed_origins)?;
    validate_security_config(&cfg.pro.security)?;
    validate_api_rate_limit(&cfg.api_rate_limit)?;
    Ok(())
}

pub fn validate_security_config(cfg: &SecurityConfig) -> Result<(), String> {
    if !(1..=1024).contains(&cfg.password_min_length) {
        return Err("pro.security.password_min_length must be within 1..=1024".to_string());
    }
    if !(1..=100).contains(&cfg.login_max_failures) {
        return Err("pro.security.login_max_failures must be within 1..=100".to_string());
    }
    if !(1..=10_080).contains(&cfg.login_lock_minutes) {
        return Err("pro.security.login_lock_minutes must be within 1..=10080".to_string());
    }
    if !(1..=525_600).contains(&cfg.session_timeout_minutes) {
        return Err("pro.security.session_timeout_minutes must be within 1..=525600".to_string());
    }
    if !(1..=3650).contains(&cfg.audit_retention_days) {
        return Err("pro.security.audit_retention_days must be within 1..=3650".to_string());
    }
    if cfg.allowed_admin_cidrs.len() > 256 {
        return Err(
            "pro.security.allowed_admin_cidrs must contain at most 256 entries".to_string(),
        );
    }
    for cidr in &cfg.allowed_admin_cidrs {
        let value = cidr.trim();
        if value.is_empty() || value != cidr {
            return Err("pro.security.allowed_admin_cidrs contains an invalid CIDR".to_string());
        }
        value
            .parse::<ipnetwork::IpNetwork>()
            .map_err(|_| "pro.security.allowed_admin_cidrs contains an invalid CIDR".to_string())?;
    }
    Ok(())
}

fn validate_api_rate_limit(cfg: &ApiRateLimitConfig) -> Result<(), String> {
    const MAX_CONCURRENCY: usize = 65_535;
    const MAX_BUCKET_VALUE: u64 = 1_000_000;
    const MAX_LRU_CAPACITY: usize = 1_000_000;

    for (name, value) in [
        ("max_in_flight", cfg.max_in_flight),
        ("telemetry_max_in_flight", cfg.telemetry_max_in_flight),
        ("auth_max_in_flight", cfg.auth_max_in_flight),
        ("argon2_max_in_flight", cfg.argon2_max_in_flight),
    ] {
        if value == 0 || value > MAX_CONCURRENCY {
            return Err(format!(
                "api_rate_limit.{name} must be within 1..={MAX_CONCURRENCY}"
            ));
        }
    }
    if cfg.telemetry_max_in_flight + cfg.auth_max_in_flight >= cfg.max_in_flight {
        return Err(
            "api_rate_limit telemetry/auth concurrency must leave capacity for other APIs"
                .to_string(),
        );
    }
    if !(100..=60_000).contains(&cfg.request_timeout_ms) {
        return Err("api_rate_limit.request_timeout_ms must be within 100..=60000".to_string());
    }
    for (name, value) in [
        ("telemetry_peer_capacity", cfg.telemetry_peer_capacity),
        (
            "telemetry_peer_refill_per_minute",
            cfg.telemetry_peer_refill_per_minute,
        ),
        ("auth_peer_capacity", cfg.auth_peer_capacity),
        (
            "auth_peer_refill_per_minute",
            cfg.auth_peer_refill_per_minute,
        ),
        ("device_capacity", cfg.device_capacity),
        ("device_refill_per_minute", cfg.device_refill_per_minute),
        (
            "address_book_actor_capacity",
            cfg.address_book_actor_capacity,
        ),
        (
            "address_book_actor_refill_per_minute",
            cfg.address_book_actor_refill_per_minute,
        ),
    ] {
        if value == 0 || value > MAX_BUCKET_VALUE {
            return Err(format!(
                "api_rate_limit.{name} must be within 1..={MAX_BUCKET_VALUE}"
            ));
        }
    }
    for (name, value) in [
        ("peer_lru_capacity", cfg.peer_lru_capacity),
        ("device_lru_capacity", cfg.device_lru_capacity),
        ("actor_lru_capacity", cfg.actor_lru_capacity),
    ] {
        if value == 0 || value > MAX_LRU_CAPACITY {
            return Err(format!(
                "api_rate_limit.{name} must be within 1..={MAX_LRU_CAPACITY}"
            ));
        }
    }
    Ok(())
}

fn validate_allowed_origins(origins: &[String]) -> Result<(), String> {
    for origin in origins {
        let value = origin.trim();
        http::HeaderValue::from_str(value).map_err(|err| {
            format!(
                "pro.oidc.allowed_origins contains invalid header value '{}': {}",
                origin, err
            )
        })?;
        let uri: http::Uri = value.parse().map_err(|err| {
            format!(
                "pro.oidc.allowed_origins contains invalid origin '{}': {}",
                origin, err
            )
        })?;
        if uri.scheme_str().is_none() || uri.authority().is_none() || uri.path() != "/" {
            return Err(format!(
                "pro.oidc.allowed_origins must be origins like https://example.com, got '{}'",
                origin
            ));
        }
    }
    Ok(())
}

fn checked_listen_port(field: &str, value: &str) -> Result<i32, String> {
    let (host, port) = split_listen_addr(field, value)?;
    validate_unspecified_host(field, host)?;
    parse_port(field, port)
}

fn split_listen_addr<'a>(field: &str, value: &'a str) -> Result<(&'a str, &'a str), String> {
    if let Some(rest) = value.strip_prefix('[') {
        let (host, suffix) = rest
            .split_once(']')
            .ok_or_else(|| format!("invalid listen address for {}: {}", field, value))?;
        let port = suffix
            .strip_prefix(':')
            .ok_or_else(|| format!("invalid listen address for {}: {}", field, value))?;
        return Ok((host, port));
    }

    value
        .rsplit_once(':')
        .ok_or_else(|| format!("invalid listen address for {}: {}", field, value))
}

fn validate_unspecified_host(field: &str, host: &str) -> Result<(), String> {
    let host = host.trim();
    if host.is_empty() || host == "*" {
        return Ok(());
    }
    let ip = host
        .parse::<IpAddr>()
        .map_err(|_| format!("invalid listen host for {}: {}", field, host))?;
    if ip.is_unspecified() {
        Ok(())
    } else {
        Err(format!(
            "{} host {} is not supported yet; hbbs/hbbr currently bind all interfaces, use 0.0.0.0 or [::]",
            field, host
        ))
    }
}

fn config_has_server_key(path: &Path) -> bool {
    let Ok(content) = std::fs::read_to_string(path) else {
        return false;
    };
    let mut in_server = false;
    for line in content.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.starts_with('[') && line.ends_with(']') {
            in_server = line.trim_matches(&['[', ']'][..]).trim() == "server";
            continue;
        }
        if in_server {
            let key = line
                .split('=')
                .next()
                .unwrap_or_default()
                .trim()
                .trim_matches('"')
                .trim_matches('\'');
            if key == "key" {
                return true;
            }
        }
    }
    false
}

fn diff_fields(old: &AppConfig, new: &AppConfig) -> Vec<String> {
    let mut fields = Vec::new();
    push_diff(
        &mut fields,
        "server.id_server",
        &old.server.id_server,
        &new.server.id_server,
    );
    push_diff(
        &mut fields,
        "server.relay_server",
        &old.server.relay_server,
        &new.server.relay_server,
    );
    push_diff(
        &mut fields,
        "server.api_server",
        &old.server.api_server,
        &new.server.api_server,
    );
    push_diff(&mut fields, "server.key", &old.server.key, &new.server.key);
    push_diff(
        &mut fields,
        "server.key_file",
        &old.server.key_file,
        &new.server.key_file,
    );
    push_diff(
        &mut fields,
        "server.db_path",
        &old.server.db_path,
        &new.server.db_path,
    );
    push_diff(
        &mut fields,
        "server.database_url",
        &old.server.database_url,
        &new.server.database_url,
    );
    push_diff(
        &mut fields,
        "rendezvous.servers",
        &old.rendezvous.servers,
        &new.rendezvous.servers,
    );
    push_diff(
        &mut fields,
        "rendezvous.software_url",
        &old.rendezvous.software_url,
        &new.rendezvous.software_url,
    );
    push_diff(
        &mut fields,
        "rendezvous.serial",
        &old.rendezvous.serial,
        &new.rendezvous.serial,
    );
    push_diff(
        &mut fields,
        "rendezvous.mask",
        &old.rendezvous.mask,
        &new.rendezvous.mask,
    );
    push_diff(
        &mut fields,
        "relay.servers",
        &old.relay.servers,
        &new.relay.servers,
    );
    push_diff(&mut fields, "relay.rmem", &old.relay.rmem, &new.relay.rmem);
    push_diff(
        &mut fields,
        "relay.max_single_bandwidth",
        &old.relay.max_single_bandwidth,
        &new.relay.max_single_bandwidth,
    );
    push_diff(
        &mut fields,
        "relay.max_total_bandwidth",
        &old.relay.max_total_bandwidth,
        &new.relay.max_total_bandwidth,
    );
    push_diff(
        &mut fields,
        "relay.limit_speed",
        &old.relay.limit_speed,
        &new.relay.limit_speed,
    );
    push_diff(
        &mut fields,
        "relay.downgrade_threshold",
        &old.relay.downgrade_threshold,
        &new.relay.downgrade_threshold,
    );
    push_diff(
        &mut fields,
        "relay.downgrade_start_check",
        &old.relay.downgrade_start_check,
        &new.relay.downgrade_start_check,
    );
    push_diff(
        &mut fields,
        "pro.enabled",
        &old.pro.enabled,
        &new.pro.enabled,
    );
    push_diff(
        &mut fields,
        "pro.web_port",
        &old.pro.web_port,
        &new.pro.web_port,
    );
    push_diff(
        &mut fields,
        "pro.tls_cert",
        &old.pro.tls_cert,
        &new.pro.tls_cert,
    );
    push_diff(
        &mut fields,
        "pro.tls_key",
        &old.pro.tls_key,
        &new.pro.tls_key,
    );
    push_diff(
        &mut fields,
        "pro.jwt_secret",
        &old.pro.jwt_secret,
        &new.pro.jwt_secret,
    );
    push_diff(
        &mut fields,
        "pro.jwt_expiry_hours",
        &old.pro.jwt_expiry_hours,
        &new.pro.jwt_expiry_hours,
    );
    push_diff(
        &mut fields,
        "pro.refresh_expiry_days",
        &old.pro.refresh_expiry_days,
        &new.pro.refresh_expiry_days,
    );
    push_diff(&mut fields, "pro.oidc", &old.pro.oidc, &new.pro.oidc);
    push_diff(&mut fields, "pro.smtp", &old.pro.smtp, &new.pro.smtp);
    push_diff(
        &mut fields,
        "pro.security",
        &old.pro.security,
        &new.pro.security,
    );
    push_diff(
        &mut fields,
        "api_rate_limit",
        &old.api_rate_limit,
        &new.api_rate_limit,
    );
    fields
}

fn push_diff<T: PartialEq>(fields: &mut Vec<String>, name: &str, old: &T, new: &T) {
    if old != new {
        fields.push(name.to_string());
    }
}

// ==========================
// Tests
// ==========================

#[cfg(test)]
mod tests {
    use super::*;
    use clap::App;
    use std::{
        fs,
        sync::Mutex,
        time::{SystemTime, UNIX_EPOCH},
    };

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_default_values() {
        let cfg = AppConfig::default();
        assert_eq!(cfg.server.id_server, "0.0.0.0:21116");
        assert_eq!(cfg.server.relay_server, "0.0.0.0:21117");
        assert_eq!(cfg.server.api_server, "0.0.0.0:21114");
        assert_eq!(cfg.server.db_path, default_db_path());
        assert!(cfg.server.database_url.is_empty());
        assert_eq!(cfg.server.key, "-");
        assert_eq!(cfg.rendezvous.serial, 0);
        assert!(cfg.rendezvous.servers.is_empty());
        assert_eq!(cfg.relay.rmem, 0);
        assert_eq!(cfg.relay.max_single_bandwidth, 128);
        assert_eq!(cfg.relay.max_total_bandwidth, 1024);
        assert!(!cfg.pro.enabled);
        assert_eq!(cfg.pro.jwt_expiry_hours, 24);
        assert_eq!(cfg.pro.refresh_expiry_days, 7);
        assert!(!cfg.pro.jwt_secret.is_empty());
        assert_eq!(cfg.pro.security, SecurityConfig::default());
    }

    #[test]
    fn database_url_overrides_path_and_is_masked() {
        let mut cfg = AppConfig::default();
        cfg.server.database_url =
            "postgresql://rustdesk:top-secret@db.example.com/rustdesk".to_string();
        assert_eq!(cfg.database_url(), cfg.server.database_url);
        let shown = cfg.server.to_string();
        assert!(shown.contains("postgresql://rustdesk:***@db.example.com/rustdesk"));
        assert!(!shown.contains("top-secret"));

        cfg.server.database_url =
            "postgresql://db.example.com/rustdesk?sslmode=require&password=query-secret"
                .to_string();
        let shown = cfg.server.to_string();
        assert!(shown.contains("sslmode=require&password=***"));
        assert!(!shown.contains("query-secret"));
    }

    #[test]
    fn test_id_server_port() {
        let cfg = AppConfig::default();
        assert_eq!(cfg.id_server_port(), 21116);
    }

    #[test]
    fn test_relay_server_port() {
        let cfg = AppConfig::default();
        assert_eq!(cfg.relay_server_port(), 21117);
    }

    #[test]
    fn test_api_server_addr_parse() {
        let cfg = AppConfig::default();
        let addr = cfg.api_server_addr().unwrap();
        assert_eq!(addr.to_string(), "0.0.0.0:21114");
    }

    #[test]
    fn test_api_server_addr_invalid() {
        let mut cfg = AppConfig::default();
        cfg.server.api_server = "invalid-addr".to_string();
        let err = cfg.api_server_addr().unwrap_err();
        assert!(err.contains("invalid api_server"));
    }

    #[test]
    fn test_set_port() {
        let mut cfg = AppConfig::default();
        cfg.set_id_server_port(9999);
        assert_eq!(cfg.id_server_port(), 9999);
        assert_eq!(cfg.server.id_server, "0.0.0.0:9999");

        cfg.set_relay_server_port(8888);
        assert_eq!(cfg.relay_server_port(), 8888);
        assert_eq!(cfg.server.relay_server, "0.0.0.0:8888");
    }

    #[test]
    fn test_mask_sensitive() {
        assert_eq!(mask_sensitive(""), "<not set>");
        assert_eq!(mask_sensitive("secret"), "***");
        assert_eq!(mask_sensitive("any-value"), "***");
    }

    #[test]
    fn test_display_masks_key() {
        let mut cfg = AppConfig::default();
        cfg.server.key = "my-secret-key".to_string();
        let output = format!("{}", cfg);
        assert!(!output.contains("my-secret-key"));
        assert!(output.contains("***"));
    }

    #[test]
    fn test_display_masks_oidc_secret() {
        let mut cfg = AppConfig::default();
        cfg.pro.oidc.client_secret = "super-secret".to_string();
        let output = format!("{}", cfg.pro.oidc);
        assert!(!output.contains("super-secret"));
        assert!(output.contains("***"));
    }

    #[test]
    fn test_display_masks_smtp_password() {
        let mut cfg = AppConfig::default();
        cfg.pro.smtp.password = "smtp-pass".to_string();
        let output = format!("{}", cfg.pro.smtp);
        assert!(!output.contains("smtp-pass"));
        assert!(output.contains("***"));
    }

    #[test]
    fn test_display_masks_jwt_secret() {
        let mut cfg = AppConfig::default();
        cfg.pro.jwt_secret = "jwt-secret".to_string();
        let output = format!("{}", cfg.pro);
        assert!(!output.contains("jwt-secret"));
        assert!(output.contains("***"));
    }

    #[test]
    fn test_hbbr_port_logic() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_test_env();
        // Simulate: PORT=21116 -> relay port = 21117
        std::env::set_var("PORT", "21116");
        let mut cfg = AppConfig::default();
        let relay_port = if let Ok(v) = std::env::var("PORT") {
            let v: i32 = v.parse().unwrap_or_default();
            if v > 0 {
                v + 1
            } else {
                RELAY_PORT
            }
        } else {
            RELAY_PORT
        };
        cfg.set_relay_server_port(relay_port);
        assert_eq!(cfg.relay_server_port(), 21117);
        clear_test_env();
    }

    #[test]
    fn test_rendezvous_servers_default() {
        let cfg = AppConfig::default();
        assert!(cfg.rendezvous.servers.is_empty());
    }

    #[test]
    fn test_custom_address_with_port() {
        let mut cfg = AppConfig::default();
        cfg.server.id_server = "192.168.1.1:21120".to_string();
        assert_eq!(cfg.id_server_port(), 21120);
        cfg.set_id_server_port(30000);
        assert_eq!(cfg.server.id_server, "192.168.1.1:30000");
    }

    #[test]
    fn test_load_from_toml() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_test_env();
        let path = temp_config(
            r#"
[server]
id_server = "0.0.0.0:31116"
key = "secret"

[rendezvous]
servers = ["rs-a.com", "rs-b.com"]
serial = 7

[relay]
max_total_bandwidth = 512
"#,
        );
        let cfg = AppConfig::load_from_path(Some(&path), ConfigTarget::Hbbs).unwrap();
        assert_eq!(cfg.server.id_server, "0.0.0.0:31116");
        assert_eq!(cfg.server.key, "secret");
        assert_eq!(cfg.rendezvous.servers, vec!["rs-a.com", "rs-b.com"]);
        assert_eq!(cfg.rendezvous.serial, 7);
        assert_eq!(cfg.relay.max_total_bandwidth, 512);
        fs::remove_file(path).ok();
    }

    #[test]
    fn test_rustdesk_env_override_default() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_test_env();
        std::env::set_var("RUSTDESK_SERVER__ID_SERVER", "0.0.0.0:41116");
        let cfg = AppConfig::load_from_path(None, ConfigTarget::Hbbs).unwrap();
        assert_eq!(cfg.server.id_server, "0.0.0.0:41116");
        clear_test_env();
    }

    #[test]
    fn test_priority_cli_over_toml_over_rustdesk_env_over_legacy_env_over_default() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_test_env();
        std::env::set_var("PORT", "21118");
        std::env::set_var("RUSTDESK_SERVER__ID_SERVER", "0.0.0.0:31116");
        let path = temp_config(
            r#"
[server]
id_server = "0.0.0.0:41116"
"#,
        );
        let matches = hbbs_matches(&[
            "hbbs",
            "--config",
            path.to_str().unwrap(),
            "--port",
            "51116",
        ]);
        let cfg = AppConfig::load_with_cli_args(&matches, ConfigTarget::Hbbs).unwrap();
        assert_eq!(cfg.server.id_server, "0.0.0.0:51116");
        fs::remove_file(path).ok();
        clear_test_env();
    }

    #[test]
    fn test_config_toml_overrides_legacy_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_test_env();
        std::env::set_var("TOTAL_BANDWIDTH", "512");
        let path = temp_config(
            r#"
[relay]
max_total_bandwidth = 1024
"#,
        );
        let cfg = AppConfig::load_from_path(Some(&path), ConfigTarget::Hbbr).unwrap();
        assert_eq!(cfg.relay.max_total_bandwidth, 1024);
        cfg.sync_to_legacy_env();
        assert_eq!(std::env::var("TOTAL_BANDWIDTH").unwrap(), "1024");
        fs::remove_file(path).ok();
        clear_test_env();
    }

    #[test]
    fn test_missing_config_file_no_error() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_test_env();
        let cwd = std::env::current_dir().unwrap();
        let temp_dir = std::env::temp_dir().join(unique_name("rustdesk-config-empty"));
        fs::create_dir_all(&temp_dir).unwrap();
        std::env::set_current_dir(&temp_dir).unwrap();
        let cfg = AppConfig::load_from_path(None, ConfigTarget::Hbbs).unwrap();
        assert_eq!(cfg.server.id_server, default_id_server());
        std::env::set_current_dir(cwd).unwrap();
        fs::remove_dir_all(temp_dir).ok();
    }

    #[test]
    fn test_specified_config_not_found_error() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_test_env();
        let path = std::env::temp_dir().join(unique_name("missing-config.toml"));
        let err = AppConfig::load_from_path(Some(&path), ConfigTarget::Hbbs).unwrap_err();
        assert!(err.contains("config file not found"));
    }

    #[test]
    fn test_bad_toml_startup_error() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_test_env();
        let path = temp_config("server = { bad syntax");
        let err = AppConfig::load_from_path(Some(&path), ConfigTarget::Hbbs).unwrap_err();
        assert!(err.contains("TOML") || err.contains("syntax") || err.contains("invalid"));
        fs::remove_file(path).ok();
    }

    #[test]
    fn test_bad_toml_reload_keep_old() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_test_env();
        let old = AppConfig::default();
        let path = temp_config("server = { bad syntax");
        let err = old
            .reload_from(Some(&path), ConfigTarget::Hbbs)
            .unwrap_err();
        assert!(err.contains("TOML") || err.contains("syntax") || err.contains("invalid"));
        assert_eq!(old.server.id_server, default_id_server());
        fs::remove_file(path).ok();
    }

    #[test]
    fn test_empty_jwt_secret_errors() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_test_env();
        let path = temp_config(
            r#"
[pro]
jwt_secret = ""
"#,
        );
        let err = AppConfig::load_from_path(Some(&path), ConfigTarget::Hbbs).unwrap_err();
        assert!(err.contains("pro.jwt_secret"));
        fs::remove_file(path).ok();
    }

    #[test]
    fn test_short_jwt_secret_errors() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_test_env();
        let path = temp_config(
            r#"
[pro]
jwt_secret = "short"
"#,
        );
        let err = AppConfig::load_from_path(Some(&path), ConfigTarget::Hbbs).unwrap_err();
        assert!(err.contains("pro.jwt_secret"));
        fs::remove_file(path).ok();
    }

    #[test]
    fn test_sync_to_legacy_env_keys() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_test_env();
        let mut cfg = AppConfig::default();
        cfg.rendezvous.servers = vec!["rs-a.com".to_string(), "rs-b.com".to_string()];
        cfg.rendezvous.software_url = "https://example.com/app".to_string();
        cfg.relay.servers = vec!["rl-a.com".to_string()];
        cfg.relay.rmem = 4096;
        cfg.relay.max_total_bandwidth = 2048;
        cfg.relay.max_single_bandwidth = 256;
        cfg.sync_to_legacy_env();
        assert_eq!(
            std::env::var("RENDEZVOUS-SERVERS").unwrap(),
            "rs-a.com,rs-b.com"
        );
        assert_eq!(
            std::env::var("SOFTWARE-URL").unwrap(),
            "https://example.com/app"
        );
        assert_eq!(std::env::var("RELAY-SERVERS").unwrap(), "rl-a.com");
        assert_eq!(std::env::var("RMEM").unwrap(), "4096");
        assert_eq!(std::env::var("TOTAL_BANDWIDTH").unwrap(), "2048");
        assert_eq!(std::env::var("SINGLE_BANDWIDTH").unwrap(), "256");
        clear_test_env();
    }

    #[test]
    fn test_reload_cold_warning_result() {
        let old = AppConfig::default();
        let mut new_cfg = old.clone();
        new_cfg.relay.max_total_bandwidth = 2048;
        let result = old.diff_reload(&new_cfg);
        assert_eq!(result.hot_applied, 0);
        assert_eq!(result.cold, 1);
        assert_eq!(result.changed_fields, vec!["relay.max_total_bandwidth"]);
    }

    #[test]
    fn test_env_var_type_error_startup_failure() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_test_env();
        std::env::set_var("TOTAL_BANDWIDTH", "abc");
        let err = AppConfig::load_from_path(None, ConfigTarget::Hbbr).unwrap_err();
        assert!(err.contains("TOTAL_BANDWIDTH"));
        clear_test_env();
    }

    #[test]
    fn test_legacy_env_total_bandwidth() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_test_env();
        std::env::set_var("TOTAL_BANDWIDTH", "512");
        let cfg = AppConfig::load_from_path(None, ConfigTarget::Hbbr).unwrap();
        assert_eq!(cfg.relay.max_total_bandwidth, 512);
        clear_test_env();
    }

    #[test]
    fn test_vec_string_env_parsing() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_test_env();
        std::env::set_var("RUSTDESK_RENDEZVOUS__SERVERS", "rs-a.com, rs-b.com");
        let cfg = AppConfig::load_from_path(None, ConfigTarget::Hbbs).unwrap();
        assert_eq!(cfg.rendezvous.servers, vec!["rs-a.com", "rs-b.com"]);
        clear_test_env();
    }

    #[test]
    fn test_hbbr_legacy_port_plus_one() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_test_env();
        std::env::set_var("PORT", "41116");
        let cfg = AppConfig::load_from_path(None, ConfigTarget::Hbbr).unwrap();
        assert_eq!(cfg.relay_server_port(), 41117);
        clear_test_env();
    }

    #[test]
    fn test_legacy_env_port_zero_errors() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_test_env();
        std::env::set_var("PORT", "0");
        let err = AppConfig::load_from_path(None, ConfigTarget::Hbbs).unwrap_err();
        assert!(err.contains("invalid port"));
        clear_test_env();
    }

    #[test]
    fn test_hbbr_legacy_port_plus_one_overflow_errors() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_test_env();
        std::env::set_var("PORT", "65535");
        let err = AppConfig::load_from_path(None, ConfigTarget::Hbbr).unwrap_err();
        assert!(err.contains("invalid port"));
        clear_test_env();
    }

    #[test]
    fn test_hbbr_default_key_is_empty() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_test_env();
        let cfg = AppConfig::load_from_path(None, ConfigTarget::Hbbr).unwrap();
        assert!(cfg.server.key.is_empty());
        clear_test_env();
    }

    #[test]
    fn test_hbbr_explicit_key_is_kept() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_test_env();
        let matches = hbbr_matches(&["hbbr", "--key", "relay-secret"]);
        let cfg = AppConfig::load_with_cli_args(&matches, ConfigTarget::Hbbr).unwrap();
        assert_eq!(cfg.server.key, "relay-secret");
        clear_test_env();
    }

    #[test]
    fn test_cli_bad_port_errors() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_test_env();
        let matches = hbbs_matches(&["hbbs", "--port", "abc"]);
        let err = AppConfig::load_with_cli_args(&matches, ConfigTarget::Hbbs).unwrap_err();
        assert!(err.contains("invalid port"));
        clear_test_env();
    }

    #[test]
    fn test_config_bad_port_errors() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_test_env();
        let path = temp_config(
            r#"
[server]
id_server = "0.0.0.0:not-a-port"
"#,
        );
        let err = AppConfig::load_from_path(Some(&path), ConfigTarget::Hbbs).unwrap_err();
        assert!(err.contains("invalid port"));
        fs::remove_file(path).ok();
    }

    #[test]
    fn test_non_unspecified_listen_host_errors() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_test_env();
        let path = temp_config(
            r#"
[server]
id_server = "127.0.0.1:21116"
"#,
        );
        let err = AppConfig::load_from_path(Some(&path), ConfigTarget::Hbbs).unwrap_err();
        assert!(err.contains("bind all interfaces"));
        fs::remove_file(path).ok();
    }

    #[test]
    fn test_api_rate_limit_defaults_and_invalid_combinations() {
        let defaults = ApiRateLimitConfig::default();
        assert_eq!(defaults.max_in_flight, 1024);
        assert_eq!(defaults.telemetry_max_in_flight, 768);
        assert_eq!(defaults.auth_max_in_flight, 64);
        assert!(validate_api_rate_limit(&defaults).is_ok());

        let mut invalid = defaults.clone();
        invalid.auth_max_in_flight = invalid.max_in_flight;
        assert!(validate_api_rate_limit(&invalid).is_err());
        invalid = defaults.clone();
        invalid.auth_max_in_flight = invalid.max_in_flight - invalid.telemetry_max_in_flight;
        assert!(validate_api_rate_limit(&invalid).is_err());
        invalid = defaults.clone();
        invalid.request_timeout_ms = 99;
        assert!(validate_api_rate_limit(&invalid).is_err());
        invalid = defaults;
        invalid.peer_lru_capacity = 0;
        assert!(validate_api_rate_limit(&invalid).is_err());
    }

    #[test]
    fn test_api_rate_limit_changes_are_cold_reload_fields() {
        let old = AppConfig::default();
        let mut new = old.clone();
        new.api_rate_limit.auth_peer_capacity += 1;
        let result = old.diff_reload(&new);
        assert_eq!(result.hot_applied, 0);
        assert_eq!(result.cold, 1);
        assert_eq!(result.changed_fields, vec!["api_rate_limit"]);
    }

    fn hbbs_matches(args: &[&str]) -> clap::ArgMatches<'static> {
        App::new("hbbs")
            .args_from_usage(
                "-c --config=[FILE] +takes_value 'Sets a custom config file'
                -p, --port=[NUMBER(default=21116)] 'Sets the listening port'
                -s, --serial=[NUMBER(default=0)] 'Sets configure update serial number'
                -R, --rendezvous-servers=[HOSTS] 'Sets rendezvous servers, separated by comma'
                -u, --software-url=[URL] 'Sets download url'
                -r, --relay-servers=[HOST] 'Sets relay servers'
                -M, --rmem=[NUMBER(default=0)] 'Sets UDP recv buffer size'
                , --mask=[MASK] 'LAN mask'
                -k, --key=[KEY] 'Only allow same key'",
            )
            .get_matches_from(args)
    }

    fn hbbr_matches(args: &[&str]) -> clap::ArgMatches<'static> {
        App::new("hbbr")
            .args_from_usage(
                "-c --config=[FILE] +takes_value 'Sets a custom config file'
                -p, --port=[NUMBER(default=21117)] 'Sets the listening port'
                -k, --key=[KEY] 'Only allow same key'",
            )
            .get_matches_from(args)
    }

    fn temp_config(content: &str) -> PathBuf {
        let path = std::env::temp_dir().join(unique_name("rustdesk-config.toml"));
        fs::write(&path, content).unwrap();
        path
    }

    fn unique_name(prefix: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("{}-{}-{}", prefix, std::process::id(), nanos)
    }

    fn clear_test_env() {
        for key in [
            "PORT",
            "KEY",
            "RENDEZVOUS-SERVERS",
            "RENDEZVOUS_SERVERS",
            "SOFTWARE-URL",
            "SOFTWARE_URL",
            "SERIAL",
            "MASK",
            "RELAY-SERVERS",
            "RELAY_SERVERS",
            "RMEM",
            "TOTAL_BANDWIDTH",
            "SINGLE_BANDWIDTH",
            "LIMIT_SPEED",
            "DOWNGRADE_THRESHOLD",
            "DOWNGRADE_START_CHECK",
            "RUSTDESK_SERVER__ID_SERVER",
            "RUSTDESK_SERVER__RELAY_SERVER",
            "RUSTDESK_SERVER__KEY",
            "RUSTDESK_PRO__JWT_SECRET",
            "RUSTDESK_PRO__JWT_EXPIRY_HOURS",
            "RUSTDESK_PRO__REFRESH_EXPIRY_DAYS",
            "RUSTDESK_RENDEZVOUS__SERVERS",
            "RUSTDESK_RELAY__SERVERS",
        ] {
            std::env::remove_var(key);
        }
    }
}
