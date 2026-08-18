use crate::{
    config::{validate_security_config, SecurityConfig},
    database::Database,
};
use chrono::Utc;
use hbb_common::ResultType;
use ipnetwork::IpNetwork;
use std::{
    net::IpAddr,
    sync::{Arc, RwLock},
};
use tokio::sync::Mutex;

const MAX_PASSWORD_BYTES: usize = 1024;
const MAX_FUTURE_IAT_SECONDS: i64 = 300;

#[derive(Clone)]
pub struct SecurityPolicyState {
    current: Arc<RwLock<SecurityConfig>>,
    update_lock: Arc<Mutex<()>>,
}

impl SecurityPolicyState {
    pub fn new(config: SecurityConfig) -> Result<Self, String> {
        validate_security_config(&config)?;
        Ok(Self {
            current: Arc::new(RwLock::new(config)),
            update_lock: Arc::new(Mutex::new(())),
        })
    }

    pub async fn load(db: &Database, defaults: &SecurityConfig) -> ResultType<Self> {
        validate_security_config(defaults).map_err(|error| hbb_common::anyhow::anyhow!(error))?;
        let config = db.load_or_create_security_policy(defaults).await?;
        validate_security_config(&config).map_err(|error| hbb_common::anyhow::anyhow!(error))?;
        Self::new(config).map_err(|error| hbb_common::anyhow::anyhow!(error))
    }

    pub fn snapshot(&self) -> Result<SecurityConfig, String> {
        self.current
            .read()
            .map(|config| config.clone())
            .map_err(|_| "security policy lock poisoned".to_string())
    }

    pub async fn update(&self, db: &Database, config: SecurityConfig) -> Result<(), String> {
        validate_security_config(&config)?;
        let _guard = self.update_lock.lock().await;
        db.save_security_policy(&config)
            .await
            .map_err(|_| "security policy save failed".to_string())?;
        let mut current = self
            .current
            .write()
            .map_err(|_| "security policy lock poisoned".to_string())?;
        *current = config;
        Ok(())
    }

    pub fn admin_ip_allowed(&self, ip: IpAddr) -> Result<bool, String> {
        let config = self.snapshot()?;
        if config.allowed_admin_cidrs.is_empty() {
            return Ok(true);
        }
        for cidr in config.allowed_admin_cidrs {
            let network = cidr
                .parse::<IpNetwork>()
                .map_err(|_| "stored security policy contains invalid CIDR".to_string())?;
            if network.contains(ip) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn validate_new_password(&self, password: &str) -> Result<(), String> {
        let config = self.snapshot()?;
        validate_password(password, &config)
    }

    pub fn access_lifetime_seconds(&self, configured_hours: i64) -> Result<i64, String> {
        let config = self.snapshot()?;
        let configured = configured_hours
            .checked_mul(3600)
            .ok_or_else(|| "configured JWT lifetime is out of range".to_string())?;
        let policy = i64::from(config.session_timeout_minutes)
            .checked_mul(60)
            .ok_or_else(|| "session timeout is out of range".to_string())?;
        Ok(configured.min(policy))
    }

    pub fn validate_session_issued_at(&self, issued_at: i64) -> Result<(), String> {
        let config = self.snapshot()?;
        let now = Utc::now().timestamp();
        if issued_at > now.saturating_add(MAX_FUTURE_IAT_SECONDS) {
            return Err("token issued-at time is in the future".to_string());
        }
        let max_age = i64::from(config.session_timeout_minutes)
            .checked_mul(60)
            .ok_or_else(|| "session timeout is out of range".to_string())?;
        if now.saturating_sub(issued_at) > max_age {
            return Err("session expired".to_string());
        }
        Ok(())
    }
}

pub fn validate_password(password: &str, config: &SecurityConfig) -> Result<(), String> {
    if password.is_empty() || password.len() > MAX_PASSWORD_BYTES {
        return Err("password must contain 1 to 1024 UTF-8 bytes".to_string());
    }
    if password.chars().count() < config.password_min_length {
        return Err(format!(
            "password must contain at least {} characters",
            config.password_min_length
        ));
    }
    if config.password_require_number && !password.chars().any(|ch| ch.is_ascii_digit()) {
        return Err("password must contain an ASCII number".to_string());
    }
    if config.password_require_symbol
        && !password
            .chars()
            .any(|ch| !ch.is_alphanumeric() && !ch.is_whitespace())
    {
        return Err("password must contain a symbol".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_policy_enforces_each_requirement() {
        let config = SecurityConfig::default();
        assert!(validate_password("Strong-pass-1", &config).is_ok());
        assert!(validate_password("short-1!", &config).is_err());
        assert!(validate_password("Strong-password!", &config).is_err());
        assert!(validate_password("Strongpassword1", &config).is_err());
    }

    #[test]
    fn admin_cidr_uses_direct_ip_membership() {
        let config = SecurityConfig {
            allowed_admin_cidrs: vec!["10.0.0.0/8".to_string(), "2001:db8::/32".to_string()],
            ..SecurityConfig::default()
        };
        let state = SecurityPolicyState::new(config).unwrap();
        assert!(state.admin_ip_allowed("10.1.2.3".parse().unwrap()).unwrap());
        assert!(state
            .admin_ip_allowed("2001:db8::1".parse().unwrap())
            .unwrap());
        assert!(!state
            .admin_ip_allowed("192.0.2.1".parse().unwrap())
            .unwrap());
    }
}
