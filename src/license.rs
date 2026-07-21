use crate::{database::Database, pubkey::VENDOR_PUBKEY};
use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{Signature, VerifyingKey};
use hbb_common::log;
use protobuf::Message as _;
use std::sync::{OnceLock, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::license_proto::license as proto;

#[derive(Debug, Clone)]
pub struct License {
    pub issued_to: String,
    pub max_devices: u32,
    pub max_users: u32,
    pub features: u64,
    pub issued_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum LicenseError {
    #[error("invalid license format: {0}")]
    InvalidFormat(String),
    #[error("base32 decode failed: {0}")]
    Base32Decode(String),
    #[error("protobuf deserialize failed: {0}")]
    ProtobufDeserialize(String),
    #[error("signature verification failed")]
    SignatureVerification,
    #[error("license has expired (expired at {0})")]
    Expired(String),
    #[error("no license configured")]
    NoLicense,
    #[error("license overuse: {current}/{max}")]
    Overuse { current: u32, max: u32 },
    #[error("database error: {0}")]
    Database(String),
}

#[derive(Debug, Clone)]
pub struct LicenseState {
    pub license: Option<License>,
    pub loaded_at: i64,
}

pub static LICENSE_STATE: OnceLock<RwLock<LicenseState>> = OnceLock::new();

pub fn init_license_state() {
    let _ = LICENSE_STATE.get_or_init(|| {
        RwLock::new(LicenseState {
            license: None,
            loaded_at: now_timestamp(),
        })
    });
}

pub fn parse_license_key(encoded: &str) -> Result<License, LicenseError> {
    let normalized = normalize_license_key(encoded)?;
    let combined = BASE32_NOPAD
        .decode(normalized.as_bytes())
        .map_err(|err| LicenseError::Base32Decode(err.to_string()))?;
    if combined.len() <= 64 {
        return Err(LicenseError::InvalidFormat(
            "license payload is too short".to_string(),
        ));
    }

    let split_at = combined.len() - 64;
    let (license_bytes, signature_bytes) = combined.split_at(split_at);
    let signature_bytes: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| LicenseError::InvalidFormat("invalid signature length".to_string()))?;
    let license_proto = proto::License::parse_from_bytes(license_bytes)
        .map_err(|err| LicenseError::ProtobufDeserialize(err.to_string()))?;

    verify_signature(license_bytes, &signature_bytes)?;

    Ok(License {
        issued_to: license_proto.issued_to().to_string(),
        max_devices: license_proto.max_devices(),
        max_users: license_proto.max_users(),
        features: license_proto.features(),
        issued_at: license_proto.issued_at(),
        expires_at: license_proto.expires_at(),
    })
}

pub fn check_license_valid_for_connection() -> Result<(), LicenseError> {
    let state = state_lock()
        .read()
        .map_err(|_| LicenseError::InvalidFormat("license state lock poisoned".to_string()))?;
    let license = state.license.as_ref().ok_or(LicenseError::NoLicense)?;
    if license.expires_at != 0 && license.expires_at < now_timestamp() {
        return Err(LicenseError::Expired(license.expires_at.to_string()));
    }
    Ok(())
}

pub async fn load_license_from_database(db: &Database) -> Result<(), LicenseError> {
    init_license_state();
    match db
        .get_active_license_key()
        .await
        .map_err(|err| LicenseError::Database(err.to_string()))?
    {
        Some(license_key) => {
            let license = parse_license_key(&license_key)?;
            set_license(license);
            log::info!("已从数据库加载许可证");
        }
        None => {
            clear_license();
            log::info!("数据库中没有激活的许可证");
        }
    }
    Ok(())
}

pub fn set_license(license: License) {
    init_license_state();
    if let Ok(mut state) = state_lock().write() {
        state.license = Some(license);
        state.loaded_at = now_timestamp();
    }
}

pub fn clear_license() {
    init_license_state();
    if let Ok(mut state) = state_lock().write() {
        state.license = None;
        state.loaded_at = now_timestamp();
    }
}

pub fn current_license() -> Option<License> {
    init_license_state();
    state_lock()
        .read()
        .ok()
        .and_then(|state| state.license.clone())
}

pub fn is_license_expired(license: &License) -> bool {
    license.expires_at != 0 && license.expires_at < now_timestamp()
}

pub fn days_remaining(license: &License) -> Option<i64> {
    if license.expires_at == 0 {
        return None;
    }
    Some(((license.expires_at - now_timestamp()) / 86_400).max(0))
}

pub fn now_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn normalize_license_key(encoded: &str) -> Result<String, LicenseError> {
    let upper = encoded.trim().to_ascii_uppercase();
    let body = upper.strip_prefix("RUSTDESK-").ok_or_else(|| {
        LicenseError::InvalidFormat("license must start with RUSTDESK-".to_string())
    })?;
    let compact = body.replace('-', "").replace(char::is_whitespace, "");
    if compact.is_empty() {
        return Err(LicenseError::InvalidFormat(
            "license payload is empty".to_string(),
        ));
    }
    if compact.contains('=') {
        return Err(LicenseError::InvalidFormat(
            "base32 padding is not supported".to_string(),
        ));
    }
    Ok(compact)
}

fn verify_signature(license_bytes: &[u8], signature_bytes: &[u8; 64]) -> Result<(), LicenseError> {
    let pubkey = VerifyingKey::from_bytes(&VENDOR_PUBKEY)
        .map_err(|_| LicenseError::SignatureVerification)?;
    let signature = Signature::from_bytes(signature_bytes);
    pubkey
        .verify_strict(license_bytes, &signature)
        .map_err(|_| LicenseError::SignatureVerification)
}

fn state_lock() -> &'static RwLock<LicenseState> {
    LICENSE_STATE.get_or_init(|| {
        RwLock::new(LicenseState {
            license: None,
            loaded_at: now_timestamp(),
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_format_requires_prefix() {
        let err = parse_license_key("INVALID-FORMAT").unwrap_err();
        assert!(matches!(err, LicenseError::InvalidFormat(_)));
    }

    #[test]
    fn invalid_format_requires_prefix_separator() {
        let err = normalize_license_key("RUSTDESKABCDEF").unwrap_err();
        assert!(matches!(err, LicenseError::InvalidFormat(_)));
    }

    #[test]
    fn normalize_allows_payload_separators() {
        let normalized = normalize_license_key(" rustdesk-AB-CD\nEF ").unwrap();
        assert_eq!(normalized, "ABCDEF");
    }

    #[test]
    fn connection_check_rejects_missing_license() {
        clear_license();
        let err = check_license_valid_for_connection().unwrap_err();
        assert!(matches!(err, LicenseError::NoLicense));
    }

    #[test]
    fn connection_check_rejects_expired_license() {
        set_license(License {
            issued_to: "测试".to_string(),
            max_devices: 1,
            max_users: 1,
            features: 0,
            issued_at: 1,
            expires_at: 1,
        });
        let err = check_license_valid_for_connection().unwrap_err();
        assert!(matches!(err, LicenseError::Expired(_)));
        clear_license();
    }
}
