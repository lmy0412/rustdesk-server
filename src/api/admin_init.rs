use crate::{
    api::middleware::ApiProtectionState,
    database::Database,
    models::user::{validate_plain_password, AdminInitInfo},
};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use hbb_common::{log, ResultType};

pub const INITIAL_ADMIN_PASSWORD_ENV: &str = "RUSTDESK_INITIAL_ADMIN_PASSWORD";

pub async fn create_initial_admin(
    db: &Database,
    protection: &ApiProtectionState,
) -> ResultType<Option<AdminInitInfo>> {
    if db.count_users().await? > 0 {
        return Ok(None);
    }

    let password = std::env::var(INITIAL_ADMIN_PASSWORD_ENV).map_err(|_| {
        hbb_common::anyhow::anyhow!(
            "{INITIAL_ADMIN_PASSWORD_ENV} must be set for first startup; inject it with a secret manager"
        )
    })?;
    validate_plain_password(&password).map_err(|message| {
        hbb_common::anyhow::anyhow!(
            "{INITIAL_ADMIN_PASSWORD_ENV} is invalid: {message}; the value was not logged"
        )
    })?;
    let password_hash = hash_password_bounded(protection, &password).await?;
    if !db.create_initial_admin_if_empty(&password_hash).await? {
        return Ok(None);
    }

    log::info!("初始管理员账号 admin 已创建，请立即轮换密码并移除一次性环境变量");

    Ok(Some(AdminInitInfo {
        username: "admin".to_string(),
    }))
}

pub async fn hash_password_bounded(
    protection: &ApiProtectionState,
    password: &str,
) -> ResultType<String> {
    validate_plain_password(password)
        .map_err(|message| hbb_common::anyhow::anyhow!(message.to_string()))?;
    let password = password.to_owned();
    let permit = protection
        .acquire_argon2()
        .await
        .map_err(|_| hbb_common::anyhow::anyhow!("password worker unavailable"))?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        hash_password(&password)
    })
    .await
    .map_err(|_| hbb_common::anyhow::anyhow!("password worker failed"))?
}

pub fn hash_password(password: &str) -> ResultType<String> {
    validate_plain_password(password)
        .map_err(|message| hbb_common::anyhow::anyhow!(message.to_string()))?;
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    Ok(argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|err| hbb_common::anyhow::anyhow!(err.to_string()))?
        .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ApiRateLimitConfig;
    use std::{
        sync::{Arc, Mutex},
        time::{SystemTime, UNIX_EPOCH},
    };
    use tokio::sync::Barrier;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_hash_password_uses_argon2() {
        let hash = hash_password("secret").unwrap();
        assert!(hash.starts_with("$argon2"));
    }

    #[test]
    fn test_hash_password_rejects_invalid_plaintext_lengths() {
        assert!(hash_password("").is_err());
        assert!(hash_password(&"a".repeat(1025)).is_err());
    }

    #[test]
    fn initial_admin_requires_a_valid_secret_and_never_echoes_it() {
        let _guard = ENV_LOCK.lock().unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir()
                .join(format!("hbbs-initial-admin-{nonce}.sqlite"))
                .to_string_lossy()
                .into_owned();
            let protection = ApiProtectionState::new(ApiRateLimitConfig::default());

            std::env::remove_var(INITIAL_ADMIN_PASSWORD_ENV);
            let db = Database::new(&path).await.unwrap();
            let missing = create_initial_admin(&db, &protection).await.unwrap_err();
            assert_eq!(db.count_users().await.unwrap(), 0);
            assert!(!missing.to_string().contains("password-value"));

            let invalid_secret = "invalid-secret".repeat(100);
            std::env::set_var(INITIAL_ADMIN_PASSWORD_ENV, &invalid_secret);
            let invalid = create_initial_admin(&db, &protection).await.unwrap_err();
            assert_eq!(db.count_users().await.unwrap(), 0);
            assert!(!invalid.to_string().contains(&invalid_secret));

            let valid_secret = "sentinel-admin-password";
            std::env::set_var(INITIAL_ADMIN_PASSWORD_ENV, valid_secret);
            let created = create_initial_admin(&db, &protection)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(created.username, "admin");
            let user = db.find_user_by_username("admin").await.unwrap().unwrap();
            assert!(!user.password_hash.contains(valid_secret));

            std::env::remove_var(INITIAL_ADMIN_PASSWORD_ENV);
            drop(db);
            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_file(format!("{path}-shm"));
            let _ = std::fs::remove_file(format!("{path}-wal"));
            let _ = std::fs::remove_file(format!("{path}.migration.lock"));
        });
    }

    #[test]
    fn concurrent_empty_database_initialization_creates_exactly_one_admin() {
        let _guard = ENV_LOCK.lock().unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir()
                .join(format!("hbbs-concurrent-initial-admin-{nonce}.sqlite"))
                .to_string_lossy()
                .into_owned();
            let first_db = Database::new(&path).await.unwrap();
            let second_db = Database::new(&path).await.unwrap();
            let first_protection = ApiProtectionState::new(ApiRateLimitConfig::default());
            let second_protection = ApiProtectionState::new(ApiRateLimitConfig::default());
            let barrier = Arc::new(Barrier::new(3));

            std::env::set_var(
                INITIAL_ADMIN_PASSWORD_ENV,
                "concurrent-sentinel-admin-password",
            );
            let first = {
                let barrier = barrier.clone();
                tokio::spawn(async move {
                    barrier.wait().await;
                    create_initial_admin(&first_db, &first_protection).await
                })
            };
            let second = {
                let barrier = barrier.clone();
                tokio::spawn(async move {
                    barrier.wait().await;
                    create_initial_admin(&second_db, &second_protection).await
                })
            };
            barrier.wait().await;
            let first = first.await.unwrap().unwrap();
            let second = second.await.unwrap().unwrap();
            assert_eq!(
                usize::from(first.is_some()) + usize::from(second.is_some()),
                1
            );

            let verification_db = Database::new(&path).await.unwrap();
            assert_eq!(verification_db.count_users().await.unwrap(), 1);
            let admin = verification_db
                .find_user_by_username("admin")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(admin.role, "admin");

            std::env::remove_var(INITIAL_ADMIN_PASSWORD_ENV);
            drop(verification_db);
            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_file(format!("{path}-shm"));
            let _ = std::fs::remove_file(format!("{path}-wal"));
            let _ = std::fs::remove_file(format!("{path}.migration.lock"));
        });
    }
}
