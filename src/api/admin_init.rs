use crate::{database::Database, models::user::AdminInitInfo};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use hbb_common::{log, ResultType};
use rand::seq::SliceRandom;

pub async fn create_initial_admin(db: &Database) -> ResultType<Option<AdminInitInfo>> {
    if db.count_users().await? > 0 {
        return Ok(None);
    }

    let password = generate_random_password(16);
    let password_hash = hash_password(&password)?;
    db.create_user("admin", &password_hash, None, "admin")
        .await?;

    log::info!("========================================");
    log::info!("  初始管理员账号已创建");
    log::info!("  用户名: admin");
    log::info!("  密码: {}", password);
    log::info!("  请登录后立即修改该密码");
    log::info!("========================================");

    Ok(Some(AdminInitInfo {
        username: "admin".to_string(),
        password,
    }))
}

pub fn generate_random_password(len: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| *CHARSET.choose(&mut rng).unwrap() as char)
        .collect()
}

pub fn hash_password(password: &str) -> ResultType<String> {
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

    #[test]
    fn test_generate_random_password_length() {
        let password = generate_random_password(16);
        assert_eq!(password.len(), 16);
    }

    #[test]
    fn test_hash_password_uses_argon2() {
        let hash = hash_password("secret").unwrap();
        assert!(hash.starts_with("$argon2"));
    }
}
