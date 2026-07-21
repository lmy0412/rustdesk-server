use crate::models::user::User;
use async_trait::async_trait;
use hbb_common::{bail, log, ResultType};
use sqlx::{
    sqlite::SqliteConnectOptions, ConnectOptions, Connection, Error as SqlxError, Row, Sqlite,
    SqliteConnection,
};
use std::{ops::DerefMut, str::FromStr};
//use sqlx::postgres::PgPoolOptions;
//use sqlx::mysql::MySqlPoolOptions;

type Pool = deadpool::managed::Pool<DbPool>;
const USER_COLUMNS: &str = "id, username, password_hash, email, role, is_active, token_version, oauth_provider, oauth_subject, last_login_at, created_at, updated_at";

pub struct DbPool {
    url: String,
}

#[async_trait]
impl deadpool::managed::Manager for DbPool {
    type Type = SqliteConnection;
    type Error = SqlxError;
    async fn create(&self) -> Result<SqliteConnection, SqlxError> {
        let mut opt = SqliteConnectOptions::from_str(&self.url).unwrap();
        opt.log_statements(log::LevelFilter::Debug);
        SqliteConnection::connect_with(&opt).await
    }
    async fn recycle(
        &self,
        obj: &mut SqliteConnection,
    ) -> deadpool::managed::RecycleResult<SqlxError> {
        Ok(obj.ping().await?)
    }
}

#[derive(Clone)]
pub struct Database {
    pool: Pool,
}

#[derive(Default, sqlx::FromRow)]
pub struct Peer {
    pub guid: Vec<u8>,
    pub id: String,
    pub uuid: Vec<u8>,
    pub pk: Vec<u8>,
    pub user: Option<Vec<u8>>,
    pub info: String,
    pub status: Option<i64>,
    pub note: Option<String>,
    pub owner_user_id: Option<i64>,
    pub group_id: Option<i64>,
    pub features: Option<String>,
    pub token_version: i64,
}

#[derive(Debug, Default)]
pub struct UpdateUserFields {
    pub email: Option<String>,
    pub role: Option<String>,
    pub is_active: Option<bool>,
    pub password_hash: Option<String>,
    pub increment_token_version: bool,
}

impl Database {
    pub async fn new(url: &str) -> ResultType<Database> {
        if let Some(parent) = std::path::Path::new(url).parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).ok();
            }
        }
        if !std::path::Path::new(url).exists() {
            std::fs::File::create(url).ok();
        }
        let n: usize = std::env::var("MAX_DATABASE_CONNECTIONS")
            .unwrap_or_else(|_| "1".to_owned())
            .parse()
            .unwrap_or(1);
        log::debug!("MAX_DATABASE_CONNECTIONS={}", n);
        let pool = Pool::new(
            DbPool {
                url: url.to_owned(),
            },
            n,
        );
        let mut conn = pool.get().await?;
        log::info!("Running database migrations...");
        sqlx::migrate!().run(conn.deref_mut()).await?;
        ensure_users_token_version_column(conn.deref_mut()).await?;
        migrate_legacy_peer_if_exists(conn.deref_mut()).await?;
        log::info!("Database migrations complete");
        let db = Database { pool };
        Ok(db)
    }

    #[allow(dead_code)]
    async fn create_tables(&self) -> ResultType<()> {
        Ok(())
    }

    pub async fn get_peer(&self, id: &str) -> ResultType<Option<Peer>> {
        Ok(sqlx::query_as::<_, Peer>(
            "
            SELECT
                guid,
                device_id AS id,
                uuid,
                pk,
                CAST(NULL AS BLOB) AS user,
                info,
                CAST(NULL AS INTEGER) AS status,
                note,
                owner_user_id,
                group_id,
                features,
                token_version
            FROM devices
            WHERE device_id = ?
            ",
        )
        .bind(id)
        .fetch_optional(self.pool.get().await?.deref_mut())
        .await?)
    }

    pub async fn insert_peer(
        &self,
        id: &str,
        uuid: &[u8],
        pk: &[u8],
        info: &str,
    ) -> ResultType<Vec<u8>> {
        let guid = uuid::Uuid::new_v4().as_bytes().to_vec();
        sqlx::query("INSERT INTO devices(guid, device_id, uuid, pk, info) VALUES(?, ?, ?, ?, ?)")
            .bind(&guid)
            .bind(id)
            .bind(uuid)
            .bind(pk)
            .bind(info)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(guid)
    }

    pub async fn update_pk(
        &self,
        guid: &Vec<u8>,
        id: &str,
        pk: &[u8],
        info: &str,
    ) -> ResultType<()> {
        sqlx::query("UPDATE devices SET device_id=?, pk=?, info=? WHERE guid=?")
            .bind(id)
            .bind(pk)
            .bind(info)
            .bind(guid)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(())
    }

    pub async fn create_user(
        &self,
        username: &str,
        password_hash: &str,
        email: Option<&str>,
        role: &str,
    ) -> ResultType<User> {
        Ok(sqlx::query_as::<_, User>(
            "
            INSERT INTO users(username, password_hash, email, role)
            VALUES(?, ?, ?, ?)
            RETURNING id, username, password_hash, email, role, is_active, token_version, oauth_provider, oauth_subject, last_login_at, created_at, updated_at
            ",
        )
        .bind(username)
        .bind(password_hash)
        .bind(email)
        .bind(role)
        .fetch_one(self.pool.get().await?.deref_mut())
        .await?)
    }

    pub async fn find_user_by_id(&self, id: i64) -> ResultType<Option<User>> {
        Ok(sqlx::query_as::<_, User>(
            "
            SELECT id, username, password_hash, email, role, is_active, token_version, oauth_provider, oauth_subject, last_login_at, created_at, updated_at
            FROM users
            WHERE id = ?
            ",
        )
        .bind(id)
        .fetch_optional(self.pool.get().await?.deref_mut())
        .await?)
    }

    pub async fn find_user_by_username(&self, username: &str) -> ResultType<Option<User>> {
        Ok(sqlx::query_as::<_, User>(
            "
            SELECT id, username, password_hash, email, role, is_active, token_version, oauth_provider, oauth_subject, last_login_at, created_at, updated_at
            FROM users
            WHERE username = ?
            ",
        )
        .bind(username)
        .fetch_optional(self.pool.get().await?.deref_mut())
        .await?)
    }

    pub async fn list_users(&self, page: i64, page_size: i64) -> ResultType<(Vec<User>, i64)> {
        let page = page.max(1);
        let page_size = page_size.clamp(1, 100);
        let offset = (page - 1) * page_size;

        let users = sqlx::query_as::<_, User>(
            "
            SELECT id, username, password_hash, email, role, is_active, token_version, oauth_provider, oauth_subject, last_login_at, created_at, updated_at
            FROM users
            ORDER BY id
            LIMIT ? OFFSET ?
            ",
        )
        .bind(page_size)
        .bind(offset)
        .fetch_all(self.pool.get().await?.deref_mut())
        .await?;

        let total = self.count_users().await?;
        Ok((users, total))
    }

    pub async fn find_users_by_email(&self, email: &str) -> ResultType<Vec<User>> {
        let sql = format!("SELECT {USER_COLUMNS} FROM users WHERE email = ?");
        Ok(sqlx::query_as::<_, User>(&sql)
            .bind(email)
            .fetch_all(self.pool.get().await?.deref_mut())
            .await?)
    }

    pub async fn find_user_by_oauth(
        &self,
        provider: &str,
        subject: &str,
    ) -> ResultType<Option<User>> {
        let sql = format!(
            "SELECT {USER_COLUMNS} FROM users WHERE oauth_provider = ? AND oauth_subject = ?"
        );
        Ok(sqlx::query_as::<_, User>(&sql)
            .bind(provider)
            .bind(subject)
            .fetch_optional(self.pool.get().await?.deref_mut())
            .await?)
    }

    pub async fn create_oidc_user(
        &self,
        username: &str,
        email: Option<&str>,
        provider: &str,
        subject: &str,
    ) -> ResultType<User> {
        Ok(sqlx::query_as::<_, User>(
            "
            INSERT INTO users(username, password_hash, email, role, oauth_provider, oauth_subject, last_login_at)
            VALUES(?, '', ?, 'user', ?, ?, current_timestamp)
            RETURNING id, username, password_hash, email, role, is_active, token_version, oauth_provider, oauth_subject, last_login_at, created_at, updated_at
            ",
        )
        .bind(username)
        .bind(email)
        .bind(provider)
        .bind(subject)
        .fetch_one(self.pool.get().await?.deref_mut())
        .await?)
    }

    pub async fn link_user_to_oidc(
        &self,
        user_id: i64,
        provider: &str,
        subject: &str,
    ) -> ResultType<User> {
        let affected = sqlx::query(
            "
            UPDATE users
            SET oauth_provider = ?, oauth_subject = ?, last_login_at = current_timestamp, updated_at = current_timestamp
            WHERE id = ? AND (oauth_provider IS NULL OR oauth_provider = '')
            ",
        )
        .bind(provider)
        .bind(subject)
        .bind(user_id)
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        if affected.rows_affected() == 0 {
            bail!("user already linked or not found");
        }
        self.find_user_by_id(user_id)
            .await?
            .ok_or_else(|| hbb_common::anyhow::anyhow!("user not found"))
    }

    pub async fn update_last_login(&self, user_id: i64) -> ResultType<User> {
        let affected = sqlx::query(
            "
            UPDATE users
            SET last_login_at = current_timestamp
            WHERE id = ?
            ",
        )
        .bind(user_id)
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        if affected.rows_affected() == 0 {
            bail!("user not found");
        }
        self.find_user_by_id(user_id)
            .await?
            .ok_or_else(|| hbb_common::anyhow::anyhow!("user not found"))
    }

    pub async fn update_user(&self, id: i64, fields: UpdateUserFields) -> ResultType<User> {
        if fields.email.is_none()
            && fields.role.is_none()
            && fields.is_active.is_none()
            && fields.password_hash.is_none()
            && !fields.increment_token_version
        {
            return self
                .find_user_by_id(id)
                .await?
                .ok_or_else(|| hbb_common::anyhow::anyhow!("user not found"));
        }

        let mut query = sqlx::QueryBuilder::<Sqlite>::new("UPDATE users SET ");
        let mut separated = query.separated(", ");
        if let Some(email) = fields.email.as_ref() {
            separated.push("email = ");
            separated.push_bind(email);
        }
        if let Some(role) = fields.role.as_ref() {
            separated.push("role = ");
            separated.push_bind(role);
        }
        if let Some(is_active) = fields.is_active {
            separated.push("is_active = ");
            separated.push_bind(is_active);
        }
        if let Some(password_hash) = fields.password_hash.as_ref() {
            separated.push("password_hash = ");
            separated.push_bind(password_hash);
        }
        if fields.increment_token_version {
            separated.push("token_version = token_version + 1");
        }
        separated.push("updated_at = current_timestamp");
        drop(separated);
        query.push(" WHERE id = ");
        query.push_bind(id);

        let affected = query
            .build()
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        if affected.rows_affected() == 0 {
            bail!("user not found");
        }

        self.find_user_by_id(id)
            .await?
            .ok_or_else(|| hbb_common::anyhow::anyhow!("user not found"))
    }

    pub async fn update_password(
        &self,
        id: i64,
        new_hash: &str,
        new_token_version: i64,
    ) -> ResultType<()> {
        let affected = sqlx::query(
            "
            UPDATE users
            SET password_hash = ?, token_version = ?, updated_at = current_timestamp
            WHERE id = ?
            ",
        )
        .bind(new_hash)
        .bind(new_token_version)
        .bind(id)
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        if affected.rows_affected() == 0 {
            bail!("user not found");
        }
        Ok(())
    }

    pub async fn increment_token_version(&self, id: i64) -> ResultType<i64> {
        let affected = sqlx::query(
            "
            UPDATE users
            SET token_version = token_version + 1, updated_at = current_timestamp
            WHERE id = ?
            ",
        )
        .bind(id)
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        if affected.rows_affected() == 0 {
            bail!("user not found");
        }
        self.get_user_token_version(id).await
    }

    pub async fn deactivate_user(&self, id: i64) -> ResultType<()> {
        let affected = sqlx::query(
            "
            UPDATE users
            SET is_active = 0, token_version = token_version + 1, updated_at = current_timestamp
            WHERE id = ?
            ",
        )
        .bind(id)
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        if affected.rows_affected() == 0 {
            bail!("user not found");
        }
        Ok(())
    }

    pub async fn delete_user(&self, id: i64) -> ResultType<()> {
        let affected = sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(id)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        if affected.rows_affected() == 0 {
            bail!("user not found");
        }
        Ok(())
    }

    pub async fn count_users(&self) -> ResultType<i64> {
        let row = sqlx::query("SELECT COUNT(*) AS count FROM users")
            .fetch_one(self.pool.get().await?.deref_mut())
            .await?;
        Ok(row.try_get::<i64, _>("count")?)
    }

    pub async fn get_user_token_version(&self, id: i64) -> ResultType<i64> {
        let row = sqlx::query("SELECT token_version FROM users WHERE id = ?")
            .bind(id)
            .fetch_optional(self.pool.get().await?.deref_mut())
            .await?;
        match row {
            Some(row) => Ok(row.try_get::<i64, _>("token_version")?),
            None => bail!("user not found"),
        }
    }
}

async fn migrate_legacy_peer_if_exists(conn: &mut SqliteConnection) -> ResultType<()> {
    let peer_exists = fetch_count(
        conn,
        "SELECT COUNT(*) AS count FROM sqlite_master WHERE type='table' AND name='peer'",
    )
    .await?
        > 0;
    if !peer_exists {
        return Ok(());
    }

    let devices_count = fetch_count(conn, "SELECT COUNT(*) AS count FROM devices").await?;
    if devices_count > 0 {
        log::info!(
            "Legacy peer migration skipped: devices already contains {} rows",
            devices_count
        );
        return Ok(());
    }

    let mut tx = conn.begin().await?;
    let affected = sqlx::query(
        "
        INSERT INTO devices (guid, uuid, pk, device_id, note, info, created_at)
        SELECT
            guid,
            uuid,
            pk,
            id AS device_id,
            CASE WHEN note IS NULL OR note = '' THEN NULL ELSE note END,
            info,
            COALESCE(created_at, current_timestamp)
        FROM peer
        ",
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query("ALTER TABLE peer RENAME TO peer_backup_legacy")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    log::info!(
        "Migrated {} rows from peer to devices; old table renamed to peer_backup_legacy",
        affected.rows_affected()
    );
    Ok(())
}

async fn ensure_users_token_version_column(conn: &mut SqliteConnection) -> ResultType<()> {
    let rows = sqlx::query("PRAGMA table_info(users)")
        .fetch_all(&mut *conn)
        .await?;
    let has_token_version = rows
        .iter()
        .any(|row| row.try_get::<String, _>("name").ok().as_deref() == Some("token_version"));
    if !has_token_version {
        sqlx::query("ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0")
            .execute(&mut *conn)
            .await?;
    }
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_users_token_version ON users (token_version)")
        .execute(&mut *conn)
        .await?;
    Ok(())
}

async fn fetch_count(conn: &mut SqliteConnection, sql: &str) -> ResultType<i64> {
    let row = sqlx::query(sql).fetch_one(&mut *conn).await?;
    Ok(row.try_get::<i64, _>("count")?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hbb_common::tokio;
    use sqlx::{Connection, Executor, SqliteConnection};
    use std::time::{SystemTime, UNIX_EPOCH};

    const TEST_GUID: &[u8] = b"guid-binary-0001";
    const TEST_UUID: &[u8] = b"uuid-binary-0001";
    const TEST_PK: &[u8] = b"pk-binary-0001";

    #[test]
    fn test_new_database_schema() {
        run(async {
            let path = temp_db_path("new-schema");
            let db = Database::new(&path).await.unwrap();

            for table in [
                "devices",
                "users",
                "groups",
                "licenses",
                "audit_logs",
                "_sqlx_migrations",
            ] {
                assert!(
                    table_exists(&db, table).await.unwrap(),
                    "{table} should exist"
                );
            }
            assert!(
                column_exists(&db, "users", "token_version").await.unwrap(),
                "users.token_version should exist"
            );
            for column in ["oauth_provider", "oauth_subject", "last_login_at"] {
                assert!(
                    column_exists(&db, "users", column).await.unwrap(),
                    "users.{column} should exist"
                );
            }
            assert!(index_exists(&db, "idx_users_oauth").await.unwrap());
            assert!(index_exists(&db, "idx_users_last_login_at").await.unwrap());

            cleanup(&path);
        });
    }

    #[test]
    fn test_existing_users_table_without_token_version_is_repaired() {
        run(async {
            let path = temp_db_path("repair-users-token-version");
            create_users_table_without_token_version(&path)
                .await
                .unwrap();

            let db = Database::new(&path).await.unwrap();

            assert!(
                column_exists(&db, "users", "token_version").await.unwrap(),
                "users.token_version should be repaired"
            );
            for column in ["oauth_provider", "oauth_subject", "last_login_at"] {
                assert!(
                    column_exists(&db, "users", column).await.unwrap(),
                    "users.{column} should be added by migration"
                );
            }
            assert!(index_exists(&db, "idx_users_token_version").await.unwrap());
            cleanup(&path);
        });
    }

    #[test]
    fn test_migrate_peer_to_devices() {
        run(async {
            let path = temp_db_path("migrate-peer");
            create_legacy_peer_db(&path, true).await.unwrap();
            insert_legacy_peer(&path, "device-a", Some("hello"))
                .await
                .unwrap();

            let db = Database::new(&path).await.unwrap();

            assert_eq!(count(&db, "SELECT COUNT(*) AS count FROM devices").await, 1);
            assert!(table_exists(&db, "peer_backup_legacy").await.unwrap());
            assert!(!table_exists(&db, "peer").await.unwrap());

            let peer = db.get_peer("device-a").await.unwrap().unwrap();
            assert_eq!(peer.guid, TEST_GUID);
            assert_eq!(peer.uuid, TEST_UUID);
            assert_eq!(peer.pk, TEST_PK);
            assert_eq!(peer.id, "device-a");
            assert_eq!(peer.note.as_deref(), Some("hello"));
            assert_eq!(peer.info, "{\"ip\":\"127.0.0.1\"}");

            cleanup(&path);
        });
    }

    #[test]
    fn test_migrate_guid_uuid_pk_blob() {
        run(async {
            let path = temp_db_path("migrate-blob");
            create_legacy_peer_db(&path, true).await.unwrap();
            insert_legacy_peer(&path, "device-blob", Some("blob-note"))
                .await
                .unwrap();

            let db = Database::new(&path).await.unwrap();
            let mut conn = db.pool.get().await.unwrap();
            let row = sqlx::query(
                "SELECT typeof(guid) AS guid_type, typeof(uuid) AS uuid_type, typeof(pk) AS pk_type FROM devices WHERE device_id = ?",
            )
            .bind("device-blob")
            .fetch_one(conn.deref_mut())
            .await
            .unwrap();

            assert_eq!(row.try_get::<String, _>("guid_type").unwrap(), "blob");
            assert_eq!(row.try_get::<String, _>("uuid_type").unwrap(), "blob");
            assert_eq!(row.try_get::<String, _>("pk_type").unwrap(), "blob");

            cleanup(&path);
        });
    }

    #[test]
    fn test_migrate_note_field() {
        run(async {
            let path = temp_db_path("migrate-note");
            create_legacy_peer_db(&path, true).await.unwrap();
            insert_legacy_peer(&path, "device-note", Some("note-value"))
                .await
                .unwrap();

            let db = Database::new(&path).await.unwrap();
            let peer = db.get_peer("device-note").await.unwrap().unwrap();

            assert_eq!(peer.note.as_deref(), Some("note-value"));

            cleanup(&path);
        });
    }

    #[test]
    fn test_migrate_idempotent() {
        run(async {
            let path = temp_db_path("migrate-idempotent");
            create_legacy_peer_db(&path, true).await.unwrap();
            insert_legacy_peer(&path, "device-idempotent", None)
                .await
                .unwrap();

            let db = Database::new(&path).await.unwrap();
            assert_eq!(count(&db, "SELECT COUNT(*) AS count FROM devices").await, 1);
            drop(db);

            let db = Database::new(&path).await.unwrap();
            assert_eq!(count(&db, "SELECT COUNT(*) AS count FROM devices").await, 1);

            cleanup(&path);
        });
    }

    #[test]
    fn test_migrate_transaction_rollback() {
        run(async {
            let path = temp_db_path("migrate-rollback");
            create_legacy_peer_db(&path, false).await.unwrap();
            insert_invalid_legacy_peer(&path).await.unwrap();

            let err = Database::new(&path).await.err().unwrap();
            assert!(err.to_string().contains("NOT NULL") || err.to_string().contains("pk"));

            let mut conn = connect(&path).await.unwrap();
            assert!(raw_table_exists(&mut conn, "peer").await.unwrap());
            assert!(!raw_table_exists(&mut conn, "peer_backup_legacy")
                .await
                .unwrap());
            assert_eq!(
                raw_count(&mut conn, "SELECT COUNT(*) AS count FROM peer")
                    .await
                    .unwrap(),
                1
            );
            assert_eq!(
                raw_count(&mut conn, "SELECT COUNT(*) AS count FROM devices")
                    .await
                    .unwrap(),
                0
            );

            cleanup(&path);
        });
    }

    #[test]
    fn test_get_peer_after_migration() {
        run(async {
            let path = temp_db_path("get-peer-after-migration");
            create_legacy_peer_db(&path, true).await.unwrap();
            insert_legacy_peer(&path, "device-get", None).await.unwrap();

            let db = Database::new(&path).await.unwrap();
            let peer = db.get_peer("device-get").await.unwrap().unwrap();

            assert_eq!(peer.id, "device-get");
            assert_eq!(peer.pk, TEST_PK);

            cleanup(&path);
        });
    }

    #[test]
    fn test_insert_peer_to_devices() {
        run(async {
            let path = temp_db_path("insert-peer");
            let db = Database::new(&path).await.unwrap();

            let guid = db
                .insert_peer("new-device", TEST_UUID, TEST_PK, "{\"ip\":\"10.0.0.1\"}")
                .await
                .unwrap();
            let peer = db.get_peer("new-device").await.unwrap().unwrap();

            assert_eq!(peer.guid, guid);
            assert_eq!(peer.uuid, TEST_UUID);
            assert_eq!(peer.pk, TEST_PK);

            cleanup(&path);
        });
    }

    #[test]
    fn test_update_pk_to_devices() {
        run(async {
            let path = temp_db_path("update-peer");
            let db = Database::new(&path).await.unwrap();

            let guid = db
                .insert_peer("before-update", TEST_UUID, TEST_PK, "{\"ip\":\"10.0.0.1\"}")
                .await
                .unwrap();
            let new_pk = b"new-pk-binary";
            db.update_pk(&guid, "after-update", new_pk, "{\"ip\":\"10.0.0.2\"}")
                .await
                .unwrap();

            assert!(db.get_peer("before-update").await.unwrap().is_none());
            let peer = db.get_peer("after-update").await.unwrap().unwrap();
            assert_eq!(peer.guid, guid);
            assert_eq!(peer.pk, new_pk);
            assert_eq!(peer.info, "{\"ip\":\"10.0.0.2\"}");

            cleanup(&path);
        });
    }

    #[test]
    fn test_insert() {
        run(async {
            let path = temp_db_path("concurrent-insert");
            let db = Database::new(&path).await.unwrap();
            let mut jobs = vec![];
            for i in 0..10000 {
                let cloned = db.clone();
                let id = i.to_string();
                let a = tokio::spawn(async move {
                    cloned
                        .insert_peer(&id, TEST_UUID, TEST_PK, "{}")
                        .await
                        .unwrap();
                });
                jobs.push(a);
            }
            for i in 0..10000 {
                let cloned = db.clone();
                let id = i.to_string();
                let a = tokio::spawn(async move {
                    cloned.get_peer(&id).await.unwrap();
                });
                jobs.push(a);
            }
            hbb_common::futures::future::join_all(jobs).await;

            cleanup(&path);
        });
    }

    fn run<F>(future: F)
    where
        F: std::future::Future<Output = ()>,
    {
        tokio::runtime::Runtime::new().unwrap().block_on(future);
    }

    fn temp_db_path(name: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir()
            .join(format!("rustdesk-{name}-{nanos}.sqlite3"))
            .to_string_lossy()
            .to_string()
    }

    fn cleanup(path: &str) {
        std::fs::remove_file(path).ok();
        std::fs::remove_file(format!("{path}-shm")).ok();
        std::fs::remove_file(format!("{path}-wal")).ok();
    }

    async fn connect(path: &str) -> ResultType<SqliteConnection> {
        if !std::path::Path::new(path).exists() {
            std::fs::File::create(path).ok();
        }
        Ok(SqliteConnection::connect(path).await?)
    }

    async fn create_legacy_peer_db(path: &str, strict_not_null: bool) -> ResultType<()> {
        let mut conn = connect(path).await?;
        let pk_definition = if strict_not_null {
            "pk BLOB NOT NULL"
        } else {
            "pk BLOB"
        };
        let sql = format!(
            "
            CREATE TABLE peer (
                guid BLOB PRIMARY KEY NOT NULL,
                id VARCHAR(100) NOT NULL,
                uuid BLOB NOT NULL,
                {pk_definition},
                created_at DATETIME NOT NULL DEFAULT (current_timestamp),
                user BLOB,
                status TINYINT,
                note VARCHAR(300),
                info TEXT NOT NULL
            ) WITHOUT ROWID
            "
        );
        conn.execute(sql.as_str()).await?;
        Ok(())
    }

    async fn create_users_table_without_token_version(path: &str) -> ResultType<()> {
        let mut conn = connect(path).await?;
        conn.execute(
            "
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username VARCHAR(100) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                email VARCHAR(255),
                role VARCHAR(50) NOT NULL DEFAULT 'user',
                is_active BOOLEAN NOT NULL DEFAULT 1,
                created_at DATETIME NOT NULL DEFAULT (current_timestamp),
                updated_at DATETIME NOT NULL DEFAULT (current_timestamp)
            )
            ",
        )
        .await?;
        Ok(())
    }

    async fn insert_legacy_peer(path: &str, device_id: &str, note: Option<&str>) -> ResultType<()> {
        let mut conn = connect(path).await?;
        sqlx::query(
            "
            INSERT INTO peer(guid, id, uuid, pk, note, info)
            VALUES(?, ?, ?, ?, ?, ?)
            ",
        )
        .bind(TEST_GUID)
        .bind(device_id)
        .bind(TEST_UUID)
        .bind(TEST_PK)
        .bind(note)
        .bind("{\"ip\":\"127.0.0.1\"}")
        .execute(&mut conn)
        .await?;
        Ok(())
    }

    async fn insert_invalid_legacy_peer(path: &str) -> ResultType<()> {
        let mut conn = connect(path).await?;
        sqlx::query(
            "
            INSERT INTO peer(guid, id, uuid, pk, note, info)
            VALUES(?, ?, ?, NULL, ?, ?)
            ",
        )
        .bind(TEST_GUID)
        .bind("broken-device")
        .bind(TEST_UUID)
        .bind("bad-note")
        .bind("{\"ip\":\"127.0.0.1\"}")
        .execute(&mut conn)
        .await?;
        Ok(())
    }

    async fn table_exists(db: &Database, table: &str) -> ResultType<bool> {
        let mut conn = db.pool.get().await?;
        raw_table_exists(conn.deref_mut(), table).await
    }

    async fn index_exists(db: &Database, index: &str) -> ResultType<bool> {
        let mut conn = db.pool.get().await?;
        let row = sqlx::query(
            "SELECT COUNT(*) AS count FROM sqlite_master WHERE type='index' AND name=?",
        )
        .bind(index)
        .fetch_one(conn.deref_mut())
        .await?;
        Ok(row.try_get::<i64, _>("count")? > 0)
    }

    async fn column_exists(db: &Database, table: &str, column: &str) -> ResultType<bool> {
        let mut conn = db.pool.get().await?;
        let sql = format!("PRAGMA table_info({})", table);
        let rows = sqlx::query(&sql).fetch_all(conn.deref_mut()).await?;
        Ok(rows
            .iter()
            .any(|row| row.try_get::<String, _>("name").ok().as_deref() == Some(column)))
    }

    async fn raw_table_exists(conn: &mut SqliteConnection, table: &str) -> ResultType<bool> {
        let row = sqlx::query(
            "SELECT COUNT(*) AS count FROM sqlite_master WHERE type='table' AND name=?",
        )
        .bind(table)
        .fetch_one(conn)
        .await?;
        Ok(row.try_get::<i64, _>("count")? > 0)
    }

    async fn count(db: &Database, sql: &str) -> i64 {
        let mut conn = db.pool.get().await.unwrap();
        raw_count(conn.deref_mut(), sql).await.unwrap()
    }

    async fn raw_count(conn: &mut SqliteConnection, sql: &str) -> ResultType<i64> {
        let row = sqlx::query(sql).fetch_one(conn).await?;
        Ok(row.try_get::<i64, _>("count")?)
    }
}
