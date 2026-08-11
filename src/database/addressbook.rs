use super::Database;
use crate::models::{
    addressbook::{
        validate_safe_device_text_fields, AddressBookChangeDto, AddressBookDeltaPage,
        AddressBookFullPage, AddressBookOperation, AddressBookSnapshot, AddressBookSource,
        PendingShareDto, PendingSharePage, SafeDeviceDto, ShareDeviceSummaryDto, ShareDto,
        ShareMutation, SharePermission, ShareStatus, SysinfoDeviceSnapshot, SysinfoUpdateResult,
    },
    user::MAX_SAFE_INTEGER,
};
use hbb_common::{bail, ResultType};
use sqlx::{sqlite::SqliteRow, Connection, Row, Sqlite, Transaction};
use std::{collections::HashMap, fmt, future::Future, ops::DerefMut};

pub type AddressBookResult<T> = Result<T, AddressBookError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressBookError {
    InvalidInput(String),
    Forbidden,
    NotFound,
    Conflict(String),
    TooLarge,
    Busy,
    Integrity(String),
    Internal(String),
}

impl fmt::Display for AddressBookError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(message) => write!(formatter, "地址簿参数非法：{message}"),
            Self::Forbidden => formatter.write_str("无地址簿写权限"),
            Self::NotFound => formatter.write_str("地址簿资源不存在"),
            Self::Conflict(message) => write!(formatter, "地址簿状态冲突：{message}"),
            Self::TooLarge => formatter.write_str("地址簿数值或结果超出安全范围"),
            Self::Busy => formatter.write_str("地址簿数据库繁忙"),
            Self::Integrity(message) => write!(formatter, "地址簿完整性错误：{message}"),
            Self::Internal(message) => write!(formatter, "地址簿数据库错误：{message}"),
        }
    }
}

impl std::error::Error for AddressBookError {}

impl From<sqlx::Error> for AddressBookError {
    fn from(error: sqlx::Error) -> Self {
        if let sqlx::Error::Database(database_error) = &error {
            let message = database_error.message();
            let lower = message.to_ascii_lowercase();
            if matches!(
                database_error.code().as_deref(),
                Some("5") | Some("6") | Some("261") | Some("517")
            ) || lower.contains("database is locked")
                || lower.contains("database table is locked")
                || lower.contains("database is busy")
            {
                return Self::Busy;
            }
            match message {
                "address_book_change_not_contiguous" => return Self::Integrity(message.to_owned()),
                "device_share_owner_mismatch"
                | "user_wire_integer_out_of_range"
                | "address_book_change_immutable" => return Self::Conflict(message.to_owned()),
                _ => {}
            }
            if lower.contains("unique constraint") {
                return Self::Conflict("unique_constraint".to_owned());
            }
            if lower.contains("foreign key constraint") {
                return Self::Conflict("foreign_key_constraint".to_owned());
            }
            if lower.contains("check constraint") {
                return Self::Conflict("check_constraint".to_owned());
            }
        }
        Self::Internal(error.to_string())
    }
}

impl From<serde_json::Error> for AddressBookError {
    fn from(error: serde_json::Error) -> Self {
        Self::Integrity(error.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Membership {
    row_id: i64,
    lifecycle: String,
    item: SafeDeviceDto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActorRole {
    Writer,
    Viewer,
    Unknown,
}

fn pool_error(error: impl fmt::Display) -> AddressBookError {
    AddressBookError::Internal(error.to_string())
}

fn inventory_lock_error(error: super::inventory::InventoryError) -> AddressBookError {
    match error {
        super::inventory::InventoryError::Busy => AddressBookError::Busy,
        other => AddressBookError::Internal(other.to_string()),
    }
}

fn validate_wire_integer(value: i64, allow_zero: bool) -> AddressBookResult<i64> {
    let minimum = if allow_zero { 0 } else { 1 };
    if !(minimum..=MAX_SAFE_INTEGER).contains(&value) {
        return Err(AddressBookError::TooLarge);
    }
    Ok(value)
}

fn validate_username_for_lookup(username: &str) -> AddressBookResult<()> {
    let scalar_count = username.chars().count();
    if !(1..=100).contains(&scalar_count) || username.chars().any(char::is_control) {
        return Err(AddressBookError::InvalidInput(
            "用户名必须为 1..=100 个非控制字符".to_owned(),
        ));
    }
    Ok(())
}

fn validate_device_id(device_id: &str) -> AddressBookResult<()> {
    let scalar_count = device_id.chars().count();
    if !(1..=100).contains(&scalar_count) || device_id.chars().any(char::is_control) {
        return Err(AddressBookError::InvalidInput(
            "设备 ID 必须为 1..=100 个非控制字符".to_owned(),
        ));
    }
    Ok(())
}

fn validate_device_lifecycle(lifecycle: &str) -> AddressBookResult<()> {
    if lifecycle.len() != 32
        || lifecycle
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(AddressBookError::Integrity(
            "设备 lifecycle 非法".to_owned(),
        ));
    }
    Ok(())
}

fn validate_sysinfo_text(value: &str, max_bytes: usize, field: &str) -> AddressBookResult<()> {
    if value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(AddressBookError::InvalidInput(format!(
            "{field} 超长或包含控制字符"
        )));
    }
    Ok(())
}

fn instance_id(management_generation: &str) -> String {
    let mut bytes = b"rustdesk-ab-instance-v1\0".to_vec();
    bytes.extend_from_slice(management_generation.as_bytes());
    let digest = sodiumoxide::crypto::hash::sha256::hash(&bytes);
    data_encoding::HEXLOWER.encode(digest.as_ref())
}

fn safe_device_summary_from_row(
    row: &SqliteRow,
) -> AddressBookResult<(String, ShareDeviceSummaryDto)> {
    let device_id = row.try_get::<String, _>("device_id")?;
    validate_device_id(&device_id)?;
    let lifecycle = row.try_get::<String, _>("device_lifecycle")?;
    validate_device_lifecycle(&lifecycle)?;
    let summary = ShareDeviceSummaryDto {
        device_id,
        instance_id: instance_id(&lifecycle),
        alias: row
            .try_get::<Option<String>, _>("alias")?
            .unwrap_or_default(),
        hostname: row
            .try_get::<Option<String>, _>("hostname")?
            .unwrap_or_default(),
        os: row.try_get::<Option<String>, _>("os")?.unwrap_or_default(),
    };
    validate_safe_device_text_fields(&summary.alias, &summary.hostname, &summary.os)
        .map_err(AddressBookError::Integrity)?;
    Ok((lifecycle, summary))
}

fn membership_from_row(row: &SqliteRow) -> AddressBookResult<Membership> {
    let row_id = validate_wire_integer(row.try_get::<i64, _>("row_id")?, false)?;
    let (lifecycle, device) = safe_device_summary_from_row(row)?;
    let source = match row.try_get::<String, _>("source")?.as_str() {
        "owned" => AddressBookSource::Owned,
        "shared" => AddressBookSource::Shared,
        other => {
            return Err(AddressBookError::Integrity(format!(
                "未知地址簿来源：{other}"
            )))
        }
    };
    let permission = SharePermission::try_from(row.try_get::<String, _>("permission")?.as_str())
        .map_err(AddressBookError::Integrity)?;
    let share_id = row.try_get::<Option<i64>, _>("share_id")?;
    let shared_by_user_id = row.try_get::<Option<i64>, _>("shared_by_user_id")?;
    if let Some(value) = share_id {
        validate_wire_integer(value, false)?;
    }
    if let Some(value) = shared_by_user_id {
        validate_wire_integer(value, false)?;
    }
    let item = SafeDeviceDto {
        device_id: device.device_id,
        instance_id: device.instance_id,
        alias: device.alias,
        hostname: device.hostname,
        os: device.os,
        source,
        permission,
        share_id,
        shared_by_user_id,
        shared_by_username: row.try_get::<Option<String>, _>("shared_by_username")?,
    };
    item.validate_shape().map_err(AddressBookError::Integrity)?;
    Ok(Membership {
        row_id,
        lifecycle,
        item,
    })
}

async fn fetch_user_version_in_tx(
    tx: &mut Transaction<'_, Sqlite>,
    user_id: i64,
) -> AddressBookResult<Option<i64>> {
    let version =
        sqlx::query_scalar::<_, i64>("SELECT address_book_version FROM users WHERE id = ?")
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?;
    version
        .map(|value| validate_wire_integer(value, true))
        .transpose()
}

async fn ensure_writer_in_tx(
    tx: &mut Transaction<'_, Sqlite>,
    user_id: i64,
) -> AddressBookResult<()> {
    let role = sqlx::query("SELECT role, is_active FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
    let Some(role) = role else {
        return Err(AddressBookError::NotFound);
    };
    if !role.try_get::<bool, _>("is_active")? {
        return Err(AddressBookError::NotFound);
    }
    let role = match role.try_get::<String, _>("role")?.as_str() {
        "admin" | "user" => ActorRole::Writer,
        "viewer" => ActorRole::Viewer,
        _ => ActorRole::Unknown,
    };
    match role {
        ActorRole::Writer => Ok(()),
        ActorRole::Viewer | ActorRole::Unknown => Err(AddressBookError::Forbidden),
    }
}

async fn current_membership_in_tx(
    tx: &mut Transaction<'_, Sqlite>,
    user_id: i64,
) -> AddressBookResult<Vec<Membership>> {
    let rows = sqlx::query(
        "SELECT
             d.id AS row_id,
             d.device_id,
             d.management_generation AS device_lifecycle,
             d.alias,
             d.device_name AS hostname,
             d.os,
             'owned' AS source,
             'full_control' AS permission,
             NULL AS share_id,
             NULL AS shared_by_user_id,
             NULL AS shared_by_username
         FROM devices d
         WHERE d.owner_user_id = ?
         UNION ALL
         SELECT
             d.id AS row_id,
             d.device_id,
             d.management_generation AS device_lifecycle,
             d.alias,
             d.device_name AS hostname,
             d.os,
             'shared' AS source,
             s.permission,
             s.id AS share_id,
             s.from_user_id AS shared_by_user_id,
             owner.username AS shared_by_username
         FROM device_shares s
         JOIN devices d
           ON d.id = s.device_row_id
          AND d.management_generation = s.device_lifecycle
          AND d.device_id = s.device_id
         JOIN users owner ON owner.id = s.from_user_id
         WHERE s.to_user_id = ? AND s.status = 'accepted'
         ORDER BY device_id, device_lifecycle",
    )
    .bind(user_id)
    .bind(user_id)
    .fetch_all(&mut *tx)
    .await?;
    rows.iter().map(membership_from_row).collect()
}

async fn membership_for_device_in_tx(
    tx: &mut Transaction<'_, Sqlite>,
    row_id: i64,
) -> AddressBookResult<Vec<(i64, Membership)>> {
    let rows = sqlx::query(
        "SELECT
             d.owner_user_id AS visible_user_id,
             d.id AS row_id,
             d.device_id,
             d.management_generation AS device_lifecycle,
             d.alias,
             d.device_name AS hostname,
             d.os,
             'owned' AS source,
             'full_control' AS permission,
             NULL AS share_id,
             NULL AS shared_by_user_id,
             NULL AS shared_by_username
         FROM devices d
         WHERE d.id = ? AND d.owner_user_id IS NOT NULL
         UNION ALL
         SELECT
             s.to_user_id AS visible_user_id,
             d.id AS row_id,
             d.device_id,
             d.management_generation AS device_lifecycle,
             d.alias,
             d.device_name AS hostname,
             d.os,
             'shared' AS source,
             s.permission,
             s.id AS share_id,
             s.from_user_id AS shared_by_user_id,
             owner.username AS shared_by_username
         FROM device_shares s
         JOIN devices d
           ON d.id = s.device_row_id
          AND d.management_generation = s.device_lifecycle
          AND d.device_id = s.device_id
         JOIN users owner ON owner.id = s.from_user_id
         WHERE d.id = ? AND s.status = 'accepted'
         ORDER BY visible_user_id",
    )
    .bind(row_id)
    .bind(row_id)
    .fetch_all(&mut *tx)
    .await?;
    rows.iter()
        .map(|row| {
            let user_id = validate_wire_integer(row.try_get::<i64, _>("visible_user_id")?, false)?;
            Ok((user_id, membership_from_row(row)?))
        })
        .collect()
}

async fn append_change_in_tx(
    tx: &mut Transaction<'_, Sqlite>,
    user_id: i64,
    membership: &Membership,
    operation: AddressBookOperation,
) -> AddressBookResult<i64> {
    validate_wire_integer(user_id, false)?;
    let next = sqlx::query_scalar::<_, i64>(
        "UPDATE users
         SET address_book_version = address_book_version + 1
         WHERE id = ? AND address_book_version < ?
         RETURNING address_book_version",
    )
    .bind(user_id)
    .bind(MAX_SAFE_INTEGER)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(next) = next else {
        if fetch_user_version_in_tx(tx, user_id).await?.is_none() {
            return Err(AddressBookError::NotFound);
        }
        return Err(AddressBookError::TooLarge);
    };
    let payload = match operation {
        AddressBookOperation::Upsert => Some(serde_json::to_string(&membership.item)?),
        AddressBookOperation::Delete => None,
    };
    sqlx::query(
        "INSERT INTO address_book_changes(
             user_id, version, device_row_id, device_lifecycle,
             device_id, share_id, operation, payload
         ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(next)
    .bind(membership.row_id)
    .bind(&membership.lifecycle)
    .bind(&membership.item.device_id)
    .bind(membership.item.share_id)
    .bind(operation.as_str())
    .bind(payload)
    .execute(&mut *tx)
    .await?;
    Ok(next)
}

pub(super) async fn upsert_device_memberships_in_tx(
    tx: &mut Transaction<'_, Sqlite>,
    row_id: i64,
) -> AddressBookResult<()> {
    for (user_id, membership) in membership_for_device_in_tx(tx, row_id).await? {
        append_change_in_tx(tx, user_id, &membership, AddressBookOperation::Upsert).await?;
    }
    Ok(())
}

pub(super) async fn delete_device_memberships_in_tx(
    tx: &mut Transaction<'_, Sqlite>,
    row_id: i64,
) -> AddressBookResult<()> {
    for (user_id, membership) in membership_for_device_in_tx(tx, row_id).await? {
        append_change_in_tx(tx, user_id, &membership, AddressBookOperation::Delete).await?;
    }
    sqlx::query("DELETE FROM device_shares WHERE device_row_id = ?")
        .bind(row_id)
        .execute(&mut *tx)
        .await?;
    Ok(())
}

pub(super) async fn rename_device_memberships_in_tx(
    tx: &mut Transaction<'_, Sqlite>,
    row_id: i64,
    old_device_id: &str,
) -> AddressBookResult<()> {
    validate_device_id(old_device_id)?;
    let memberships = membership_for_device_in_tx(tx, row_id).await?;
    for (user_id, membership) in memberships {
        let mut old = membership.clone();
        old.item.device_id = old_device_id.to_owned();
        append_change_in_tx(tx, user_id, &old, AddressBookOperation::Delete).await?;
        append_change_in_tx(tx, user_id, &membership, AddressBookOperation::Upsert).await?;
    }
    Ok(())
}

async fn latest_items_at_version_in_tx(
    tx: &mut Transaction<'_, Sqlite>,
    user_id: i64,
    version: i64,
    limit: Option<i64>,
    offset: Option<i64>,
) -> AddressBookResult<Vec<SafeDeviceDto>> {
    let mut sql = String::from(
        "WITH latest AS (
             SELECT device_lifecycle, MAX(version) AS version
             FROM address_book_changes
             WHERE user_id = ? AND version <= ?
             GROUP BY device_lifecycle
         )
         SELECT changes.payload
         FROM latest
         JOIN address_book_changes changes
           ON changes.user_id = ?
          AND changes.device_lifecycle = latest.device_lifecycle
          AND changes.version = latest.version
         WHERE changes.operation = 'upsert'
         ORDER BY changes.device_id, changes.device_lifecycle",
    );
    if limit.is_some() {
        sql.push_str(" LIMIT ? OFFSET ?");
    }
    let mut query = sqlx::query(&sql).bind(user_id).bind(version).bind(user_id);
    if let Some(limit) = limit {
        query = query.bind(limit).bind(offset.unwrap_or(0));
    }
    let rows = query.fetch_all(&mut *tx).await?;
    rows.into_iter()
        .map(|row| {
            let payload = row.try_get::<String, _>("payload")?;
            let item = serde_json::from_str::<SafeDeviceDto>(&payload)?;
            item.validate_shape().map_err(AddressBookError::Integrity)?;
            Ok(item)
        })
        .collect()
}

async fn latest_item_count_at_version_in_tx(
    tx: &mut Transaction<'_, Sqlite>,
    user_id: i64,
    version: i64,
) -> AddressBookResult<i64> {
    let total = sqlx::query_scalar::<_, i64>(
        "WITH latest AS (
             SELECT device_lifecycle, MAX(version) AS version
             FROM address_book_changes
             WHERE user_id = ? AND version <= ?
             GROUP BY device_lifecycle
         )
         SELECT COUNT(*)
         FROM latest
         JOIN address_book_changes changes
           ON changes.user_id = ?
          AND changes.device_lifecycle = latest.device_lifecycle
          AND changes.version = latest.version
         WHERE changes.operation = 'upsert'",
    )
    .bind(user_id)
    .bind(version)
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await?;
    validate_wire_integer(total, true)
}

fn change_from_row(row: &SqliteRow) -> AddressBookResult<AddressBookChangeDto> {
    let version = validate_wire_integer(row.try_get::<i64, _>("version")?, false)?;
    let operation = AddressBookOperation::try_from(row.try_get::<String, _>("operation")?.as_str())
        .map_err(AddressBookError::Integrity)?;
    let device_id = row.try_get::<String, _>("device_id")?;
    validate_device_id(&device_id)?;
    let lifecycle = row.try_get::<String, _>("device_lifecycle")?;
    validate_device_lifecycle(&lifecycle)?;
    let share_id = row.try_get::<Option<i64>, _>("share_id")?;
    if let Some(value) = share_id {
        validate_wire_integer(value, false)?;
    }
    let payload = row.try_get::<Option<String>, _>("payload")?;
    let item = payload
        .as_deref()
        .map(serde_json::from_str::<SafeDeviceDto>)
        .transpose()?;
    match operation {
        AddressBookOperation::Upsert => {
            let Some(item) = item.as_ref() else {
                return Err(AddressBookError::Integrity(
                    "upsert 变化缺少 item".to_owned(),
                ));
            };
            item.validate_shape().map_err(AddressBookError::Integrity)?;
            if item.device_id != device_id
                || item.instance_id != instance_id(&lifecycle)
                || item.share_id != share_id
            {
                return Err(AddressBookError::Integrity(
                    "upsert 顶层身份与 item 不一致".to_owned(),
                ));
            }
        }
        AddressBookOperation::Delete if item.is_some() => {
            return Err(AddressBookError::Integrity(
                "delete 变化不得携带 item".to_owned(),
            ))
        }
        AddressBookOperation::Delete => {}
    }
    Ok(AddressBookChangeDto {
        version,
        operation,
        device_id,
        instance_id: instance_id(&lifecycle),
        share_id,
        item,
    })
}

fn apply_change_to_replay_state(
    state: &mut HashMap<(i64, String), SafeDeviceDto>,
    user_id: i64,
    change: &AddressBookChangeDto,
) -> AddressBookResult<()> {
    validate_wire_integer(user_id, false)?;
    let key = (user_id, change.instance_id.clone());
    match change.operation {
        AddressBookOperation::Upsert => {
            let item = change
                .item
                .as_ref()
                .ok_or_else(|| AddressBookError::Integrity("upsert 变化缺少 item".to_owned()))?;
            if let Some(previous) = state.get(&key) {
                if previous.device_id != item.device_id
                    || previous.source != item.source
                    || previous.share_id != item.share_id
                    || previous.shared_by_user_id != item.shared_by_user_id
                    || previous.shared_by_username != item.shared_by_username
                {
                    return Err(AddressBookError::Integrity(
                        "同一地址簿实例未先 delete 就改变设备或共享身份".to_owned(),
                    ));
                }
            }
            state.insert(key, item.clone());
        }
        AddressBookOperation::Delete => {
            let previous = state.remove(&key).ok_or_else(|| {
                AddressBookError::Integrity("delete 变化缺少可重放前态".to_owned())
            })?;
            if previous.device_id != change.device_id || previous.share_id != change.share_id {
                return Err(AddressBookError::Integrity(
                    "delete 顶层身份与可重放前态不一致".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn share_dto_from_row(row: &SqliteRow) -> AddressBookResult<ShareDto> {
    let id = validate_wire_integer(row.try_get::<i64, _>("id")?, false)?;
    let from_user_id = validate_wire_integer(row.try_get::<i64, _>("from_user_id")?, false)?;
    let to_user_id = validate_wire_integer(row.try_get::<i64, _>("to_user_id")?, false)?;
    let (_, device) = safe_device_summary_from_row(row)?;
    Ok(ShareDto {
        id,
        device,
        from_user_id,
        from_username: row.try_get("from_username")?,
        to_user_id,
        to_username: row.try_get("to_username")?,
        permission: SharePermission::try_from(row.try_get::<String, _>("permission")?.as_str())
            .map_err(AddressBookError::Integrity)?,
        status: ShareStatus::try_from(row.try_get::<String, _>("status")?.as_str())
            .map_err(AddressBookError::Integrity)?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

const SHARE_DTO_SELECT: &str = "
    SELECT
        s.id,
        s.device_lifecycle,
        s.device_id,
        d.alias,
        d.device_name AS hostname,
        d.os,
        s.from_user_id,
        owner.username AS from_username,
        s.to_user_id,
        recipient.username AS to_username,
        s.permission,
        s.status,
        strftime('%Y-%m-%dT%H:%M:%SZ', s.created_at) AS created_at,
        strftime('%Y-%m-%dT%H:%M:%SZ', s.updated_at) AS updated_at
    FROM device_shares s
    JOIN devices d
      ON d.id = s.device_row_id
     AND d.management_generation = s.device_lifecycle
     AND d.device_id = s.device_id
    JOIN users owner ON owner.id = s.from_user_id
    JOIN users recipient ON recipient.id = s.to_user_id
";

async fn fetch_share_dto_in_tx(
    tx: &mut Transaction<'_, Sqlite>,
    share_id: i64,
) -> AddressBookResult<Option<ShareDto>> {
    let row = sqlx::query(&format!("{SHARE_DTO_SELECT} WHERE s.id = ?"))
        .bind(share_id)
        .fetch_optional(&mut *tx)
        .await?;
    row.as_ref().map(share_dto_from_row).transpose()
}

async fn fetch_shared_membership_in_tx(
    tx: &mut Transaction<'_, Sqlite>,
    share_id: i64,
) -> AddressBookResult<Option<(i64, Membership)>> {
    let row = sqlx::query(
        "SELECT
             s.to_user_id AS visible_user_id,
             d.id AS row_id,
             d.device_id,
             d.management_generation AS device_lifecycle,
             d.alias,
             d.device_name AS hostname,
             d.os,
             'shared' AS source,
             s.permission,
             s.id AS share_id,
             s.from_user_id AS shared_by_user_id,
             owner.username AS shared_by_username
         FROM device_shares s
         JOIN devices d
           ON d.id = s.device_row_id
          AND d.management_generation = s.device_lifecycle
          AND d.device_id = s.device_id
         JOIN users owner ON owner.id = s.from_user_id
         WHERE s.id = ?",
    )
    .bind(share_id)
    .fetch_optional(&mut *tx)
    .await?;
    row.as_ref()
        .map(|row| {
            Ok((
                validate_wire_integer(row.try_get::<i64, _>("visible_user_id")?, false)?,
                membership_from_row(row)?,
            ))
        })
        .transpose()
}

impl Database {
    pub async fn get_address_book_version(&self, user_id: i64) -> AddressBookResult<Option<i64>> {
        validate_wire_integer(user_id, false)?;
        let mut connection = self.pool.get().await.map_err(pool_error)?;
        let mut tx = connection.begin().await?;
        let version = fetch_user_version_in_tx(&mut tx, user_id).await?;
        tx.commit().await?;
        Ok(version)
    }

    pub async fn get_address_book_snapshot(
        &self,
        user_id: i64,
    ) -> AddressBookResult<AddressBookSnapshot> {
        validate_wire_integer(user_id, false)?;
        let mut connection = self.pool.get().await.map_err(pool_error)?;
        let mut tx = connection.begin().await?;
        let ab_ver = fetch_user_version_in_tx(&mut tx, user_id)
            .await?
            .ok_or(AddressBookError::NotFound)?;
        let items = current_membership_in_tx(&mut tx, user_id)
            .await?
            .into_iter()
            .map(|membership| membership.item)
            .collect();
        tx.commit().await?;
        Ok(AddressBookSnapshot { ab_ver, items })
    }

    pub async fn get_address_book_full(
        &self,
        user_id: i64,
        page: u64,
        page_size: u64,
        sync_ver: Option<i64>,
    ) -> AddressBookResult<AddressBookFullPage> {
        validate_wire_integer(user_id, false)?;
        if page == 0 || page > MAX_SAFE_INTEGER as u64 || !(1..=200).contains(&page_size) {
            return Err(AddressBookError::InvalidInput(
                "page/page_size 超出范围".to_owned(),
            ));
        }
        let offset = page
            .checked_sub(1)
            .and_then(|value| value.checked_mul(page_size))
            .and_then(|value| i64::try_from(value).ok())
            .ok_or(AddressBookError::TooLarge)?;
        let page_size_i64 = i64::try_from(page_size).map_err(|_| AddressBookError::TooLarge)?;
        let mut connection = self.pool.get().await.map_err(pool_error)?;
        let mut tx = connection.begin().await?;
        let current = fetch_user_version_in_tx(&mut tx, user_id)
            .await?
            .ok_or(AddressBookError::NotFound)?;
        let target = sync_ver.unwrap_or(current);
        if target < 0 || target > current || (page > 1 && sync_ver.is_none()) {
            return Err(AddressBookError::InvalidInput(
                "sync_ver 与分页快照不匹配".to_owned(),
            ));
        }
        let total = latest_item_count_at_version_in_tx(&mut tx, user_id, target).await?;
        let items = latest_items_at_version_in_tx(
            &mut tx,
            user_id,
            target,
            Some(page_size_i64),
            Some(offset),
        )
        .await?;
        let returned = i64::try_from(items.len()).map_err(|_| AddressBookError::TooLarge)?;
        let has_more = offset
            .checked_add(returned)
            .ok_or(AddressBookError::TooLarge)?
            < total;
        tx.commit().await?;
        Ok(AddressBookFullPage {
            mode: "full",
            ab_ver: target,
            items,
            page,
            page_size,
            total,
            has_more,
        })
    }

    pub async fn get_address_book_delta(
        &self,
        user_id: i64,
        ab_ver: i64,
        page_size: i64,
    ) -> AddressBookResult<AddressBookDeltaPage> {
        self.get_address_book_delta_with_reset(user_id, ab_ver, page_size, false)
            .await
    }

    pub(crate) async fn get_address_book_delta_with_reset(
        &self,
        user_id: i64,
        ab_ver: i64,
        page_size: i64,
        force_reset: bool,
    ) -> AddressBookResult<AddressBookDeltaPage> {
        validate_wire_integer(user_id, false)?;
        validate_wire_integer(ab_ver, true)?;
        if !(1..=200).contains(&page_size) {
            return Err(AddressBookError::InvalidInput(
                "page_size 超出范围".to_owned(),
            ));
        }
        let mut connection = self.pool.get().await.map_err(pool_error)?;
        let mut tx = connection.begin().await?;
        let target = fetch_user_version_in_tx(&mut tx, user_id)
            .await?
            .ok_or(AddressBookError::NotFound)?;
        let reset_required = force_reset || ab_ver > target;
        let cursor = if reset_required { 0 } else { ab_ver };
        let rows = sqlx::query(
            "SELECT version, operation, device_id, device_lifecycle, share_id, payload
             FROM address_book_changes
             WHERE user_id = ? AND version > ? AND version <= ?
             ORDER BY version
             LIMIT ?",
        )
        .bind(user_id)
        .bind(cursor)
        .bind(target)
        .bind(page_size)
        .fetch_all(&mut tx)
        .await?;
        let changes = rows
            .iter()
            .map(change_from_row)
            .collect::<AddressBookResult<Vec<_>>>()?;
        let mut expected = cursor.checked_add(1).ok_or(AddressBookError::TooLarge)?;
        for change in &changes {
            if change.version != expected {
                return Err(AddressBookError::Integrity(format!(
                    "用户 {user_id} 的变化日志在版本 {expected} 处存在缺口"
                )));
            }
            expected = expected.checked_add(1).ok_or(AddressBookError::TooLarge)?;
        }
        let next_ab_ver = changes
            .last()
            .map(|change| change.version)
            .unwrap_or(target);
        if changes.is_empty() && cursor < target {
            return Err(AddressBookError::Integrity(format!(
                "用户 {user_id} 的变化日志缺失"
            )));
        }
        let has_more = next_ab_ver < target;
        tx.commit().await?;
        Ok(AddressBookDeltaPage {
            mode: "delta".to_owned(),
            ab_ver: target,
            next_ab_ver,
            changes,
            page_size,
            has_more,
            reset_required,
        })
    }

    pub async fn get_pending_shares(
        &self,
        user_id: i64,
        after_id: i64,
        page_size: i64,
    ) -> AddressBookResult<PendingSharePage> {
        validate_wire_integer(user_id, false)?;
        validate_wire_integer(after_id, true)?;
        if !(1..=200).contains(&page_size) {
            return Err(AddressBookError::InvalidInput(
                "page_size 超出范围".to_owned(),
            ));
        }
        let fetch_limit = page_size.checked_add(1).ok_or(AddressBookError::TooLarge)?;
        let mut connection = self.pool.get().await.map_err(pool_error)?;
        let rows = sqlx::query(
            "SELECT
                 s.id,
                 s.device_lifecycle,
                 s.device_id,
                 d.alias,
                 d.device_name AS hostname,
                 d.os,
                 s.from_user_id,
                 owner.username AS from_username,
                 s.permission,
                 strftime('%Y-%m-%dT%H:%M:%SZ', s.created_at) AS created_at,
                 strftime('%Y-%m-%dT%H:%M:%SZ', s.updated_at) AS updated_at
             FROM device_shares s
             JOIN devices d
               ON d.id = s.device_row_id
              AND d.management_generation = s.device_lifecycle
              AND d.device_id = s.device_id
             JOIN users owner ON owner.id = s.from_user_id
             WHERE s.to_user_id = ? AND s.status = 'pending' AND s.id > ?
             ORDER BY s.id
             LIMIT ?",
        )
        .bind(user_id)
        .bind(after_id)
        .bind(fetch_limit)
        .fetch_all(connection.deref_mut())
        .await?;
        let has_more = rows.len() > page_size as usize;
        let mut items = Vec::with_capacity(rows.len().min(page_size as usize));
        for row in rows.iter().take(page_size as usize) {
            let id = validate_wire_integer(row.try_get::<i64, _>("id")?, false)?;
            let from_user_id =
                validate_wire_integer(row.try_get::<i64, _>("from_user_id")?, false)?;
            let (_, device) = safe_device_summary_from_row(row)?;
            items.push(PendingShareDto {
                id,
                device,
                from_user_id,
                from_username: row.try_get("from_username")?,
                permission: SharePermission::try_from(
                    row.try_get::<String, _>("permission")?.as_str(),
                )
                .map_err(AddressBookError::Integrity)?,
                created_at: row.try_get("created_at")?,
                updated_at: row.try_get("updated_at")?,
            });
        }
        let next_after_id = items.last().map(|item| item.id).unwrap_or(after_id);
        Ok(PendingSharePage {
            items,
            next_after_id,
            page_size,
            has_more,
        })
    }

    pub async fn share_device(
        &self,
        actor_user_id: i64,
        device_id: &str,
        to_username: &str,
        permission: SharePermission,
    ) -> AddressBookResult<ShareMutation> {
        self.share_device_with_before_lock(
            actor_user_id,
            device_id,
            to_username,
            permission,
            || std::future::ready(()),
        )
        .await
    }

    async fn share_device_with_before_lock<F, Fut>(
        &self,
        actor_user_id: i64,
        device_id: &str,
        to_username: &str,
        permission: SharePermission,
        before_lock: F,
    ) -> AddressBookResult<ShareMutation>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = ()>,
    {
        validate_wire_integer(actor_user_id, false)?;
        validate_device_id(device_id)?;
        validate_username_for_lookup(to_username)?;
        let mut connection = self.pool.get().await.map_err(pool_error)?;
        let mut tx = connection.begin().await?;
        before_lock().await;
        super::inventory::lock_inventory(&mut tx)
            .await
            .map_err(inventory_lock_error)?;
        ensure_writer_in_tx(&mut tx, actor_user_id).await?;
        let device = sqlx::query(
            "SELECT id, management_generation, device_id
             FROM devices
             WHERE device_id = ? AND owner_user_id = ?",
        )
        .bind(device_id)
        .bind(actor_user_id)
        .fetch_optional(&mut tx)
        .await?
        .ok_or(AddressBookError::NotFound)?;
        let row_id = device.try_get::<i64, _>("id")?;
        let lifecycle = device.try_get::<String, _>("management_generation")?;
        let target = sqlx::query(
            "SELECT id
             FROM users
             WHERE username = ? AND is_active = 1 AND role IN ('admin', 'user')",
        )
        .bind(to_username)
        .fetch_optional(&mut tx)
        .await?
        .ok_or(AddressBookError::NotFound)?;
        let target_id = validate_wire_integer(target.try_get::<i64, _>("id")?, false)?;
        if target_id == actor_user_id {
            return Err(AddressBookError::InvalidInput("不能共享给自己".to_owned()));
        }
        let existing = sqlx::query(
            "SELECT id, permission, status
             FROM device_shares
             WHERE device_row_id = ? AND to_user_id = ?",
        )
        .bind(row_id)
        .bind(target_id)
        .fetch_optional(&mut tx)
        .await?;
        let (share_id, created, needs_upsert) = if let Some(existing) = existing {
            let existing_id = existing.try_get::<i64, _>("id")?;
            let existing_permission = existing.try_get::<String, _>("permission")?;
            let status = existing.try_get::<String, _>("status")?;
            match status.as_str() {
                "pending" => {
                    if existing_permission != permission.as_str() {
                        sqlx::query(
                            "UPDATE device_shares
                             SET permission = ?, updated_at = current_timestamp
                             WHERE id = ?",
                        )
                        .bind(permission.as_str())
                        .bind(existing_id)
                        .execute(&mut tx)
                        .await?;
                    }
                    (existing_id, false, false)
                }
                "accepted" => {
                    let changed = existing_permission != permission.as_str();
                    if changed {
                        sqlx::query(
                            "UPDATE device_shares
                             SET permission = ?, updated_at = current_timestamp
                             WHERE id = ?",
                        )
                        .bind(permission.as_str())
                        .bind(existing_id)
                        .execute(&mut tx)
                        .await?;
                    }
                    (existing_id, false, changed)
                }
                "rejected" => {
                    sqlx::query("DELETE FROM device_shares WHERE id = ?")
                        .bind(existing_id)
                        .execute(&mut tx)
                        .await?;
                    let id = sqlx::query_scalar::<_, i64>(
                        "INSERT INTO device_shares(
                             device_row_id, device_lifecycle, device_id,
                             from_user_id, to_user_id, permission, status
                         ) VALUES(?, ?, ?, ?, ?, ?, 'pending')
                         RETURNING id",
                    )
                    .bind(row_id)
                    .bind(&lifecycle)
                    .bind(device_id)
                    .bind(actor_user_id)
                    .bind(target_id)
                    .bind(permission.as_str())
                    .fetch_one(&mut tx)
                    .await?;
                    (id, true, false)
                }
                other => {
                    return Err(AddressBookError::Integrity(format!(
                        "未知共享状态：{other}"
                    )))
                }
            }
        } else {
            let id = sqlx::query_scalar::<_, i64>(
                "INSERT INTO device_shares(
                     device_row_id, device_lifecycle, device_id,
                     from_user_id, to_user_id, permission, status
                 ) VALUES(?, ?, ?, ?, ?, ?, 'pending')
                 RETURNING id",
            )
            .bind(row_id)
            .bind(&lifecycle)
            .bind(device_id)
            .bind(actor_user_id)
            .bind(target_id)
            .bind(permission.as_str())
            .fetch_one(&mut tx)
            .await?;
            (id, true, false)
        };
        validate_wire_integer(share_id, false)?;
        if needs_upsert {
            let (recipient, membership) = fetch_shared_membership_in_tx(&mut tx, share_id)
                .await?
                .ok_or_else(|| {
                AddressBookError::Integrity("accepted 共享在权限更新后消失".to_owned())
            })?;
            append_change_in_tx(
                &mut tx,
                recipient,
                &membership,
                AddressBookOperation::Upsert,
            )
            .await?;
        }
        let share = fetch_share_dto_in_tx(&mut tx, share_id)
            .await?
            .ok_or_else(|| AddressBookError::Integrity("共享创建后消失".to_owned()))?;
        tx.commit().await?;
        Ok(ShareMutation { created, share })
    }

    pub async fn cancel_device_share(
        &self,
        actor_user_id: i64,
        device_id: &str,
        to_username: &str,
    ) -> AddressBookResult<()> {
        validate_wire_integer(actor_user_id, false)?;
        validate_device_id(device_id)?;
        validate_username_for_lookup(to_username)?;
        let mut connection = self.pool.get().await.map_err(pool_error)?;
        let mut tx = connection.begin().await?;
        super::inventory::lock_inventory(&mut tx)
            .await
            .map_err(inventory_lock_error)?;
        ensure_writer_in_tx(&mut tx, actor_user_id).await?;
        let device_row_id = sqlx::query_scalar::<_, i64>(
            "SELECT id FROM devices WHERE device_id = ? AND owner_user_id = ?",
        )
        .bind(device_id)
        .bind(actor_user_id)
        .fetch_optional(&mut tx)
        .await?
        .ok_or(AddressBookError::NotFound)?;
        let target_id = sqlx::query_scalar::<_, i64>("SELECT id FROM users WHERE username = ?")
            .bind(to_username)
            .fetch_optional(&mut tx)
            .await?;
        let Some(target_id) = target_id else {
            tx.commit().await?;
            return Ok(());
        };
        let share = sqlx::query(
            "SELECT id, status
             FROM device_shares
             WHERE device_row_id = ? AND to_user_id = ?",
        )
        .bind(device_row_id)
        .bind(target_id)
        .fetch_optional(&mut tx)
        .await?;
        let Some(share) = share else {
            tx.commit().await?;
            return Ok(());
        };
        let share_id = share.try_get::<i64, _>("id")?;
        if share.try_get::<String, _>("status")? == "accepted" {
            let (recipient, membership) = fetch_shared_membership_in_tx(&mut tx, share_id)
                .await?
                .ok_or_else(|| {
                AddressBookError::Integrity("accepted 共享在取消前缺少 membership".to_owned())
            })?;
            append_change_in_tx(
                &mut tx,
                recipient,
                &membership,
                AddressBookOperation::Delete,
            )
            .await?;
        }
        sqlx::query("DELETE FROM device_shares WHERE id = ?")
            .bind(share_id)
            .execute(&mut tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn accept_device_share(
        &self,
        actor_user_id: i64,
        share_id: i64,
    ) -> AddressBookResult<ShareDto> {
        self.resolve_share_invitation(actor_user_id, share_id, true)
            .await
    }

    pub async fn reject_device_share(
        &self,
        actor_user_id: i64,
        share_id: i64,
    ) -> AddressBookResult<ShareDto> {
        self.resolve_share_invitation(actor_user_id, share_id, false)
            .await
    }

    async fn resolve_share_invitation(
        &self,
        actor_user_id: i64,
        share_id: i64,
        accept: bool,
    ) -> AddressBookResult<ShareDto> {
        self.resolve_share_invitation_with_before_lock(actor_user_id, share_id, accept, || {
            std::future::ready(())
        })
        .await
    }

    async fn resolve_share_invitation_with_before_lock<F, Fut>(
        &self,
        actor_user_id: i64,
        share_id: i64,
        accept: bool,
        before_lock: F,
    ) -> AddressBookResult<ShareDto>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = ()>,
    {
        validate_wire_integer(actor_user_id, false)?;
        validate_wire_integer(share_id, false)?;
        let mut connection = self.pool.get().await.map_err(pool_error)?;
        let mut tx = connection.begin().await?;
        before_lock().await;
        super::inventory::lock_inventory(&mut tx)
            .await
            .map_err(inventory_lock_error)?;
        ensure_writer_in_tx(&mut tx, actor_user_id).await?;
        let state = sqlx::query("SELECT status FROM device_shares WHERE id = ? AND to_user_id = ?")
            .bind(share_id)
            .bind(actor_user_id)
            .fetch_optional(&mut tx)
            .await?
            .ok_or(AddressBookError::NotFound)?
            .try_get::<String, _>("status")?;
        match (accept, state.as_str()) {
            (true, "pending") => {
                sqlx::query(
                    "UPDATE device_shares
                     SET status = 'accepted', updated_at = current_timestamp
                     WHERE id = ?",
                )
                .bind(share_id)
                .execute(&mut tx)
                .await?;
                let (recipient, membership) = fetch_shared_membership_in_tx(&mut tx, share_id)
                    .await?
                    .ok_or_else(|| {
                        AddressBookError::Integrity("accepted 共享缺少 membership".to_owned())
                    })?;
                append_change_in_tx(
                    &mut tx,
                    recipient,
                    &membership,
                    AddressBookOperation::Upsert,
                )
                .await?;
            }
            (true, "accepted") => {}
            (true, "rejected") => {
                return Err(AddressBookError::Conflict(
                    "rejected_share_cannot_be_accepted".to_owned(),
                ))
            }
            (false, "pending") => {
                sqlx::query(
                    "UPDATE device_shares
                     SET status = 'rejected', updated_at = current_timestamp
                     WHERE id = ?",
                )
                .bind(share_id)
                .execute(&mut tx)
                .await?;
            }
            (false, "accepted") => {
                let (recipient, membership) = fetch_shared_membership_in_tx(&mut tx, share_id)
                    .await?
                    .ok_or_else(|| {
                        AddressBookError::Integrity("accepted 共享缺少 membership".to_owned())
                    })?;
                append_change_in_tx(
                    &mut tx,
                    recipient,
                    &membership,
                    AddressBookOperation::Delete,
                )
                .await?;
                sqlx::query(
                    "UPDATE device_shares
                     SET status = 'rejected', updated_at = current_timestamp
                     WHERE id = ?",
                )
                .bind(share_id)
                .execute(&mut tx)
                .await?;
            }
            (false, "rejected") => {}
            (_, other) => {
                return Err(AddressBookError::Integrity(format!(
                    "未知共享状态：{other}"
                )))
            }
        }
        let share = fetch_share_dto_in_tx(&mut tx, share_id)
            .await?
            .ok_or_else(|| AddressBookError::Integrity("共享状态更新后消失".to_owned()))?;
        tx.commit().await?;
        Ok(share)
    }

    pub async fn match_sysinfo_device(
        &self,
        device_id: &str,
        uuid: &[u8],
    ) -> AddressBookResult<Option<SysinfoDeviceSnapshot>> {
        validate_device_id(device_id)?;
        let mut connection = self.pool.get().await.map_err(pool_error)?;
        let row = sqlx::query(
            "SELECT management_generation, owner_user_id
             FROM devices
             WHERE device_id = ? AND uuid = ?",
        )
        .bind(device_id)
        .bind(uuid)
        .fetch_optional(connection.deref_mut())
        .await?;
        row.map(|row| {
            Ok(SysinfoDeviceSnapshot {
                management_generation: row.try_get("management_generation")?,
                owner_user_id: row.try_get("owner_user_id")?,
            })
        })
        .transpose()
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_owned_device_sysinfo(
        &self,
        actor_user_id: i64,
        device_id: &str,
        uuid: &[u8],
        expected_generation: &str,
        hostname: Option<&str>,
        os: Option<&str>,
    ) -> AddressBookResult<SysinfoUpdateResult> {
        self.update_owned_device_sysinfo_with_before_lock(
            actor_user_id,
            device_id,
            uuid,
            expected_generation,
            hostname,
            os,
            || std::future::ready(()),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn update_owned_device_sysinfo_with_before_lock<F, Fut>(
        &self,
        actor_user_id: i64,
        device_id: &str,
        uuid: &[u8],
        expected_generation: &str,
        hostname: Option<&str>,
        os: Option<&str>,
        before_lock: F,
    ) -> AddressBookResult<SysinfoUpdateResult>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = ()>,
    {
        validate_wire_integer(actor_user_id, false)?;
        validate_device_id(device_id)?;
        if let Some(hostname) = hostname {
            validate_sysinfo_text(hostname, 200, "hostname")?;
        }
        if let Some(os) = os {
            validate_sysinfo_text(os, 100, "os")?;
        }
        let mut connection = self.pool.get().await.map_err(pool_error)?;
        let mut tx = connection.begin().await?;
        before_lock().await;
        super::inventory::lock_inventory(&mut tx)
            .await
            .map_err(inventory_lock_error)?;
        let before_version = fetch_user_version_in_tx(&mut tx, actor_user_id)
            .await?
            .ok_or(AddressBookError::NotFound)?;
        let row = sqlx::query(
            "SELECT id, owner_user_id, device_name, os
             FROM devices
             WHERE device_id = ? AND uuid = ? AND management_generation = ?",
        )
        .bind(device_id)
        .bind(uuid)
        .bind(expected_generation)
        .fetch_optional(&mut tx)
        .await?;
        let Some(row) = row else {
            tx.commit().await?;
            return Ok(SysinfoUpdateResult {
                matched: false,
                is_owner: false,
                changed: false,
                previous_address_book_version: before_version,
                address_book_version: before_version,
            });
        };
        let is_owner = row.try_get::<Option<i64>, _>("owner_user_id")? == Some(actor_user_id);
        if !is_owner {
            tx.commit().await?;
            return Ok(SysinfoUpdateResult {
                matched: true,
                is_owner: false,
                changed: false,
                previous_address_book_version: before_version,
                address_book_version: before_version,
            });
        }
        let stored_hostname = row
            .try_get::<Option<String>, _>("device_name")?
            .unwrap_or_default();
        let stored_os = row.try_get::<Option<String>, _>("os")?.unwrap_or_default();
        let changed = hostname.is_some_and(|value| stored_hostname != value)
            || os.is_some_and(|value| stored_os != value);
        let row_id = row.try_get::<i64, _>("id")?;
        if changed {
            sqlx::query(
                "UPDATE devices
                 SET device_name = CASE WHEN ? IS NULL THEN device_name ELSE ? END,
                     os = CASE WHEN ? IS NULL THEN os ELSE ? END,
                     updated_at = current_timestamp
                 WHERE id = ?",
            )
            .bind(hostname)
            .bind(hostname)
            .bind(os)
            .bind(os)
            .bind(row_id)
            .execute(&mut tx)
            .await?;
            upsert_device_memberships_in_tx(&mut tx, row_id).await?;
        }
        let address_book_version = fetch_user_version_in_tx(&mut tx, actor_user_id)
            .await?
            .ok_or(AddressBookError::NotFound)?;
        tx.commit().await?;
        Ok(SysinfoUpdateResult {
            matched: true,
            is_owner: true,
            changed,
            previous_address_book_version: before_version,
            address_book_version,
        })
    }
}

pub(super) async fn initialize_address_book(tx: &mut Transaction<'_, Sqlite>) -> ResultType<()> {
    let completed = sqlx::query_scalar::<_, i64>(
        "SELECT completed FROM address_book_backfill_state WHERE id = 1",
    )
    .fetch_one(&mut *tx)
    .await?;
    if completed == 0 {
        let dirty = sqlx::query_scalar::<_, i64>(
            "SELECT
                 (SELECT COUNT(*) FROM address_book_changes)
               + (SELECT COUNT(*) FROM users WHERE address_book_version <> 0)",
        )
        .fetch_one(&mut *tx)
        .await?;
        if dirty != 0 {
            bail!("address-book backfill marker is incomplete but data already exists");
        }
        let rows = sqlx::query(
            "SELECT
                 d.owner_user_id AS visible_user_id,
                 d.id AS row_id,
                 d.device_id,
                 d.management_generation AS device_lifecycle,
                 d.alias,
                 d.device_name AS hostname,
                 d.os,
                 'owned' AS source,
                 'full_control' AS permission,
                 NULL AS share_id,
                 NULL AS shared_by_user_id,
                 NULL AS shared_by_username
             FROM devices d
             WHERE d.owner_user_id IS NOT NULL
             ORDER BY d.owner_user_id, d.id",
        )
        .fetch_all(&mut *tx)
        .await?;
        for row in &rows {
            let user_id = row.try_get::<i64, _>("visible_user_id")?;
            let membership = membership_from_row(row)
                .map_err(|error| hbb_common::anyhow::anyhow!(error.to_string()))?;
            append_change_in_tx(tx, user_id, &membership, AddressBookOperation::Upsert)
                .await
                .map_err(|error| hbb_common::anyhow::anyhow!(error.to_string()))?;
        }
        sqlx::query("UPDATE address_book_backfill_state SET completed = 1 WHERE id = 1")
            .execute(&mut *tx)
            .await?;
    } else if completed != 1 {
        bail!("address-book backfill marker is invalid");
    }
    verify_address_book_integrity(tx).await
}

pub(super) async fn verify_address_book_integrity(
    tx: &mut Transaction<'_, Sqlite>,
) -> ResultType<()> {
    if let Some(row) = sqlx::query(
        "SELECT id, username, token_version, address_book_version
         FROM users
         WHERE typeof(id) <> 'integer'
            OR id NOT BETWEEN 1 AND 9007199254740991
            OR typeof(token_version) <> 'integer'
            OR token_version NOT BETWEEN 0 AND 9007199254740991
            OR typeof(address_book_version) <> 'integer'
            OR address_book_version NOT BETWEEN 0 AND 9007199254740991
            OR length(username) NOT BETWEEN 1 AND 100
         LIMIT 1",
    )
    .fetch_optional(&mut *tx)
    .await?
    {
        bail!(
            "address-book integrity error: user {} has invalid wire fields",
            row.try_get::<i64, _>("id")?
        );
    }
    let usernames = sqlx::query("SELECT id, username FROM users ORDER BY id")
        .fetch_all(&mut *tx)
        .await?;
    for row in usernames {
        let username = row.try_get::<String, _>("username")?;
        if username.chars().any(char::is_control) {
            bail!(
                "address-book integrity error: user {} has a control character in username",
                row.try_get::<i64, _>("id")?
            );
        }
    }
    if let Some(row) = sqlx::query(
        "SELECT id
         FROM devices
         WHERE typeof(id) <> 'integer'
            OR id NOT BETWEEN 1 AND 9007199254740991
            OR length(device_id) NOT BETWEEN 1 AND 100
            OR management_generation IS NULL
            OR length(management_generation) <> 32
            OR management_generation <> lower(management_generation)
            OR management_generation GLOB '*[^0-9a-f]*'
         LIMIT 1",
    )
    .fetch_optional(&mut *tx)
    .await?
    {
        bail!(
            "address-book integrity error: device {} has invalid identity",
            row.try_get::<i64, _>("id")?
        );
    }
    if let Some(row) = sqlx::query(
        "SELECT s.id
         FROM device_shares s
         LEFT JOIN devices d
           ON d.id = s.device_row_id
          AND d.management_generation = s.device_lifecycle
          AND d.device_id = s.device_id
         WHERE typeof(s.id) <> 'integer'
            OR s.id NOT BETWEEN 1 AND 9007199254740991
            OR d.id IS NULL
            OR d.owner_user_id IS NULL
            OR d.owner_user_id <> s.from_user_id
            OR s.from_user_id = s.to_user_id
            OR s.permission NOT IN ('view_only', 'full_control')
            OR s.status NOT IN ('pending', 'accepted', 'rejected')
         LIMIT 1",
    )
    .fetch_optional(&mut *tx)
    .await?
    {
        bail!(
            "address-book integrity error: share {} is inconsistent",
            row.try_get::<i64, _>("id")?
        );
    }
    if let Some(row) = sqlx::query(
        "SELECT u.id
         FROM users u
         LEFT JOIN (
             SELECT user_id, MIN(version) AS min_version,
                    MAX(version) AS max_version, COUNT(*) AS change_count
             FROM address_book_changes
             GROUP BY user_id
         ) log ON log.user_id = u.id
         WHERE (log.user_id IS NULL AND u.address_book_version <> 0)
            OR (log.user_id IS NOT NULL AND (
                   log.min_version <> 1
                OR log.max_version <> u.address_book_version
                OR log.change_count <> log.max_version
            ))
         LIMIT 1",
    )
    .fetch_optional(&mut *tx)
    .await?
    {
        bail!(
            "address-book integrity error: user {} has a non-contiguous change log",
            row.try_get::<i64, _>("id")?
        );
    }
    let change_rows = sqlx::query(
        "SELECT user_id, version, operation, device_id, device_lifecycle, share_id, payload
         FROM address_book_changes
         ORDER BY user_id, version",
    )
    .fetch_all(&mut *tx)
    .await?;
    let mut replay_state = HashMap::new();
    for row in &change_rows {
        let user_id = row.try_get::<i64, _>("user_id")?;
        let change =
            change_from_row(row).map_err(|error| hbb_common::anyhow::anyhow!(error.to_string()))?;
        apply_change_to_replay_state(&mut replay_state, user_id, &change)
            .map_err(|error| hbb_common::anyhow::anyhow!(error.to_string()))?;
    }
    let users = sqlx::query("SELECT id, address_book_version FROM users ORDER BY id")
        .fetch_all(&mut *tx)
        .await?;
    for row in users {
        let user_id = row.try_get::<i64, _>("id")?;
        let version = row.try_get::<i64, _>("address_book_version")?;
        let current = current_membership_in_tx(tx, user_id)
            .await
            .map_err(|error| hbb_common::anyhow::anyhow!(error.to_string()))?
            .into_iter()
            .map(|membership| membership.item)
            .collect::<Vec<_>>();
        let replay = latest_items_at_version_in_tx(tx, user_id, version, None, None)
            .await
            .map_err(|error| hbb_common::anyhow::anyhow!(error.to_string()))?;
        if current != replay {
            bail!(
                "address-book integrity error: user {} current membership differs from replay",
                user_id
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hbb_common::tokio;
    use std::{
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn inventory_busy_error_remains_retryable() {
        assert_eq!(
            inventory_lock_error(super::super::inventory::InventoryError::Busy),
            AddressBookError::Busy
        );
    }

    #[test]
    fn replay_rejects_delete_with_identity_different_from_previous_upsert() {
        let lifecycle = "a".repeat(32);
        let item = SafeDeviceDto {
            device_id: "device".to_owned(),
            instance_id: instance_id(&lifecycle),
            alias: String::new(),
            hostname: String::new(),
            os: String::new(),
            source: AddressBookSource::Owned,
            permission: SharePermission::FullControl,
            share_id: None,
            shared_by_user_id: None,
            shared_by_username: None,
        };
        let upsert = AddressBookChangeDto {
            version: 1,
            operation: AddressBookOperation::Upsert,
            device_id: item.device_id.clone(),
            instance_id: item.instance_id.clone(),
            share_id: None,
            item: Some(item),
        };
        let invalid_delete = AddressBookChangeDto {
            version: 2,
            operation: AddressBookOperation::Delete,
            device_id: "device".to_owned(),
            instance_id: instance_id(&lifecycle),
            share_id: Some(42),
            item: None,
        };
        let mut state = HashMap::new();
        apply_change_to_replay_state(&mut state, 1, &upsert).unwrap();
        assert!(apply_change_to_replay_state(&mut state, 1, &invalid_delete).is_err());
    }

    #[test]
    fn replay_requires_delete_before_device_id_change() {
        let lifecycle = "c".repeat(32);
        let first = SafeDeviceDto {
            device_id: "old-device".to_owned(),
            instance_id: instance_id(&lifecycle),
            alias: String::new(),
            hostname: String::new(),
            os: String::new(),
            source: AddressBookSource::Owned,
            permission: SharePermission::FullControl,
            share_id: None,
            shared_by_user_id: None,
            shared_by_username: None,
        };
        let mut renamed = first.clone();
        renamed.device_id = "new-device".to_owned();
        let mut state = HashMap::new();
        apply_change_to_replay_state(
            &mut state,
            1,
            &AddressBookChangeDto {
                version: 1,
                operation: AddressBookOperation::Upsert,
                device_id: first.device_id.clone(),
                instance_id: first.instance_id.clone(),
                share_id: None,
                item: Some(first),
            },
        )
        .unwrap();
        assert!(apply_change_to_replay_state(
            &mut state,
            1,
            &AddressBookChangeDto {
                version: 2,
                operation: AddressBookOperation::Upsert,
                device_id: renamed.device_id.clone(),
                instance_id: renamed.instance_id.clone(),
                share_id: None,
                item: Some(renamed),
            },
        )
        .is_err());
    }

    #[test]
    fn safe_device_rejects_out_of_range_historical_shared_user() {
        let item = SafeDeviceDto {
            device_id: "device".to_owned(),
            instance_id: instance_id(&"b".repeat(32)),
            alias: String::new(),
            hostname: String::new(),
            os: String::new(),
            source: AddressBookSource::Shared,
            permission: SharePermission::ViewOnly,
            share_id: Some(1),
            shared_by_user_id: Some(MAX_SAFE_INTEGER + 1),
            shared_by_username: Some("owner".to_owned()),
        };
        assert!(item.validate_shape().is_err());
    }

    #[test]
    fn empty_sysinfo_does_not_turn_nulls_into_a_new_version() {
        run(async {
            let path = temp_db_path("sysinfo-null-normalization");
            let db = Database::new(&path).await.unwrap();
            let owner = user(&db, "owner", "user").await;
            device(&db, "device-null", owner).await;
            let before = db.get_address_book_version(owner).await.unwrap().unwrap();
            let snapshot = db
                .match_sysinfo_device("device-null", b"uuid")
                .await
                .unwrap()
                .unwrap();

            let result = db
                .update_owned_device_sysinfo(
                    owner,
                    "device-null",
                    b"uuid",
                    &snapshot.management_generation,
                    Some(""),
                    Some(""),
                )
                .await
                .unwrap();

            assert!(!result.changed);
            assert_eq!(result.previous_address_book_version, before);
            assert_eq!(result.address_book_version, before);
            assert_eq!(
                db.get_address_book_version(owner).await.unwrap(),
                Some(before)
            );
            drop(db);
            let _ = std::fs::remove_file(path);
        });
    }

    #[test]
    fn sysinfo_supports_independent_hostname_and_os_updates() {
        run(async {
            let path = temp_db_path("sysinfo-partial-update");
            let db = Database::new(&path).await.unwrap();
            let owner = user(&db, "owner", "user").await;
            device(&db, "device-partial", owner).await;
            let snapshot = db
                .match_sysinfo_device("device-partial", b"uuid")
                .await
                .unwrap()
                .unwrap();
            let before = db.get_address_book_version(owner).await.unwrap().unwrap();

            let hostname_update = db
                .update_owned_device_sysinfo(
                    owner,
                    "device-partial",
                    b"uuid",
                    &snapshot.management_generation,
                    Some("host-a"),
                    None,
                )
                .await
                .unwrap();
            assert!(hostname_update.changed);
            assert_eq!(hostname_update.previous_address_book_version, before);
            assert_eq!(hostname_update.address_book_version, before + 1);
            let after_hostname = db.get_address_book_snapshot(owner).await.unwrap();
            assert_eq!(after_hostname.items[0].hostname, "host-a");
            assert_eq!(after_hostname.items[0].os, "");

            let os_update = db
                .update_owned_device_sysinfo(
                    owner,
                    "device-partial",
                    b"uuid",
                    &snapshot.management_generation,
                    None,
                    Some("Linux"),
                )
                .await
                .unwrap();
            assert!(os_update.changed);
            assert_eq!(
                os_update.previous_address_book_version,
                hostname_update.address_book_version
            );
            assert_eq!(
                os_update.address_book_version,
                hostname_update.address_book_version + 1
            );
            let after_os = db.get_address_book_snapshot(owner).await.unwrap();
            assert_eq!(after_os.items[0].hostname, "host-a");
            assert_eq!(after_os.items[0].os, "Linux");

            let no_change = db
                .update_owned_device_sysinfo(
                    owner,
                    "device-partial",
                    b"uuid",
                    &snapshot.management_generation,
                    Some("host-a"),
                    None,
                )
                .await
                .unwrap();
            assert!(!no_change.changed);
            assert_eq!(
                no_change.previous_address_book_version,
                os_update.address_book_version
            );
            assert_eq!(
                no_change.address_book_version,
                os_update.address_book_version
            );
            drop(db);
            let _ = std::fs::remove_file(path);
        });
    }

    fn run<F>(future: F)
    where
        F: std::future::Future<Output = ()>,
    {
        tokio::runtime::Runtime::new().unwrap().block_on(future);
    }

    fn temp_db_path(name: &str) -> String {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir()
            .join(format!("hbbs-address-book-{name}-{nonce}.sqlite"))
            .to_string_lossy()
            .into_owned()
    }

    async fn user(db: &Database, username: &str, role: &str) -> i64 {
        db.create_user(username, "test-password-hash", None, role)
            .await
            .unwrap()
            .id
    }

    async fn device(db: &Database, device_id: &str, owner_user_id: i64) {
        db.insert_peer(device_id, b"uuid", b"pk", "{}")
            .await
            .unwrap();
        db.update_managed_device(
            super::super::OwnerScope::All,
            device_id,
            &super::super::DeviceUpdate {
                owner_user_id: Some(Some(owner_user_id)),
                alias: Some(Some(format!("{device_id}-alias"))),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    }

    async fn delete_device_in_tx(tx: &mut Transaction<'_, Sqlite>, device_id: &str) -> i64 {
        let row_id = sqlx::query_scalar::<_, i64>("SELECT id FROM devices WHERE device_id = ?")
            .bind(device_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        delete_device_memberships_in_tx(tx, row_id).await.unwrap();
        assert_eq!(
            sqlx::query("DELETE FROM devices WHERE id = ?")
                .bind(row_id)
                .execute(&mut *tx)
                .await
                .unwrap()
                .rows_affected(),
            1
        );
        row_id
    }

    async fn transfer_device_in_tx(
        tx: &mut Transaction<'_, Sqlite>,
        device_id: &str,
        new_owner: i64,
    ) -> i64 {
        let row_id = sqlx::query_scalar::<_, i64>("SELECT id FROM devices WHERE device_id = ?")
            .bind(device_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        delete_device_memberships_in_tx(tx, row_id).await.unwrap();
        assert_eq!(
            sqlx::query(
                "UPDATE devices
                 SET owner_user_id = ?, updated_at = current_timestamp
                 WHERE id = ?",
            )
            .bind(new_owner)
            .bind(row_id)
            .execute(&mut *tx)
            .await
            .unwrap()
            .rows_affected(),
            1
        );
        upsert_device_memberships_in_tx(tx, row_id).await.unwrap();
        row_id
    }

    fn cleanup(path: &str) {
        for suffix in ["", "-shm", "-wal", ".migration.lock"] {
            let _ = std::fs::remove_file(format!("{path}{suffix}"));
        }
    }

    #[test]
    fn startup_rejects_out_of_range_pending_and_rejected_share_ids() {
        run(async {
            for status in ["pending", "rejected"] {
                let path = temp_db_path(&format!("share-id-{status}"));
                let db = Database::new(&path).await.unwrap();
                let owner = user(&db, "owner", "user").await;
                let recipient = user(&db, "recipient", "user").await;
                device(&db, "device-1", owner).await;
                let share = db
                    .share_device(owner, "device-1", "recipient", SharePermission::ViewOnly)
                    .await
                    .unwrap();
                if status == "rejected" {
                    db.reject_device_share(recipient, share.share.id)
                        .await
                        .unwrap();
                }
                let mut connection = db.pool.get().await.unwrap();
                sqlx::query("PRAGMA ignore_check_constraints = ON")
                    .execute(connection.deref_mut())
                    .await
                    .unwrap();
                sqlx::query("UPDATE device_shares SET id = ? WHERE id = ?")
                    .bind(MAX_SAFE_INTEGER + 1)
                    .bind(share.share.id)
                    .execute(connection.deref_mut())
                    .await
                    .unwrap();
                drop(connection);
                drop(db);

                let error = Database::new(&path).await.err().unwrap();
                assert!(
                    error.to_string().contains("share")
                        && error.to_string().contains("inconsistent"),
                    "{status}: {error:#}"
                );
                let _ = std::fs::remove_file(path);
            }
        });
    }

    #[test]
    fn share_accept_delta_and_reject_are_contiguous() {
        run(async {
            let path = temp_db_path("share-state");
            let db = Database::new(&path).await.unwrap();
            let owner = user(&db, "owner", "user").await;
            let recipient = user(&db, "recipient", "user").await;
            device(&db, "device-1", owner).await;

            let created = db
                .share_device(owner, "device-1", "recipient", SharePermission::ViewOnly)
                .await
                .unwrap();
            assert!(created.created);
            assert_eq!(
                db.get_address_book_version(recipient).await.unwrap(),
                Some(0)
            );

            db.accept_device_share(recipient, created.share.id)
                .await
                .unwrap();
            let delta = db.get_address_book_delta(recipient, 0, 50).await.unwrap();
            assert_eq!(delta.next_ab_ver, 1);
            assert_eq!(delta.changes[0].operation, AddressBookOperation::Upsert);

            db.reject_device_share(recipient, created.share.id)
                .await
                .unwrap();
            let delta = db.get_address_book_delta(recipient, 1, 50).await.unwrap();
            assert_eq!(delta.next_ab_ver, 2);
            assert_eq!(delta.changes[0].operation, AddressBookOperation::Delete);
            drop(db);
            let _ = std::fs::remove_file(path);
        });
    }

    #[test]
    fn null_device_text_is_normalized_consistently_across_all_address_book_views() {
        run(async {
            let path = temp_db_path("null-safe-device");
            let db = Database::new(&path).await.unwrap();
            let owner = user(&db, "owner", "user").await;
            let recipient = user(&db, "recipient", "user").await;
            db.insert_peer("null-device", b"uuid", b"pk", "{}")
                .await
                .unwrap();
            db.update_managed_device(
                super::super::OwnerScope::All,
                "null-device",
                &super::super::DeviceUpdate {
                    owner_user_id: Some(Some(owner)),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

            let owned = db.get_address_book_snapshot(owner).await.unwrap();
            assert_eq!(
                (
                    owned.items[0].alias.as_str(),
                    owned.items[0].hostname.as_str(),
                    owned.items[0].os.as_str()
                ),
                ("", "", "")
            );

            let created = db
                .share_device(owner, "null-device", "recipient", SharePermission::ViewOnly)
                .await
                .unwrap();
            assert_eq!(
                (
                    created.share.device.alias.as_str(),
                    created.share.device.hostname.as_str(),
                    created.share.device.os.as_str()
                ),
                ("", "", "")
            );
            let pending = db.get_pending_shares(recipient, 0, 50).await.unwrap();
            assert_eq!(
                (
                    pending.items[0].device.alias.as_str(),
                    pending.items[0].device.hostname.as_str(),
                    pending.items[0].device.os.as_str()
                ),
                ("", "", "")
            );

            let accepted = db
                .accept_device_share(recipient, created.share.id)
                .await
                .unwrap();
            assert_eq!(
                (
                    accepted.device.alias.as_str(),
                    accepted.device.hostname.as_str(),
                    accepted.device.os.as_str()
                ),
                ("", "", "")
            );
            let delta = db.get_address_book_delta(recipient, 0, 50).await.unwrap();
            let shared = delta.changes[0].item.as_ref().unwrap();
            assert_eq!(
                (
                    shared.alias.as_str(),
                    shared.hostname.as_str(),
                    shared.os.as_str()
                ),
                ("", "", "")
            );
            drop(db);
            let _ = std::fs::remove_file(path);
        });
    }

    #[test]
    fn full_snapshot_pages_remain_stable_across_concurrent_add_update_and_delete() {
        run(async {
            let path = temp_db_path("full-snapshot");
            let db = Database::new(&path).await.unwrap();
            let owner = user(&db, "owner", "user").await;
            for device_id in ["device-c", "device-a", "device-b"] {
                device(&db, device_id, owner).await;
            }
            let first = db.get_address_book_full(owner, 1, 1, None).await.unwrap();
            assert_eq!(first.items[0].device_id, "device-a");
            assert_eq!(first.total, 3);
            assert!(first.has_more);

            db.update_managed_device(
                super::super::OwnerScope::Owner(owner),
                "device-a",
                &super::super::DeviceUpdate {
                    alias: Some(Some("new-alias".to_owned())),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
            {
                let mut connection = db.pool.get().await.unwrap();
                let mut tx = connection.begin().await.unwrap();
                delete_device_in_tx(&mut tx, "device-b").await;
                tx.commit().await.unwrap();
            }
            device(&db, "device-d", owner).await;

            assert!(db.get_address_book_full(owner, 2, 1, None).await.is_err());
            let second = db
                .get_address_book_full(owner, 2, 1, Some(first.ab_ver))
                .await
                .unwrap();
            let third = db
                .get_address_book_full(owner, 3, 1, Some(first.ab_ver))
                .await
                .unwrap();
            assert_eq!(second.ab_ver, first.ab_ver);
            assert_eq!(third.ab_ver, first.ab_ver);
            assert_eq!(second.total, 3);
            assert_eq!(third.total, 3);
            assert!(second.has_more);
            assert!(!third.has_more);
            assert_eq!(
                [
                    first.items[0].device_id.as_str(),
                    second.items[0].device_id.as_str(),
                    third.items[0].device_id.as_str()
                ],
                ["device-a", "device-b", "device-c"]
            );
            assert_eq!(first.items[0].alias, "device-a-alias");

            let current = db.get_address_book_full(owner, 1, 3, None).await.unwrap();
            assert_eq!(current.total, 3);
            assert!(!current.has_more);
            assert_eq!(
                current
                    .items
                    .iter()
                    .map(|item| item.device_id.as_str())
                    .collect::<Vec<_>>(),
                ["device-a", "device-c", "device-d"]
            );
            assert_eq!(current.items[0].alias, "new-alias");
            drop(db);
            let _ = std::fs::remove_file(path);
        });
    }

    #[test]
    fn full_snapshot_rejects_non_json_safe_page_numbers() {
        run(async {
            let path = temp_db_path("full-safe-page");
            let db = Database::new(&path).await.unwrap();
            let owner = user(&db, "owner", "user").await;
            assert!(db
                .get_address_book_full(owner, MAX_SAFE_INTEGER as u64 + 1, 1, None,)
                .await
                .is_err());
            assert!(db
                .get_address_book_full(owner, u64::MAX, 1, None)
                .await
                .is_err());
            drop(db);
            let _ = std::fs::remove_file(path);
        });
    }

    #[test]
    fn pending_keyset_does_not_skip_recreated_invitation() {
        run(async {
            let path = temp_db_path("pending-keyset");
            let db = Database::new(&path).await.unwrap();
            let owner = user(&db, "owner", "user").await;
            let recipient = user(&db, "recipient", "user").await;
            device(&db, "device-1", owner).await;
            let first = db
                .share_device(owner, "device-1", "recipient", SharePermission::ViewOnly)
                .await
                .unwrap();
            db.reject_device_share(recipient, first.share.id)
                .await
                .unwrap();
            let second = db
                .share_device(owner, "device-1", "recipient", SharePermission::ViewOnly)
                .await
                .unwrap();
            assert!(second.created);
            assert!(second.share.id > first.share.id);
            let page = db
                .get_pending_shares(recipient, first.share.id, 50)
                .await
                .unwrap();
            assert_eq!(page.items[0].id, second.share.id);
            drop(db);
            let _ = std::fs::remove_file(path);
        });
    }

    #[test]
    fn startup_rejects_tampered_deleted_history_lifecycle() {
        run(async {
            let path = temp_db_path("tampered-history-lifecycle");
            let db = Database::new(&path).await.unwrap();
            let owner = user(&db, "owner", "user").await;
            device(&db, "device-1", owner).await;

            let mut connection = db.pool.get().await.unwrap();
            let mut tx = connection.begin().await.unwrap();
            super::super::inventory::lock_inventory(&mut tx)
                .await
                .unwrap();
            delete_device_in_tx(&mut tx, "device-1").await;
            tx.commit().await.unwrap();
            drop(connection);

            let mut connection = db.pool.get().await.unwrap();
            sqlx::query("DROP TRIGGER address_book_change_immutable_update")
                .execute(connection.deref_mut())
                .await
                .unwrap();
            sqlx::query("PRAGMA ignore_check_constraints = ON")
                .execute(connection.deref_mut())
                .await
                .unwrap();
            let payload = sqlx::query_scalar::<_, String>(
                "SELECT payload
                 FROM address_book_changes
                 WHERE user_id = ? AND version = 1",
            )
            .bind(owner)
            .fetch_one(connection.deref_mut())
            .await
            .unwrap();
            let tampered_lifecycle = "A".repeat(32);
            let mut item = serde_json::from_str::<SafeDeviceDto>(&payload).unwrap();
            item.instance_id = instance_id(&tampered_lifecycle);
            let tampered_payload = serde_json::to_string(&item).unwrap();
            sqlx::query(
                "UPDATE address_book_changes
                 SET device_lifecycle = ?,
                     payload = CASE WHEN operation = 'upsert' THEN ? ELSE NULL END
                 WHERE user_id = ?",
            )
            .bind(&tampered_lifecycle)
            .bind(tampered_payload)
            .bind(owner)
            .execute(connection.deref_mut())
            .await
            .unwrap();
            drop(connection);
            drop(db);

            let error = Database::new(&path).await.err().unwrap();
            assert!(
                error.to_string().contains("lifecycle"),
                "unexpected startup error: {error:#}"
            );
            cleanup(&path);
        });
    }

    #[test]
    fn hundred_thousand_change_full_query_uses_lifecycle_index_and_is_correct() {
        run(async {
            let path = temp_db_path("hundred-thousand-history");
            let db = Database::new(&path).await.unwrap();
            let owner = user(&db, "owner", "user").await;
            db.insert_peer("history-device", b"uuid", b"pk", "{}")
                .await
                .unwrap();

            let mut connection = db.pool.get().await.unwrap();
            sqlx::query("UPDATE devices SET owner_user_id = ? WHERE device_id = 'history-device'")
                .bind(owner)
                .execute(connection.deref_mut())
                .await
                .unwrap();
            let row = sqlx::query(
                "SELECT id, management_generation
                 FROM devices
                 WHERE device_id = 'history-device'",
            )
            .fetch_one(connection.deref_mut())
            .await
            .unwrap();
            let row_id = row.try_get::<i64, _>("id").unwrap();
            let lifecycle = row.try_get::<String, _>("management_generation").unwrap();
            let payload = serde_json::to_string(&SafeDeviceDto {
                device_id: "history-device".to_owned(),
                instance_id: instance_id(&lifecycle),
                alias: String::new(),
                hostname: String::new(),
                os: String::new(),
                source: AddressBookSource::Owned,
                permission: SharePermission::FullControl,
                share_id: None,
                shared_by_user_id: None,
                shared_by_username: None,
            })
            .unwrap();

            sqlx::query("DROP TRIGGER address_book_change_insert_valid")
                .execute(connection.deref_mut())
                .await
                .unwrap();
            sqlx::query("UPDATE users SET address_book_version = 100000 WHERE id = ?")
                .bind(owner)
                .execute(connection.deref_mut())
                .await
                .unwrap();
            sqlx::query(
                "WITH digits(n) AS (
                     VALUES(0),(1),(2),(3),(4),(5),(6),(7),(8),(9)
                 )
                 INSERT INTO address_book_changes(
                     user_id, version, device_row_id, device_lifecycle,
                     device_id, share_id, operation, payload
                 )
                 SELECT ?, 1 + a.n + 10*b.n + 100*c.n + 1000*d.n + 10000*e.n,
                        ?, ?, 'history-device', NULL, 'upsert', ?
                 FROM digits a
                 CROSS JOIN digits b
                 CROSS JOIN digits c
                 CROSS JOIN digits d
                 CROSS JOIN digits e",
            )
            .bind(owner)
            .bind(row_id)
            .bind(&lifecycle)
            .bind(&payload)
            .execute(connection.deref_mut())
            .await
            .unwrap();

            let plan = sqlx::query(
                "EXPLAIN QUERY PLAN
                 WITH latest AS (
                     SELECT device_lifecycle, MAX(version) AS version
                     FROM address_book_changes
                     WHERE user_id = ? AND version <= ?
                     GROUP BY device_lifecycle
                 )
                 SELECT changes.payload
                 FROM latest
                 JOIN address_book_changes changes
                   ON changes.user_id = ?
                  AND changes.device_lifecycle = latest.device_lifecycle
                  AND changes.version = latest.version
                 WHERE changes.operation = 'upsert'
                 ORDER BY changes.device_id, changes.device_lifecycle
                 LIMIT ? OFFSET ?",
            )
            .bind(owner)
            .bind(100_000_i64)
            .bind(owner)
            .bind(200_i64)
            .bind(0_i64)
            .fetch_all(connection.deref_mut())
            .await
            .unwrap();
            let details = plan
                .iter()
                .map(|row| row.try_get::<String, _>("detail").unwrap())
                .collect::<Vec<_>>();
            assert!(
                details
                    .iter()
                    .any(|detail| detail.contains("idx_ab_changes_user_lifecycle_version")),
                "query plan 未命中 lifecycle/version 索引：{details:?}"
            );
            drop(connection);

            let full = db.get_address_book_full(owner, 1, 200, None).await.unwrap();
            assert_eq!(full.ab_ver, 100_000);
            assert_eq!(full.total, 1);
            assert_eq!(full.items.len(), 1);
            assert_eq!(full.items[0].device_id, "history-device");

            drop(db);
            cleanup(&path);
        });
    }

    #[test]
    fn max_safe_ids_versions_and_page_boundary_are_atomic() {
        run(async {
            let path = temp_db_path("max-safe-boundaries");
            let db = Database::new(&path).await.unwrap();
            let owner = user(&db, "owner", "user").await;
            let recipient = user(&db, "recipient", "user").await;
            let second_recipient = user(&db, "recipient-2", "user").await;
            device(&db, "device-1", owner).await;
            let snapshot = db
                .match_sysinfo_device("device-1", b"uuid")
                .await
                .unwrap()
                .unwrap();

            let mut connection = db.pool.get().await.unwrap();
            sqlx::query("UPDATE sqlite_sequence SET seq = ? WHERE name = 'users'")
                .bind(MAX_SAFE_INTEGER - 1)
                .execute(connection.deref_mut())
                .await
                .unwrap();
            drop(connection);
            let max_user = db
                .create_user("max-user", "hash", None, "user")
                .await
                .unwrap();
            assert_eq!(max_user.id, MAX_SAFE_INTEGER);
            assert!(db
                .create_user("overflow-user", "hash", None, "user")
                .await
                .is_err());
            assert!(db
                .find_user_by_username("overflow-user")
                .await
                .unwrap()
                .is_none());

            let mut connection = db.pool.get().await.unwrap();
            sqlx::query("DELETE FROM sqlite_sequence WHERE name = 'device_shares'")
                .execute(connection.deref_mut())
                .await
                .unwrap();
            sqlx::query("INSERT INTO sqlite_sequence(name, seq) VALUES('device_shares', ?)")
                .bind(MAX_SAFE_INTEGER - 1)
                .execute(connection.deref_mut())
                .await
                .unwrap();
            drop(connection);
            let max_share = db
                .share_device(owner, "device-1", "recipient", SharePermission::ViewOnly)
                .await
                .unwrap();
            assert_eq!(max_share.share.id, MAX_SAFE_INTEGER);
            assert!(db
                .share_device(owner, "device-1", "recipient-2", SharePermission::ViewOnly,)
                .await
                .is_err());
            assert_eq!(
                db.get_pending_shares(second_recipient, 0, 50)
                    .await
                    .unwrap()
                    .items
                    .len(),
                0
            );
            assert_eq!(
                db.get_pending_shares(recipient, 0, 50).await.unwrap().items[0].id,
                MAX_SAFE_INTEGER
            );

            let mut connection = db.pool.get().await.unwrap();
            sqlx::query("DROP TRIGGER address_book_change_immutable_update")
                .execute(connection.deref_mut())
                .await
                .unwrap();
            sqlx::query("UPDATE address_book_changes SET version = ? WHERE user_id = ?")
                .bind(MAX_SAFE_INTEGER - 1)
                .bind(owner)
                .execute(connection.deref_mut())
                .await
                .unwrap();
            sqlx::query("UPDATE users SET address_book_version = ? WHERE id = ?")
                .bind(MAX_SAFE_INTEGER - 1)
                .bind(owner)
                .execute(connection.deref_mut())
                .await
                .unwrap();
            drop(connection);

            let at_max = db
                .update_owned_device_sysinfo(
                    owner,
                    "device-1",
                    b"uuid",
                    &snapshot.management_generation,
                    Some("at-max"),
                    None,
                )
                .await
                .unwrap();
            assert_eq!(at_max.address_book_version, MAX_SAFE_INTEGER);
            let before_count = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM address_book_changes WHERE user_id = ?",
            )
            .bind(owner)
            .fetch_one(db.pool.get().await.unwrap().deref_mut())
            .await
            .unwrap();
            assert_eq!(
                db.update_owned_device_sysinfo(
                    owner,
                    "device-1",
                    b"uuid",
                    &snapshot.management_generation,
                    Some("must-rollback"),
                    None,
                )
                .await,
                Err(AddressBookError::TooLarge)
            );
            let current = db.get_address_book_snapshot(owner).await.unwrap();
            assert_eq!(current.ab_ver, MAX_SAFE_INTEGER);
            assert_eq!(current.items[0].hostname, "at-max");
            assert_eq!(
                sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM address_book_changes WHERE user_id = ?",
                )
                .bind(owner)
                .fetch_one(db.pool.get().await.unwrap().deref_mut())
                .await
                .unwrap(),
                before_count
            );

            let last_safe_page = db
                .get_address_book_full(owner, MAX_SAFE_INTEGER as u64, 1, Some(MAX_SAFE_INTEGER))
                .await
                .unwrap();
            assert!(last_safe_page.items.is_empty());
            assert_eq!(last_safe_page.total, 1);
            assert!(db
                .get_address_book_full(owner, MAX_SAFE_INTEGER as u64 + 1, 1, None)
                .await
                .is_err());
            assert_eq!(
                validate_wire_integer(MAX_SAFE_INTEGER, true).unwrap(),
                MAX_SAFE_INTEGER
            );
            assert!(validate_wire_integer(MAX_SAFE_INTEGER + 1, true).is_err());
            let wire_page = AddressBookFullPage {
                mode: "full",
                ab_ver: MAX_SAFE_INTEGER,
                items: Vec::new(),
                page: MAX_SAFE_INTEGER as u64,
                page_size: 200,
                total: MAX_SAFE_INTEGER,
                has_more: false,
            };
            let encoded_page = serde_json::to_value(&wire_page).unwrap();
            assert_eq!(encoded_page["ab_ver"].as_i64(), Some(MAX_SAFE_INTEGER));
            assert_eq!(encoded_page["page"].as_u64(), Some(MAX_SAFE_INTEGER as u64));
            assert_eq!(encoded_page["total"].as_i64(), Some(MAX_SAFE_INTEGER));
            assert_eq!(
                serde_json::to_value(&max_user).unwrap()["id"].as_i64(),
                Some(MAX_SAFE_INTEGER)
            );
            assert_eq!(
                serde_json::to_value(&max_share.share).unwrap()["id"].as_i64(),
                Some(MAX_SAFE_INTEGER)
            );

            drop(db);
            cleanup(&path);
        });
    }

    #[test]
    fn two_database_busy_is_retryable_with_single_connection_pool() {
        run(async {
            let path = temp_db_path("address-book-busy");
            let holder_db = Database::new(&path).await.unwrap();
            let owner = user(&holder_db, "owner", "user").await;
            user(&holder_db, "recipient", "user").await;
            device(&holder_db, "device-1", owner).await;
            let worker_db = Database::new(&path).await.unwrap();
            assert_eq!(holder_db.pool.status().max_size, 1);
            assert_eq!(worker_db.pool.status().max_size, 1);

            let mut holder = holder_db.pool.get().await.unwrap();
            let mut holder_tx = holder.begin().await.unwrap();
            super::super::inventory::lock_inventory(&mut holder_tx)
                .await
                .unwrap();
            assert_eq!(
                worker_db
                    .share_device(owner, "device-1", "recipient", SharePermission::ViewOnly)
                    .await,
                Err(AddressBookError::Busy)
            );
            holder_tx.rollback().await.unwrap();
            drop(holder);

            assert!(worker_db
                .share_device(owner, "device-1", "recipient", SharePermission::ViewOnly)
                .await
                .is_ok());
            let snapshot = worker_db
                .match_sysinfo_device("device-1", b"uuid")
                .await
                .unwrap()
                .unwrap();
            let mut telemetry_holder = holder_db.pool.get().await.unwrap();
            let mut telemetry_tx = telemetry_holder.begin().await.unwrap();
            super::super::inventory::lock_inventory(&mut telemetry_tx)
                .await
                .unwrap();
            assert_eq!(
                worker_db
                    .update_owned_device_sysinfo(
                        owner,
                        "device-1",
                        b"uuid",
                        &snapshot.management_generation,
                        Some("after-busy"),
                        None,
                    )
                    .await,
                Err(AddressBookError::Busy)
            );
            telemetry_tx.rollback().await.unwrap();
            drop(telemetry_holder);
            let recovered = worker_db
                .update_owned_device_sysinfo(
                    owner,
                    "device-1",
                    b"uuid",
                    &snapshot.management_generation,
                    Some("after-busy"),
                    None,
                )
                .await
                .unwrap();
            assert!(recovered.changed);
            assert_eq!(
                worker_db
                    .get_address_book_snapshot(owner)
                    .await
                    .unwrap()
                    .items[0]
                    .hostname,
                "after-busy"
            );
            drop(worker_db);
            drop(holder_db);
            cleanup(&path);
        });
    }

    #[test]
    fn synchronized_three_hundred_sysinfo_flows_finish_on_single_connection() {
        run(async {
            let path = temp_db_path("three-hundred-sysinfo");
            let db = Database::new(&path).await.unwrap();
            assert_eq!(db.pool.status().max_size, 1);
            let owner = user(&db, "owner", "user").await;
            for index in 0..300 {
                device(&db, &format!("device-{index:03}"), owner).await;
            }

            let operations = (0..300)
                .map(|index| {
                    let db = db.clone();
                    tokio::spawn(async move {
                        let device_id = format!("device-{index:03}");
                        let snapshot = db
                            .match_sysinfo_device(&device_id, b"uuid")
                            .await?
                            .ok_or(AddressBookError::NotFound)?;
                        db.update_owned_device_sysinfo(
                            owner,
                            &device_id,
                            b"uuid",
                            &snapshot.management_generation,
                            None,
                            None,
                        )
                        .await
                    })
                })
                .collect::<Vec<_>>();
            let results = tokio::time::timeout(std::time::Duration::from_secs(10), async move {
                let mut results = Vec::with_capacity(operations.len());
                for operation in operations {
                    results.push(operation.await.unwrap());
                }
                results
            })
            .await
            .expect("300 台同步 sysinfo 的真实 SQLite 流程应在 10 秒内完成");
            assert_eq!(results.len(), 300);
            for result in results {
                let result = result.unwrap();
                assert!(result.matched);
                assert!(result.is_owner);
                assert!(!result.changed);
            }

            drop(db);
            cleanup(&path);
        });
    }

    #[test]
    fn share_waiting_on_inventory_lock_observes_committed_device_delete() {
        run(async {
            let path = temp_db_path("share-delete-barrier");
            let holder_db = Database::new(&path).await.unwrap();
            let owner = user(&holder_db, "owner", "user").await;
            user(&holder_db, "recipient", "user").await;
            device(&holder_db, "device-1", owner).await;
            let worker_db = Database::new(&path).await.unwrap();

            let mut holder = holder_db.pool.get().await.unwrap();
            let mut holder_tx = holder.begin().await.unwrap();
            super::super::inventory::lock_inventory(&mut holder_tx)
                .await
                .unwrap();

            let entered = Arc::new(tokio::sync::Barrier::new(2));
            let resume = Arc::new(tokio::sync::Barrier::new(2));
            let task = {
                let entered = entered.clone();
                let resume = resume.clone();
                tokio::spawn(async move {
                    worker_db
                        .share_device_with_before_lock(
                            owner,
                            "device-1",
                            "recipient",
                            SharePermission::ViewOnly,
                            move || async move {
                                entered.wait().await;
                                resume.wait().await;
                            },
                        )
                        .await
                })
            };
            entered.wait().await;
            delete_device_in_tx(&mut holder_tx, "device-1").await;
            holder_tx.commit().await.unwrap();
            drop(holder);
            resume.wait().await;

            assert_eq!(task.await.unwrap(), Err(AddressBookError::NotFound));
            assert!(holder_db
                .get_address_book_snapshot(owner)
                .await
                .unwrap()
                .items
                .is_empty());
            assert_eq!(
                sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM device_shares")
                    .fetch_one(holder_db.pool.get().await.unwrap().deref_mut())
                    .await
                    .unwrap(),
                0
            );

            drop(holder_db);
            Database::new(&path).await.unwrap();
            cleanup(&path);
        });
    }

    #[test]
    fn accept_waiting_on_inventory_lock_observes_committed_cancel() {
        run(async {
            let path = temp_db_path("accept-cancel-barrier");
            let holder_db = Database::new(&path).await.unwrap();
            let owner = user(&holder_db, "owner", "user").await;
            let recipient = user(&holder_db, "recipient", "user").await;
            device(&holder_db, "device-1", owner).await;
            let share = holder_db
                .share_device(owner, "device-1", "recipient", SharePermission::ViewOnly)
                .await
                .unwrap();
            let share_id = share.share.id;
            let worker_db = Database::new(&path).await.unwrap();

            let mut holder = holder_db.pool.get().await.unwrap();
            let mut holder_tx = holder.begin().await.unwrap();
            super::super::inventory::lock_inventory(&mut holder_tx)
                .await
                .unwrap();

            let entered = Arc::new(tokio::sync::Barrier::new(2));
            let resume = Arc::new(tokio::sync::Barrier::new(2));
            let task = {
                let entered = entered.clone();
                let resume = resume.clone();
                tokio::spawn(async move {
                    worker_db
                        .resolve_share_invitation_with_before_lock(
                            recipient,
                            share_id,
                            true,
                            move || async move {
                                entered.wait().await;
                                resume.wait().await;
                            },
                        )
                        .await
                })
            };
            entered.wait().await;
            assert_eq!(
                sqlx::query("DELETE FROM device_shares WHERE id = ?")
                    .bind(share_id)
                    .execute(&mut holder_tx)
                    .await
                    .unwrap()
                    .rows_affected(),
                1
            );
            holder_tx.commit().await.unwrap();
            drop(holder);
            resume.wait().await;

            assert_eq!(task.await.unwrap(), Err(AddressBookError::NotFound));
            assert_eq!(
                holder_db.get_address_book_version(recipient).await.unwrap(),
                Some(0)
            );
            assert!(holder_db
                .get_address_book_snapshot(recipient)
                .await
                .unwrap()
                .items
                .is_empty());

            drop(holder_db);
            Database::new(&path).await.unwrap();
            cleanup(&path);
        });
    }

    #[test]
    fn share_waiting_on_inventory_lock_observes_owner_transfer() {
        run(async {
            let path = temp_db_path("share-transfer-barrier");
            let holder_db = Database::new(&path).await.unwrap();
            let old_owner = user(&holder_db, "old-owner", "user").await;
            let new_owner = user(&holder_db, "new-owner", "user").await;
            let recipient = user(&holder_db, "recipient", "user").await;
            device(&holder_db, "device-1", old_owner).await;
            let worker_db = Database::new(&path).await.unwrap();

            let mut holder = holder_db.pool.get().await.unwrap();
            let mut holder_tx = holder.begin().await.unwrap();
            super::super::inventory::lock_inventory(&mut holder_tx)
                .await
                .unwrap();

            let entered = Arc::new(tokio::sync::Barrier::new(2));
            let resume = Arc::new(tokio::sync::Barrier::new(2));
            let task = {
                let entered = entered.clone();
                let resume = resume.clone();
                tokio::spawn(async move {
                    worker_db
                        .share_device_with_before_lock(
                            old_owner,
                            "device-1",
                            "recipient",
                            SharePermission::ViewOnly,
                            move || async move {
                                entered.wait().await;
                                resume.wait().await;
                            },
                        )
                        .await
                })
            };
            entered.wait().await;
            transfer_device_in_tx(&mut holder_tx, "device-1", new_owner).await;
            holder_tx.commit().await.unwrap();
            drop(holder);
            resume.wait().await;

            assert_eq!(task.await.unwrap(), Err(AddressBookError::NotFound));
            assert!(holder_db
                .get_address_book_snapshot(old_owner)
                .await
                .unwrap()
                .items
                .is_empty());
            assert_eq!(
                holder_db
                    .get_address_book_snapshot(new_owner)
                    .await
                    .unwrap()
                    .items[0]
                    .device_id,
                "device-1"
            );
            assert!(holder_db
                .get_pending_shares(recipient, 0, 50)
                .await
                .unwrap()
                .items
                .is_empty());

            drop(holder_db);
            Database::new(&path).await.unwrap();
            cleanup(&path);
        });
    }

    #[test]
    fn sysinfo_waiting_on_inventory_lock_observes_delete_and_owner_transfer() {
        run(async {
            for transfer in [false, true] {
                let path = temp_db_path(if transfer {
                    "sysinfo-transfer-barrier"
                } else {
                    "sysinfo-delete-barrier"
                });
                let holder_db = Database::new(&path).await.unwrap();
                let old_owner = user(&holder_db, "old-owner", "user").await;
                let new_owner = user(&holder_db, "new-owner", "user").await;
                device(&holder_db, "device-1", old_owner).await;
                let snapshot = holder_db
                    .match_sysinfo_device("device-1", b"uuid")
                    .await
                    .unwrap()
                    .unwrap();
                let expected_generation = snapshot.management_generation;
                let worker_db = Database::new(&path).await.unwrap();

                let mut holder = holder_db.pool.get().await.unwrap();
                let mut holder_tx = holder.begin().await.unwrap();
                super::super::inventory::lock_inventory(&mut holder_tx)
                    .await
                    .unwrap();

                let entered = Arc::new(tokio::sync::Barrier::new(2));
                let resume = Arc::new(tokio::sync::Barrier::new(2));
                let task = {
                    let entered = entered.clone();
                    let resume = resume.clone();
                    tokio::spawn(async move {
                        worker_db
                            .update_owned_device_sysinfo_with_before_lock(
                                old_owner,
                                "device-1",
                                b"uuid",
                                &expected_generation,
                                Some("stale-hostname"),
                                Some("stale-os"),
                                move || async move {
                                    entered.wait().await;
                                    resume.wait().await;
                                },
                            )
                            .await
                    })
                };
                entered.wait().await;
                if transfer {
                    transfer_device_in_tx(&mut holder_tx, "device-1", new_owner).await;
                } else {
                    delete_device_in_tx(&mut holder_tx, "device-1").await;
                }
                holder_tx.commit().await.unwrap();
                drop(holder);
                resume.wait().await;

                let result = task.await.unwrap().unwrap();
                assert!(!result.changed);
                assert_eq!(result.matched, transfer);
                assert!(!result.is_owner);
                if transfer {
                    let current = holder_db
                        .get_address_book_snapshot(new_owner)
                        .await
                        .unwrap();
                    assert_eq!(current.items[0].hostname, "");
                    assert_eq!(current.items[0].os, "");
                } else {
                    assert!(holder_db
                        .match_sysinfo_device("device-1", b"uuid")
                        .await
                        .unwrap()
                        .is_none());
                }
                assert!(holder_db
                    .get_address_book_snapshot(old_owner)
                    .await
                    .unwrap()
                    .items
                    .is_empty());

                drop(holder_db);
                Database::new(&path).await.unwrap();
                cleanup(&path);
            }
        });
    }
}
