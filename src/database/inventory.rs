use super::{
    addressbook::{
        delete_device_memberships_in_tx, upsert_device_memberships_in_tx, AddressBookError,
    },
    Database, PortableQuery,
};
use crate::models::device::{DeviceSortBy, SortDirection};
use chrono::{Duration as ChronoDuration, NaiveDateTime, Utc};
use hbb_common::{bail, ResultType};
use sqlx::{Any, Connection, FromRow, Row, Transaction};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt,
    future::Future,
    ops::DerefMut,
};

const MAX_GROUP_TREE_NODES: i64 = 10_000;
const MAX_DEVICE_TAGS: usize = 100;
const DELETION_OUTBOX_CAPACITY: i64 = 4_096;
const MAX_DISPATCH_BATCH: i64 = 32;

pub type InventoryResult<T> = Result<T, InventoryError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InventoryError {
    NotFound,
    Conflict(String),
    DepthExceeded,
    TooLarge,
    Busy,
    Internal(String),
}

impl fmt::Display for InventoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => formatter.write_str("inventory resource not found"),
            Self::Conflict(code) => write!(formatter, "inventory conflict: {code}"),
            Self::DepthExceeded => formatter.write_str("group depth exceeded"),
            Self::TooLarge => formatter.write_str("inventory operation is too large"),
            Self::Busy => formatter.write_str("inventory database is busy"),
            Self::Internal(message) => write!(formatter, "inventory database error: {message}"),
        }
    }
}

impl std::error::Error for InventoryError {}

impl From<sqlx::Error> for InventoryError {
    fn from(error: sqlx::Error) -> Self {
        if let sqlx::Error::Database(database_error) = &error {
            let message = database_error.message();
            let lower = message.to_ascii_lowercase();
            let code = database_error.code();
            if matches!(
                code.as_deref(),
                Some("5") | Some("6") | Some("261") | Some("517")
            ) || lower.contains("database is locked")
                || lower.contains("database table is locked")
                || lower.contains("database is busy")
            {
                return Self::Busy;
            }
            match message {
                "group_depth_exceeded" => return Self::DepthExceeded,
                "group_owner_immutable"
                | "group_parent_owner_mismatch"
                | "group_cycle"
                | "device_group_owner_mismatch"
                | "device_owner_change_with_tags"
                | "tag_owner_immutable"
                | "device_tag_unowned_device"
                | "device_tag_owner_mismatch"
                | "device_management_generation_immutable"
                | "device_management_generation_invalid" => {
                    return Self::Conflict(message.to_owned());
                }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerScope {
    All,
    Owner(i64),
}

#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct GroupRecord {
    pub id: i64,
    pub name: String,
    pub owner_user_id: i64,
    pub parent_group_id: Option<i64>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GroupUpdate {
    pub name: Option<String>,
    pub parent_group_id: Option<Option<i64>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupDeleteOutcome {
    Deleted,
    NotFound,
    NotEmpty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForceDeleteOutcome {
    pub deleted_groups: u64,
    pub ungrouped_devices: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupDeviceBatchOutcome {
    pub matched: u64,
    pub changed: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedDevice {
    pub device_id: String,
    pub owner_user_id: Option<i64>,
    pub group_id: Option<i64>,
    pub alias: Option<String>,
    pub device_name: Option<String>,
    pub os: Option<String>,
    pub note: Option<String>,
    pub status: String,
    pub management_generation: String,
    pub tags: Vec<String>,
    pub last_seen: NaiveDateTime,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceListFilter {
    pub group_id: Option<i64>,
    pub tag: Option<String>,
    pub status: Option<String>,
    pub query: Option<String>,
    pub page: i64,
    pub page_size: i64,
    pub sort_by: DeviceSortBy,
    pub sort_dir: SortDirection,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceUpdate {
    pub alias: Option<Option<String>>,
    pub note: Option<Option<String>>,
    pub group_id: Option<Option<i64>>,
    pub owner_user_id: Option<Option<i64>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceTagBatchOutcome {
    pub devices: u64,
    pub added: u64,
    pub removed: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct TagRecord {
    pub id: i64,
    pub owner_user_id: i64,
    pub name: String,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeletionReceiptState {
    Pending,
    Completed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletionReceipt {
    pub id: i64,
    pub actor_user_id: i64,
    pub device_id: String,
    pub management_generation: String,
    pub deleted_guid: Vec<u8>,
    pub state: DeletionReceiptState,
    pub attempt_count: i64,
    pub next_attempt_at: NaiveDateTime,
    pub lease_token: Option<String>,
    pub lease_until: Option<NaiveDateTime>,
    pub completed_at: Option<NaiveDateTime>,
    pub expires_at: Option<NaiveDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceDeleteOutcome {
    Pending(DeletionReceipt),
    Completed,
    DeletedAndPending(DeletionReceipt),
    ScopedMiss,
    GenerationMismatch,
    CapacityFull,
}

#[derive(Debug, Clone, FromRow)]
struct ManagedDeviceRow {
    row_id: i64,
    device_id: String,
    owner_user_id: Option<i64>,
    group_id: Option<i64>,
    alias: Option<String>,
    device_name: Option<String>,
    os: Option<String>,
    note: Option<String>,
    status: String,
    management_generation: String,
    last_seen: NaiveDateTime,
    created_at: NaiveDateTime,
    updated_at: NaiveDateTime,
}

impl ManagedDeviceRow {
    fn with_tags(self, tags: Vec<String>) -> ManagedDevice {
        ManagedDevice {
            device_id: self.device_id,
            owner_user_id: self.owner_user_id,
            group_id: self.group_id,
            alias: self.alias,
            device_name: self.device_name,
            os: self.os,
            note: self.note,
            status: self.status,
            management_generation: self.management_generation,
            tags,
            last_seen: self.last_seen,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

#[derive(Debug, Clone, FromRow)]
struct DeletionReceiptRow {
    id: i64,
    actor_user_id: i64,
    device_id: String,
    management_generation: String,
    deleted_guid: Vec<u8>,
    state: String,
    attempt_count: i64,
    next_attempt_at: NaiveDateTime,
    lease_token: Option<String>,
    lease_until: Option<NaiveDateTime>,
    completed_at: Option<NaiveDateTime>,
    expires_at: Option<NaiveDateTime>,
}

impl TryFrom<DeletionReceiptRow> for DeletionReceipt {
    type Error = InventoryError;

    fn try_from(row: DeletionReceiptRow) -> InventoryResult<Self> {
        let state = match row.state.as_str() {
            "pending" => DeletionReceiptState::Pending,
            "completed" => DeletionReceiptState::Completed,
            other => {
                return Err(InventoryError::Internal(format!(
                    "unknown deletion receipt state: {other}"
                )))
            }
        };
        Ok(Self {
            id: row.id,
            actor_user_id: row.actor_user_id,
            device_id: row.device_id,
            management_generation: row.management_generation,
            deleted_guid: row.deleted_guid,
            state,
            attempt_count: row.attempt_count,
            next_attempt_at: row.next_attempt_at,
            lease_token: row.lease_token,
            lease_until: row.lease_until,
            completed_at: row.completed_at,
            expires_at: row.expires_at,
        })
    }
}

fn pool_error(error: impl fmt::Display) -> InventoryError {
    InventoryError::Internal(error.to_string())
}

fn address_book_error(error: AddressBookError) -> InventoryError {
    match error {
        AddressBookError::Busy => InventoryError::Busy,
        AddressBookError::NotFound => InventoryError::NotFound,
        AddressBookError::TooLarge => InventoryError::TooLarge,
        AddressBookError::Conflict(code) => InventoryError::Conflict(code),
        other => InventoryError::Internal(other.to_string()),
    }
}

fn scope_allows_owner(scope: OwnerScope, owner_user_id: Option<i64>) -> bool {
    match scope {
        OwnerScope::All => true,
        OwnerScope::Owner(expected) => owner_user_id == Some(expected),
    }
}

pub(super) async fn lock_inventory(tx: &mut Transaction<'_, Any>) -> InventoryResult<()> {
    sqlx::query("UPDATE inventory_write_lock SET version = version + 1 WHERE id = 1")
        .execute(&mut *tx)
        .await?;
    Ok(())
}

async fn lock_quota_then_inventory(tx: &mut Transaction<'_, Any>) -> InventoryResult<()> {
    sqlx::query("UPDATE device_quota_lock SET version = version + 1 WHERE id = 1")
        .execute(&mut *tx)
        .await?;
    lock_inventory(tx).await
}

async fn fetch_group_in_tx(
    tx: &mut Transaction<'_, Any>,
    scope: OwnerScope,
    id: i64,
) -> InventoryResult<Option<GroupRecord>> {
    let row = match scope {
        OwnerScope::All => {
            sqlx::query_as::<_, GroupRecord>(
                "SELECT id, name, owner_user_id, parent_group_id, created_at, updated_at
                 FROM groups WHERE id = $1",
            )
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
        }
        OwnerScope::Owner(owner_user_id) => {
            sqlx::query_as::<_, GroupRecord>(
                "SELECT id, name, owner_user_id, parent_group_id, created_at, updated_at
                 FROM groups WHERE id = $1 AND owner_user_id = $2",
            )
            .bind(id)
            .bind(owner_user_id)
            .fetch_optional(&mut *tx)
            .await?
        }
    };
    Ok(row)
}

async fn count_group_subtree_in_tx(
    tx: &mut Transaction<'_, Any>,
    scope: OwnerScope,
    id: i64,
) -> InventoryResult<i64> {
    let mut query = PortableQuery::new(
        "WITH RECURSIVE subtree(id) AS (
             SELECT id FROM groups WHERE id = ",
    );
    query.push_bind(id);
    if let OwnerScope::Owner(owner_user_id) = scope {
        query.push(" AND owner_user_id = ");
        query.push_bind(owner_user_id);
    }
    query.push(
        " UNION
             SELECT child.id
             FROM groups child
             JOIN subtree parent ON child.parent_group_id = parent.id
         )
         SELECT COUNT(*) AS count
         FROM (SELECT id FROM subtree LIMIT ",
    );
    query.push_bind(MAX_GROUP_TREE_NODES + 1);
    query.push(")");
    Ok(query
        .fetch_one(&mut *tx)
        .await?
        .try_get::<i64, _>("count")?)
}

async fn fetch_group_subtree_in_tx(
    tx: &mut Transaction<'_, Any>,
    scope: OwnerScope,
    id: i64,
) -> InventoryResult<Vec<GroupRecord>> {
    let mut query = PortableQuery::new(
        "WITH RECURSIVE subtree(id) AS (
             SELECT id FROM groups WHERE id = ",
    );
    query.push_bind(id);
    if let OwnerScope::Owner(owner_user_id) = scope {
        query.push(" AND owner_user_id = ");
        query.push_bind(owner_user_id);
    }
    query.push(
        " UNION
             SELECT child.id
             FROM groups child
             JOIN subtree parent ON child.parent_group_id = parent.id
         )
         SELECT grouped.id, grouped.name, grouped.owner_user_id,
                grouped.parent_group_id, grouped.created_at, grouped.updated_at
         FROM groups grouped
         JOIN subtree ON subtree.id = grouped.id
         ORDER BY lower(grouped.name), grouped.id",
    );
    Ok(query
        .fetch_all(&mut *tx)
        .await?
        .iter()
        .map(GroupRecord::from_row)
        .collect::<Result<Vec<_>, _>>()?)
}

impl Database {
    pub async fn create_group(
        &self,
        scope: OwnerScope,
        owner_user_id: i64,
        name: &str,
        parent_group_id: Option<i64>,
    ) -> InventoryResult<GroupRecord> {
        if !scope_allows_owner(scope, Some(owner_user_id)) {
            return Err(InventoryError::NotFound);
        }
        let mut connection = self.pool.get().await.map_err(pool_error)?;
        let mut tx = connection.begin().await?;
        lock_inventory(&mut tx).await?;
        let owner_exists = sqlx::query_scalar::<_, i64>(
            "SELECT CAST(1 AS BIGINT) FROM users WHERE id = $1 AND is_active = TRUE",
        )
        .bind(owner_user_id)
        .fetch_optional(&mut tx)
        .await?
        .is_some();
        if !owner_exists {
            return Err(InventoryError::NotFound);
        }
        if let Some(parent_id) = parent_group_id {
            let parent =
                fetch_group_in_tx(&mut tx, OwnerScope::Owner(owner_user_id), parent_id).await?;
            if parent.is_none() {
                if scope == OwnerScope::All
                    && fetch_group_in_tx(&mut tx, OwnerScope::All, parent_id)
                        .await?
                        .is_some()
                {
                    return Err(InventoryError::Conflict(
                        "group_parent_owner_mismatch".to_owned(),
                    ));
                }
                return Err(InventoryError::NotFound);
            }
        }
        let group = sqlx::query_as::<_, GroupRecord>(
            "INSERT INTO groups(name, owner_user_id, parent_group_id)
             VALUES($1, $2, $3)
             RETURNING id, name, owner_user_id, parent_group_id, created_at, updated_at",
        )
        .bind(name)
        .bind(owner_user_id)
        .bind(parent_group_id)
        .fetch_one(&mut tx)
        .await?;
        tx.commit().await?;
        Ok(group)
    }

    pub async fn list_groups(&self, scope: OwnerScope) -> InventoryResult<Vec<GroupRecord>> {
        let mut connection = self.pool.get().await.map_err(pool_error)?;
        let rows = match scope {
            OwnerScope::All => {
                sqlx::query_as::<_, GroupRecord>(
                    "SELECT id, name, owner_user_id, parent_group_id, created_at, updated_at
                     FROM groups
                     ORDER BY owner_user_id, lower(name), id
                     LIMIT 10001",
                )
                .fetch_all(connection.deref_mut())
                .await?
            }
            OwnerScope::Owner(owner_user_id) => {
                sqlx::query_as::<_, GroupRecord>(
                    "SELECT id, name, owner_user_id, parent_group_id, created_at, updated_at
                     FROM groups
                     WHERE owner_user_id = $1
                     ORDER BY lower(name), id
                     LIMIT 10001",
                )
                .bind(owner_user_id)
                .fetch_all(connection.deref_mut())
                .await?
            }
        };
        if rows.len() as i64 > MAX_GROUP_TREE_NODES {
            return Err(InventoryError::TooLarge);
        }
        Ok(rows)
    }

    pub async fn get_group(
        &self,
        scope: OwnerScope,
        id: i64,
    ) -> InventoryResult<Option<GroupRecord>> {
        let mut connection = self.pool.get().await.map_err(pool_error)?;
        let mut tx = connection.begin().await?;
        let group = fetch_group_in_tx(&mut tx, scope, id).await?;
        tx.commit().await?;
        Ok(group)
    }

    pub async fn get_group_subtree(
        &self,
        scope: OwnerScope,
        id: i64,
    ) -> InventoryResult<Vec<GroupRecord>> {
        let mut connection = self.pool.get().await.map_err(pool_error)?;
        let mut tx = connection.begin().await?;
        let subtree_count = count_group_subtree_in_tx(&mut tx, scope, id).await?;
        if subtree_count > MAX_GROUP_TREE_NODES {
            return Err(InventoryError::TooLarge);
        }
        let rows = fetch_group_subtree_in_tx(&mut tx, scope, id).await?;
        tx.commit().await?;
        Ok(rows)
    }

    pub async fn update_group(
        &self,
        scope: OwnerScope,
        id: i64,
        update: &GroupUpdate,
    ) -> InventoryResult<Option<Vec<GroupRecord>>> {
        let mut connection = self.pool.get().await.map_err(pool_error)?;
        let mut tx = connection.begin().await?;
        lock_inventory(&mut tx).await?;
        let Some(current) = fetch_group_in_tx(&mut tx, scope, id).await? else {
            return Ok(None);
        };
        let name = update.name.as_deref().unwrap_or(&current.name);
        let parent_group_id = update.parent_group_id.unwrap_or(current.parent_group_id);
        if let Some(parent_id) = parent_group_id {
            let parent =
                fetch_group_in_tx(&mut tx, OwnerScope::Owner(current.owner_user_id), parent_id)
                    .await?;
            if parent.is_none() {
                if scope == OwnerScope::All
                    && fetch_group_in_tx(&mut tx, OwnerScope::All, parent_id)
                        .await?
                        .is_some()
                {
                    return Err(InventoryError::Conflict(
                        "group_parent_owner_mismatch".to_owned(),
                    ));
                }
                return Err(InventoryError::NotFound);
            }
        }
        sqlx::query(
            "UPDATE groups
             SET name = $1, parent_group_id = $2, updated_at = current_timestamp
             WHERE id = $3",
        )
        .bind(name)
        .bind(parent_group_id)
        .bind(id)
        .execute(&mut tx)
        .await?;
        let subtree_count = count_group_subtree_in_tx(&mut tx, scope, id).await?;
        if subtree_count > MAX_GROUP_TREE_NODES {
            return Err(InventoryError::TooLarge);
        }
        let updated = fetch_group_subtree_in_tx(&mut tx, scope, id).await?;
        tx.commit().await?;
        Ok(Some(updated))
    }

    pub async fn delete_group(
        &self,
        scope: OwnerScope,
        id: i64,
    ) -> InventoryResult<GroupDeleteOutcome> {
        let mut connection = self.pool.get().await.map_err(pool_error)?;
        let mut tx = connection.begin().await?;
        lock_inventory(&mut tx).await?;
        if fetch_group_in_tx(&mut tx, scope, id).await?.is_none() {
            return Ok(GroupDeleteOutcome::NotFound);
        }
        let non_empty = sqlx::query_scalar::<_, i64>(
            "SELECT CAST(1 AS BIGINT) FROM groups WHERE parent_group_id = $1
             UNION ALL
             SELECT CAST(1 AS BIGINT) FROM devices WHERE group_id = $2
             LIMIT 1",
        )
        .bind(id)
        .bind(id)
        .fetch_optional(&mut tx)
        .await?
        .is_some();
        if non_empty {
            return Ok(GroupDeleteOutcome::NotEmpty);
        }
        sqlx::query("DELETE FROM groups WHERE id = $1")
            .bind(id)
            .execute(&mut tx)
            .await?;
        tx.commit().await?;
        Ok(GroupDeleteOutcome::Deleted)
    }

    pub async fn force_delete_group(
        &self,
        scope: OwnerScope,
        id: i64,
    ) -> InventoryResult<Option<ForceDeleteOutcome>> {
        let mut connection = self.pool.get().await.map_err(pool_error)?;
        let mut tx = connection.begin().await?;
        lock_inventory(&mut tx).await?;
        if fetch_group_in_tx(&mut tx, scope, id).await?.is_none() {
            return Ok(None);
        }
        let subtree_count = count_group_subtree_in_tx(&mut tx, OwnerScope::All, id).await?;
        if subtree_count > MAX_GROUP_TREE_NODES {
            return Err(InventoryError::TooLarge);
        }
        let ungrouped_devices = sqlx::query(
            "WITH RECURSIVE subtree(id) AS (
                 SELECT $1
                 UNION
                 SELECT child.id
                 FROM groups child
                 JOIN subtree parent ON child.parent_group_id = parent.id
             )
             UPDATE devices
             SET group_id = NULL, updated_at = current_timestamp
             WHERE group_id IN (SELECT id FROM subtree)",
        )
        .bind(id)
        .execute(&mut tx)
        .await?
        .rows_affected();
        let deleted_groups = sqlx::query(
            "WITH RECURSIVE subtree(id) AS (
                 SELECT $1
                 UNION
                 SELECT child.id
                 FROM groups child
                 JOIN subtree parent ON child.parent_group_id = parent.id
             )
             DELETE FROM groups WHERE id IN (SELECT id FROM subtree)",
        )
        .bind(id)
        .execute(&mut tx)
        .await?
        .rows_affected();
        tx.commit().await?;
        Ok(Some(ForceDeleteOutcome {
            deleted_groups,
            ungrouped_devices,
        }))
    }

    pub async fn add_devices_to_group(
        &self,
        scope: OwnerScope,
        group_id: i64,
        device_ids: &[String],
    ) -> InventoryResult<GroupDeviceBatchOutcome> {
        self.change_group_devices(scope, group_id, device_ids, true)
            .await
    }

    pub async fn remove_devices_from_group(
        &self,
        scope: OwnerScope,
        group_id: i64,
        device_ids: &[String],
    ) -> InventoryResult<GroupDeviceBatchOutcome> {
        self.change_group_devices(scope, group_id, device_ids, false)
            .await
    }

    async fn change_group_devices(
        &self,
        scope: OwnerScope,
        group_id: i64,
        device_ids: &[String],
        add: bool,
    ) -> InventoryResult<GroupDeviceBatchOutcome> {
        let unique_ids = device_ids.iter().cloned().collect::<BTreeSet<_>>();
        if unique_ids.is_empty() {
            return Ok(GroupDeviceBatchOutcome {
                matched: 0,
                changed: 0,
            });
        }
        let mut connection = self.pool.get().await.map_err(pool_error)?;
        let mut tx = connection.begin().await?;
        lock_inventory(&mut tx).await?;
        let Some(group) = fetch_group_in_tx(&mut tx, scope, group_id).await? else {
            return Err(InventoryError::NotFound);
        };
        let mut query = PortableQuery::new(
            "SELECT device_id, owner_user_id, group_id FROM devices WHERE device_id IN (",
        );
        query.push_bind_list(&unique_ids);
        query.push(")");
        match scope {
            OwnerScope::All => {}
            OwnerScope::Owner(owner_user_id) => {
                query.push(" AND owner_user_id = ");
                query.push_bind(owner_user_id);
            }
        }
        let rows = query.fetch_all(&mut *tx).await?;
        if rows.len() != unique_ids.len() {
            return Err(InventoryError::NotFound);
        }
        for row in &rows {
            let owner_user_id = row.try_get::<Option<i64>, _>("owner_user_id")?;
            if owner_user_id != Some(group.owner_user_id) {
                return Err(InventoryError::Conflict(
                    "device_group_owner_mismatch".to_owned(),
                ));
            }
            if !add {
                let current_group = row.try_get::<Option<i64>, _>("group_id")?;
                if current_group.is_some() && current_group != Some(group_id) {
                    return Err(InventoryError::Conflict("device_in_other_group".to_owned()));
                }
            }
        }
        let mut update = PortableQuery::new("UPDATE devices SET group_id = ");
        if add {
            update.push_bind(group_id);
        } else {
            update.push("NULL");
        }
        update.push(", updated_at = current_timestamp WHERE device_id IN (");
        update.push_bind_list(&unique_ids);
        update.push(")");
        if add {
            update.push(" AND group_id IS NOT ");
            update.push_bind(group_id);
        } else {
            update.push(" AND group_id = ");
            update.push_bind(group_id);
        }
        let changed = update.execute(&mut *tx).await?.rows_affected();
        tx.commit().await?;
        Ok(GroupDeviceBatchOutcome {
            matched: unique_ids.len() as u64,
            changed,
        })
    }
}

const MANAGED_DEVICE_COLUMNS: &str = "
    d.id AS row_id,
    d.device_id,
    d.owner_user_id,
    d.group_id,
    d.alias,
    d.device_name,
    d.os,
    d.note,
    d.status,
    d.management_generation,
    d.last_seen,
    d.created_at,
    d.updated_at
";

fn push_device_scope(query: &mut PortableQuery, scope: OwnerScope) {
    if let OwnerScope::Owner(owner_user_id) = scope {
        query.push(" AND d.owner_user_id = ");
        query.push_bind(owner_user_id);
    }
}

fn escape_like_literal(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' | '%' | '_' => {
                escaped.push('\\');
                escaped.push(character);
            }
            _ => escaped.push(character),
        }
    }
    escaped
}

fn push_device_filters(query: &mut PortableQuery, scope: OwnerScope, filter: &DeviceListFilter) {
    push_device_scope(query, scope);
    if let Some(group_id) = filter.group_id {
        query.push(" AND d.group_id = ");
        query.push_bind(group_id);
    }
    if let Some(status) = filter.status.as_deref() {
        query.push(" AND d.status = ");
        query.push_bind(status);
    }
    if let Some(tag) = filter.tag.as_deref() {
        query.push(
            " AND EXISTS (
                SELECT 1
                FROM device_tags filtered_device_tag
                JOIN tags filtered_tag ON filtered_tag.id = filtered_device_tag.tag_id
                WHERE filtered_device_tag.device_row_id = d.id
                  AND lower(filtered_tag.name) = lower(",
        );
        query.push_bind(tag);
        query.push("))");
    }
    if let Some(search) = filter.query.as_deref() {
        let pattern = format!("%{}%", escape_like_literal(search));
        query.push(" AND (lower(d.device_id) LIKE lower(");
        query.push_bind(pattern.clone());
        query.push(") ESCAPE '\\' OR lower(COALESCE(d.alias, '')) LIKE lower(");
        query.push_bind(pattern.clone());
        query.push(") ESCAPE '\\' OR lower(COALESCE(d.device_name, '')) LIKE lower(");
        query.push_bind(pattern);
        query.push(") ESCAPE '\\')");
    }
}

fn push_device_order(query: &mut PortableQuery, sort_by: DeviceSortBy, sort_dir: SortDirection) {
    query.push(" ORDER BY ");
    query.push(match sort_by {
        DeviceSortBy::DeviceId => "lower(d.device_id)",
        DeviceSortBy::Alias => "lower(COALESCE(d.alias, ''))",
        DeviceSortBy::Hostname => "lower(COALESCE(d.device_name, ''))",
        DeviceSortBy::Os => "lower(COALESCE(d.os, ''))",
        DeviceSortBy::Status => "lower(d.status)",
        DeviceSortBy::LastSeen => "d.last_seen",
        DeviceSortBy::CreatedAt => "d.created_at",
        DeviceSortBy::UpdatedAt => "d.updated_at",
    });
    query.push(match sort_dir {
        SortDirection::Asc => " ASC",
        SortDirection::Desc => " DESC",
    });
    query.push(", d.id ASC");
}

async fn fetch_device_row_in_tx(
    tx: &mut Transaction<'_, Any>,
    scope: OwnerScope,
    device_id: &str,
) -> InventoryResult<Option<ManagedDeviceRow>> {
    let mut query = PortableQuery::new(format!(
        "SELECT {MANAGED_DEVICE_COLUMNS} FROM devices d WHERE d.device_id = "
    ));
    query.push_bind(device_id);
    push_device_scope(&mut query, scope);
    query
        .fetch_optional(&mut *tx)
        .await?
        .map(|row| ManagedDeviceRow::from_row(&row).map_err(InventoryError::from))
        .transpose()
}

async fn fetch_tags_for_device_rows(
    tx: &mut Transaction<'_, Any>,
    device_row_ids: &[i64],
) -> InventoryResult<BTreeMap<i64, Vec<String>>> {
    let mut tags = BTreeMap::<i64, Vec<String>>::new();
    if device_row_ids.is_empty() {
        return Ok(tags);
    }
    let mut query = PortableQuery::new(
        "SELECT relation.device_row_id, tag.name
         FROM device_tags relation
         JOIN tags tag ON tag.id = relation.tag_id
         WHERE relation.device_row_id IN (",
    );
    query.push_bind_list(device_row_ids.iter().copied());
    query.push(") ORDER BY relation.device_row_id, lower(tag.name), tag.id");
    for row in query.fetch_all(&mut *tx).await? {
        tags.entry(row.try_get::<i64, _>("device_row_id")?)
            .or_default()
            .push(row.try_get::<String, _>("name")?);
    }
    Ok(tags)
}

async fn fetch_managed_device_in_tx(
    tx: &mut Transaction<'_, Any>,
    scope: OwnerScope,
    device_id: &str,
) -> InventoryResult<Option<ManagedDevice>> {
    let Some(row) = fetch_device_row_in_tx(tx, scope, device_id).await? else {
        return Ok(None);
    };
    let row_id = row.row_id;
    let mut tags = fetch_tags_for_device_rows(tx, &[row_id]).await?;
    Ok(Some(
        row.with_tags(tags.remove(&row_id).unwrap_or_default()),
    ))
}

async fn upsert_tag_in_tx(
    tx: &mut Transaction<'_, Any>,
    owner_user_id: i64,
    name: &str,
) -> InventoryResult<TagRecord> {
    let inserted = sqlx::query_as::<_, TagRecord>(
        "INSERT INTO tags(owner_user_id, name)
         VALUES($1, $2)
         ON CONFLICT DO NOTHING
         RETURNING id, owner_user_id, name, created_at, updated_at",
    )
    .bind(owner_user_id)
    .bind(name)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(inserted) = inserted {
        return Ok(inserted);
    }
    Ok(sqlx::query_as::<_, TagRecord>(
        "UPDATE tags
         SET updated_at = current_timestamp
         WHERE owner_user_id = $1 AND lower(name) = lower($2)
         RETURNING id, owner_user_id, name, created_at, updated_at",
    )
    .bind(owner_user_id)
    .bind(name)
    .fetch_one(&mut *tx)
    .await?)
}

impl Database {
    pub async fn get_managed_device(
        &self,
        scope: OwnerScope,
        device_id: &str,
    ) -> InventoryResult<Option<ManagedDevice>> {
        let mut connection = self.pool.get().await.map_err(pool_error)?;
        let mut tx = connection.begin().await?;
        let device = fetch_managed_device_in_tx(&mut tx, scope, device_id).await?;
        tx.commit().await?;
        Ok(device)
    }

    pub async fn list_managed_devices(
        &self,
        scope: OwnerScope,
        filter: &DeviceListFilter,
    ) -> InventoryResult<(Vec<ManagedDevice>, i64)> {
        if filter.page < 1 || filter.page_size < 1 {
            return Err(InventoryError::Conflict("invalid_pagination".to_owned()));
        }
        let page_size = filter.page_size.min(200);
        let offset = filter
            .page
            .checked_sub(1)
            .and_then(|page| page.checked_mul(page_size))
            .ok_or(InventoryError::TooLarge)?;
        let mut connection = self.pool.get().await.map_err(pool_error)?;
        let mut tx = connection.begin().await?;

        let mut count_query =
            PortableQuery::new("SELECT COUNT(*) AS count FROM devices d WHERE 1 = 1");
        push_device_filters(&mut count_query, scope, filter);
        let total = count_query
            .fetch_one(&mut *tx)
            .await?
            .try_get::<i64, _>("count")?;

        let mut items_query = PortableQuery::new(format!(
            "SELECT {MANAGED_DEVICE_COLUMNS} FROM devices d WHERE 1 = 1"
        ));
        push_device_filters(&mut items_query, scope, filter);
        push_device_order(&mut items_query, filter.sort_by, filter.sort_dir);
        items_query.push(" LIMIT ");
        items_query.push_bind(page_size);
        items_query.push(" OFFSET ");
        items_query.push_bind(offset);
        let rows = items_query
            .fetch_all(&mut *tx)
            .await?
            .iter()
            .map(ManagedDeviceRow::from_row)
            .collect::<Result<Vec<_>, _>>()?;
        let row_ids = rows.iter().map(|row| row.row_id).collect::<Vec<_>>();
        let mut tags = fetch_tags_for_device_rows(&mut tx, &row_ids).await?;
        let devices = rows
            .into_iter()
            .map(|row| {
                let row_id = row.row_id;
                row.with_tags(tags.remove(&row_id).unwrap_or_default())
            })
            .collect();
        tx.commit().await?;
        Ok((devices, total))
    }

    pub async fn update_managed_device(
        &self,
        scope: OwnerScope,
        device_id: &str,
        update: &DeviceUpdate,
    ) -> InventoryResult<Option<ManagedDevice>> {
        let mut connection = self.pool.get().await.map_err(pool_error)?;
        let mut tx = connection.begin().await?;
        lock_inventory(&mut tx).await?;
        let Some(current) = fetch_device_row_in_tx(&mut tx, scope, device_id).await? else {
            return Ok(None);
        };

        let final_owner = update.owner_user_id.unwrap_or(current.owner_user_id);
        if !scope_allows_owner(scope, final_owner) {
            return Err(InventoryError::Conflict("owner_scope_mismatch".to_owned()));
        }
        let owner_changed = final_owner != current.owner_user_id;
        if owner_changed {
            if let Some(owner_user_id) = final_owner {
                let active = sqlx::query_scalar::<_, i64>(
                    "SELECT CAST(1 AS BIGINT) FROM users WHERE id = $1 AND is_active = TRUE",
                )
                .bind(owner_user_id)
                .fetch_optional(&mut tx)
                .await?
                .is_some();
                if !active {
                    return Err(InventoryError::NotFound);
                }
            }
            delete_device_memberships_in_tx(&mut tx, current.row_id)
                .await
                .map_err(address_book_error)?;
            sqlx::query("DELETE FROM device_tags WHERE device_row_id = $1")
                .bind(current.row_id)
                .execute(&mut tx)
                .await?;
        }

        let final_alias = match &update.alias {
            Some(value) => value.clone(),
            None if owner_changed => None,
            None => current.alias.clone(),
        };
        let alias_changed = final_alias != current.alias;
        let final_note = match &update.note {
            Some(value) => value.clone(),
            None if owner_changed => None,
            None => current.note.clone(),
        };
        let final_group = match update.group_id {
            Some(value) => value,
            None if owner_changed => None,
            None => current.group_id,
        };
        if let Some(group_id) = final_group {
            let Some(owner_user_id) = final_owner else {
                return Err(InventoryError::Conflict(
                    "device_group_owner_mismatch".to_owned(),
                ));
            };
            if fetch_group_in_tx(&mut tx, OwnerScope::Owner(owner_user_id), group_id)
                .await?
                .is_none()
            {
                if scope == OwnerScope::All
                    && fetch_group_in_tx(&mut tx, OwnerScope::All, group_id)
                        .await?
                        .is_some()
                {
                    return Err(InventoryError::Conflict(
                        "device_group_owner_mismatch".to_owned(),
                    ));
                }
                return Err(InventoryError::NotFound);
            }
        }

        sqlx::query(
            "UPDATE devices
             SET owner_user_id = $1, group_id = $2, alias = $3, note = $4,
                 updated_at = current_timestamp
             WHERE id = $5",
        )
        .bind(final_owner)
        .bind(final_group)
        .bind(final_alias)
        .bind(final_note)
        .bind(current.row_id)
        .execute(&mut tx)
        .await?;
        if owner_changed {
            delete_orphan_tags_in_tx(&mut tx).await?;
            if final_owner.is_some() {
                upsert_device_memberships_in_tx(&mut tx, current.row_id)
                    .await
                    .map_err(address_book_error)?;
            }
        } else if alias_changed {
            upsert_device_memberships_in_tx(&mut tx, current.row_id)
                .await
                .map_err(address_book_error)?;
        }
        let updated = fetch_managed_device_in_tx(&mut tx, OwnerScope::All, device_id).await?;
        tx.commit().await?;
        Ok(updated)
    }

    pub async fn list_tags(&self, scope: OwnerScope) -> InventoryResult<Vec<TagRecord>> {
        let mut connection = self.pool.get().await.map_err(pool_error)?;
        let tags = match scope {
            OwnerScope::All => {
                sqlx::query_as::<_, TagRecord>(
                    "SELECT id, owner_user_id, name, created_at, updated_at
                     FROM tags
                     ORDER BY owner_user_id, lower(name), id",
                )
                .fetch_all(connection.deref_mut())
                .await?
            }
            OwnerScope::Owner(owner_user_id) => {
                sqlx::query_as::<_, TagRecord>(
                    "SELECT id, owner_user_id, name, created_at, updated_at
                     FROM tags
                     WHERE owner_user_id = $1
                     ORDER BY lower(name), id",
                )
                .bind(owner_user_id)
                .fetch_all(connection.deref_mut())
                .await?
            }
        };
        Ok(tags)
    }

    pub async fn upsert_tag(&self, owner_user_id: i64, name: &str) -> InventoryResult<TagRecord> {
        let mut connection = self.pool.get().await.map_err(pool_error)?;
        let mut tx = connection.begin().await?;
        lock_inventory(&mut tx).await?;
        let tag = upsert_tag_in_tx(&mut tx, owner_user_id, name).await?;
        tx.commit().await?;
        Ok(tag)
    }

    pub async fn batch_update_device_tags(
        &self,
        scope: OwnerScope,
        device_ids: &[String],
        add_tags: &[String],
        remove_tags: &[String],
    ) -> InventoryResult<DeviceTagBatchOutcome> {
        let unique_device_ids = device_ids.iter().cloned().collect::<BTreeSet<_>>();
        let add_by_key = add_tags
            .iter()
            .map(|name| (name.to_ascii_lowercase(), name.clone()))
            .collect::<BTreeMap<_, _>>();
        let remove_by_key = remove_tags
            .iter()
            .map(|name| (name.to_ascii_lowercase(), name.clone()))
            .collect::<BTreeMap<_, _>>();
        if add_by_key.keys().any(|key| remove_by_key.contains_key(key)) {
            return Err(InventoryError::Conflict(
                "tag_add_remove_overlap".to_owned(),
            ));
        }
        if unique_device_ids.is_empty() {
            return Ok(DeviceTagBatchOutcome {
                devices: 0,
                added: 0,
                removed: 0,
            });
        }

        let mut connection = self.pool.get().await.map_err(pool_error)?;
        let mut tx = connection.begin().await?;
        lock_inventory(&mut tx).await?;

        let mut device_query = PortableQuery::new(
            "SELECT id, device_id, owner_user_id FROM devices WHERE device_id IN (",
        );
        device_query.push_bind_list(&unique_device_ids);
        device_query.push(")");
        if let OwnerScope::Owner(owner_user_id) = scope {
            device_query.push(" AND owner_user_id = ");
            device_query.push_bind(owner_user_id);
        }
        let device_rows = device_query.fetch_all(&mut *tx).await?;
        if device_rows.len() != unique_device_ids.len() {
            return Err(InventoryError::NotFound);
        }
        let mut devices = Vec::with_capacity(device_rows.len());
        for row in device_rows {
            let owner_user_id = row
                .try_get::<Option<i64>, _>("owner_user_id")?
                .ok_or_else(|| InventoryError::Conflict("device_tag_unowned_device".to_owned()))?;
            devices.push((
                row.try_get::<i64, _>("id")?,
                row.try_get::<String, _>("device_id")?,
                owner_user_id,
            ));
        }

        let device_row_ids = devices.iter().map(|device| device.0).collect::<Vec<_>>();
        let existing_tags = fetch_tags_for_device_rows(&mut tx, &device_row_ids).await?;
        for (row_id, _, _) in &devices {
            let mut final_tags = existing_tags
                .get(row_id)
                .into_iter()
                .flatten()
                .map(|name| name.to_ascii_lowercase())
                .collect::<BTreeSet<_>>();
            for key in remove_by_key.keys() {
                final_tags.remove(key);
            }
            final_tags.extend(add_by_key.keys().cloned());
            if final_tags.len() > MAX_DEVICE_TAGS {
                return Err(InventoryError::Conflict("device_tag_limit".to_owned()));
            }
        }

        let mut removed = 0;
        if !remove_by_key.is_empty() {
            let mut delete_query =
                PortableQuery::new("DELETE FROM device_tags WHERE device_row_id IN (");
            delete_query.push_bind_list(device_row_ids.iter().copied());
            delete_query.push(") AND tag_id IN (SELECT id FROM tags WHERE name IN (");
            delete_query.push_bind_list(remove_by_key.values());
            delete_query.push("))");
            removed = delete_query.execute(&mut *tx).await?.rows_affected();
        }

        let mut tag_ids = HashMap::<(i64, String), i64>::new();
        let owners = devices
            .iter()
            .map(|device| device.2)
            .collect::<BTreeSet<_>>();
        for owner_user_id in owners {
            for (key, name) in &add_by_key {
                let tag = upsert_tag_in_tx(&mut tx, owner_user_id, name).await?;
                tag_ids.insert((owner_user_id, key.clone()), tag.id);
            }
        }
        let mut added = 0;
        for (row_id, _, owner_user_id) in &devices {
            for key in add_by_key.keys() {
                let tag_id = tag_ids
                    .get(&(*owner_user_id, key.clone()))
                    .copied()
                    .ok_or_else(|| {
                        InventoryError::Internal("upserted tag disappeared".to_owned())
                    })?;
                added += sqlx::query(
                    "INSERT INTO device_tags(device_row_id, tag_id) VALUES($1, $2)
                     ON CONFLICT(device_row_id, tag_id) DO NOTHING",
                )
                .bind(row_id)
                .bind(tag_id)
                .execute(&mut tx)
                .await?
                .rows_affected();
            }
        }
        delete_orphan_tags_in_tx(&mut tx).await?;
        tx.commit().await?;
        Ok(DeviceTagBatchOutcome {
            devices: unique_device_ids.len() as u64,
            added,
            removed,
        })
    }
}

async fn delete_orphan_tags_in_tx(tx: &mut Transaction<'_, Any>) -> InventoryResult<()> {
    sqlx::query(
        "DELETE FROM tags
         WHERE NOT EXISTS (
             SELECT 1 FROM device_tags relation WHERE relation.tag_id = tags.id
         )",
    )
    .execute(&mut *tx)
    .await?;
    Ok(())
}

const DELETION_RECEIPT_COLUMNS: &str = "
    id,
    actor_user_id,
    device_id,
    management_generation,
    deleted_guid,
    state,
    attempt_count,
    next_attempt_at,
    lease_token,
    lease_until,
    completed_at,
    expires_at
";

async fn fetch_deletion_receipt_in_tx(
    tx: &mut Transaction<'_, Any>,
    actor_user_id: i64,
    device_id: &str,
    management_generation: &str,
) -> InventoryResult<Option<DeletionReceipt>> {
    let row = sqlx::query_as::<_, DeletionReceiptRow>(&format!(
        "SELECT {DELETION_RECEIPT_COLUMNS}
         FROM device_deletion_outbox
         WHERE actor_user_id = $1
           AND device_id = $2
           AND management_generation = $3
           AND (state = 'pending' OR expires_at > current_timestamp)"
    ))
    .bind(actor_user_id)
    .bind(device_id)
    .bind(management_generation)
    .fetch_optional(&mut *tx)
    .await?;
    row.map(TryInto::try_into).transpose()
}

fn receipt_outcome(receipt: DeletionReceipt) -> DeviceDeleteOutcome {
    match receipt.state {
        DeletionReceiptState::Pending => DeviceDeleteOutcome::Pending(receipt),
        DeletionReceiptState::Completed => DeviceDeleteOutcome::Completed,
    }
}

impl Database {
    pub async fn get_deletion_receipt(
        &self,
        actor_user_id: i64,
        device_id: &str,
        management_generation: &str,
    ) -> InventoryResult<Option<DeletionReceipt>> {
        let mut connection = self.pool.get().await.map_err(pool_error)?;
        let row = sqlx::query_as::<_, DeletionReceiptRow>(&format!(
            "SELECT {DELETION_RECEIPT_COLUMNS}
             FROM device_deletion_outbox
             WHERE actor_user_id = $1
               AND device_id = $2
               AND management_generation = $3
               AND (state = 'pending' OR expires_at > current_timestamp)"
        ))
        .bind(actor_user_id)
        .bind(device_id)
        .bind(management_generation)
        .fetch_optional(connection.deref_mut())
        .await?;
        row.map(TryInto::try_into).transpose()
    }

    pub async fn delete_managed_device(
        &self,
        actor_user_id: i64,
        scope: OwnerScope,
        device_id: &str,
        management_generation: &str,
    ) -> InventoryResult<DeviceDeleteOutcome> {
        self.delete_managed_device_with_hooks(
            actor_user_id,
            scope,
            device_id,
            management_generation,
            || async {},
            || async {},
        )
        .await
    }

    async fn delete_managed_device_with_hooks<B, Before, A, After>(
        &self,
        actor_user_id: i64,
        scope: OwnerScope,
        device_id: &str,
        management_generation: &str,
        before_lock: B,
        after_commit: A,
    ) -> InventoryResult<DeviceDeleteOutcome>
    where
        B: FnOnce() -> Before,
        Before: Future<Output = ()>,
        A: FnOnce() -> After,
        After: Future<Output = ()>,
    {
        if let Some(receipt) = self
            .get_deletion_receipt(actor_user_id, device_id, management_generation)
            .await?
        {
            return Ok(receipt_outcome(receipt));
        }

        let mut connection = self.pool.get().await.map_err(pool_error)?;
        let mut tx = connection.begin().await?;
        before_lock().await;
        lock_quota_then_inventory(&mut tx).await?;
        sqlx::query(
            "DELETE FROM device_deletion_outbox
             WHERE state = 'completed'
               AND expires_at IS NOT NULL
               AND expires_at <= current_timestamp",
        )
        .execute(&mut tx)
        .await?;
        if let Some(receipt) =
            fetch_deletion_receipt_in_tx(&mut tx, actor_user_id, device_id, management_generation)
                .await?
        {
            return Ok(receipt_outcome(receipt));
        }

        let mut candidate_query = PortableQuery::new(
            "SELECT id, management_generation FROM devices d WHERE d.device_id = ",
        );
        candidate_query.push_bind(device_id);
        push_device_scope(&mut candidate_query, scope);
        let Some(candidate) = candidate_query.fetch_optional(&mut *tx).await? else {
            return Ok(DeviceDeleteOutcome::ScopedMiss);
        };
        let row_id = candidate.try_get::<i64, _>("id")?;
        if candidate.try_get::<String, _>("management_generation")? != management_generation {
            return Ok(DeviceDeleteOutcome::GenerationMismatch);
        }

        let outbox_count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM device_deletion_outbox")
                .fetch_one(&mut tx)
                .await?;
        if outbox_count >= DELETION_OUTBOX_CAPACITY {
            return Ok(DeviceDeleteOutcome::CapacityFull);
        }

        delete_device_memberships_in_tx(&mut tx, row_id)
            .await
            .map_err(address_book_error)?;

        let mut delete_query = PortableQuery::new("DELETE FROM devices WHERE id = ");
        delete_query.push_bind(row_id);
        delete_query.push(" AND device_id = ");
        delete_query.push_bind(device_id);
        delete_query.push(" AND management_generation = ");
        delete_query.push_bind(management_generation);
        match scope {
            OwnerScope::All => {}
            OwnerScope::Owner(owner_user_id) => {
                delete_query.push(" AND owner_user_id = ");
                delete_query.push_bind(owner_user_id);
            }
        }
        delete_query.push(" RETURNING guid, device_id, management_generation, owner_user_id");
        let Some(deleted) = delete_query.fetch_optional(&mut *tx).await? else {
            return Ok(DeviceDeleteOutcome::ScopedMiss);
        };
        let deleted_guid = deleted.try_get::<Vec<u8>, _>("guid")?;
        delete_orphan_tags_in_tx(&mut tx).await?;
        let receipt_row = sqlx::query_as::<_, DeletionReceiptRow>(&format!(
            "INSERT INTO device_deletion_outbox(
                 actor_user_id, device_id, management_generation, deleted_guid
             )
             VALUES($1, $2, $3, $4)
             RETURNING {DELETION_RECEIPT_COLUMNS}"
        ))
        .bind(actor_user_id)
        .bind(device_id)
        .bind(management_generation)
        .bind(deleted_guid)
        .fetch_one(&mut tx)
        .await?;
        let receipt = receipt_row.try_into()?;
        tx.commit().await?;
        drop(connection);
        after_commit().await;
        Ok(DeviceDeleteOutcome::DeletedAndPending(receipt))
    }

    pub async fn claim_deletion_receipt(
        &self,
        actor_user_id: i64,
        device_id: &str,
        management_generation: &str,
        lease_seconds: i64,
    ) -> InventoryResult<Option<DeletionReceipt>> {
        let lease_seconds = lease_seconds.max(1);
        let lease_until = Utc::now().naive_utc() + ChronoDuration::seconds(lease_seconds);
        let lease_token = uuid::Uuid::new_v4().simple().to_string();
        let mut connection = self.pool.get().await.map_err(pool_error)?;
        let row = sqlx::query_as::<_, DeletionReceiptRow>(&format!(
            "UPDATE device_deletion_outbox
             SET lease_token = $1,
                 lease_until = $2,
                 attempt_count = attempt_count + 1,
                 updated_at = current_timestamp
             WHERE actor_user_id = $3
               AND device_id = $4
               AND management_generation = $5
               AND state = 'pending'
               AND next_attempt_at <= current_timestamp
               AND (lease_until IS NULL OR lease_until <= current_timestamp)
             RETURNING {DELETION_RECEIPT_COLUMNS}"
        ))
        .bind(lease_token)
        .bind(lease_until)
        .bind(actor_user_id)
        .bind(device_id)
        .bind(management_generation)
        .fetch_optional(connection.deref_mut())
        .await?;
        row.map(TryInto::try_into).transpose()
    }

    pub async fn claim_due_deletion_receipts(
        &self,
        limit: i64,
        lease_seconds: i64,
    ) -> InventoryResult<Vec<DeletionReceipt>> {
        let limit = limit.clamp(1, MAX_DISPATCH_BATCH);
        let lease_seconds = lease_seconds.max(1);
        let mut connection = self.pool.get().await.map_err(pool_error)?;
        let mut receipts = Vec::with_capacity(limit as usize);
        for _ in 0..limit {
            let lease_token = uuid::Uuid::new_v4().simple().to_string();
            let lease_until = Utc::now().naive_utc() + ChronoDuration::seconds(lease_seconds);
            let row = sqlx::query_as::<_, DeletionReceiptRow>(&format!(
                "UPDATE device_deletion_outbox
                 SET lease_token = $1,
                     lease_until = $2,
                     attempt_count = attempt_count + 1,
                     updated_at = current_timestamp
                 WHERE id = (
                     SELECT id
                     FROM device_deletion_outbox
                     WHERE state = 'pending'
                       AND next_attempt_at <= current_timestamp
                       AND (lease_until IS NULL OR lease_until <= current_timestamp)
                     ORDER BY next_attempt_at, id
                     LIMIT 1
                 )
                   AND state = 'pending'
                   AND next_attempt_at <= current_timestamp
                   AND (lease_until IS NULL OR lease_until <= current_timestamp)
                 RETURNING {DELETION_RECEIPT_COLUMNS}"
            ))
            .bind(lease_token)
            .bind(lease_until)
            .fetch_optional(connection.deref_mut())
            .await?;
            let Some(row) = row else {
                break;
            };
            receipts.push(row.try_into()?);
        }
        Ok(receipts)
    }

    pub async fn complete_deletion_receipt(
        &self,
        receipt_id: i64,
        lease_token: &str,
        completed_ttl_seconds: i64,
    ) -> InventoryResult<bool> {
        let completed_ttl_seconds = completed_ttl_seconds.max(1);
        let expires_at = Utc::now().naive_utc() + ChronoDuration::seconds(completed_ttl_seconds);
        let mut connection = self.pool.get().await.map_err(pool_error)?;
        let affected = sqlx::query(
            "UPDATE device_deletion_outbox
             SET state = 'completed',
                 completed_at = current_timestamp,
                 expires_at = $1,
                 lease_token = NULL,
                 lease_until = NULL,
                 updated_at = current_timestamp
             WHERE id = $2
               AND state = 'pending'
               AND lease_token = $3",
        )
        .bind(expires_at)
        .bind(receipt_id)
        .bind(lease_token)
        .execute(connection.deref_mut())
        .await?;
        Ok(affected.rows_affected() == 1)
    }

    pub async fn fail_deletion_receipt(
        &self,
        receipt_id: i64,
        lease_token: &str,
        retry_after_seconds: i64,
    ) -> InventoryResult<bool> {
        let retry_after_seconds = retry_after_seconds.max(1);
        let next_attempt_at = Utc::now().naive_utc() + ChronoDuration::seconds(retry_after_seconds);
        let mut connection = self.pool.get().await.map_err(pool_error)?;
        let affected = sqlx::query(
            "UPDATE device_deletion_outbox
             SET next_attempt_at = $1,
                 lease_token = NULL,
                 lease_until = NULL,
                 updated_at = current_timestamp
             WHERE id = $2
               AND state = 'pending'
               AND lease_token = $3",
        )
        .bind(next_attempt_at)
        .bind(receipt_id)
        .bind(lease_token)
        .execute(connection.deref_mut())
        .await?;
        Ok(affected.rows_affected() == 1)
    }
}

pub(super) async fn verify_inventory_integrity(tx: &mut Transaction<'_, Any>) -> ResultType<()> {
    if let Some(row) = sqlx::query(
        "SELECT child.id
         FROM groups child
         LEFT JOIN groups parent ON parent.id = child.parent_group_id
         WHERE child.parent_group_id IS NOT NULL AND parent.id IS NULL
         LIMIT 1",
    )
    .fetch_optional(&mut *tx)
    .await?
    {
        bail!(
            "inventory integrity error: group {} has an orphan parent",
            row.try_get::<i64, _>("id")?
        );
    }
    if let Some(row) = sqlx::query(
        "SELECT child.id
         FROM groups child
         JOIN groups parent ON parent.id = child.parent_group_id
         WHERE child.owner_user_id <> parent.owner_user_id
         LIMIT 1",
    )
    .fetch_optional(&mut *tx)
    .await?
    {
        bail!(
            "inventory integrity error: group {} has a cross-owner parent",
            row.try_get::<i64, _>("id")?
        );
    }
    if let Some(row) = sqlx::query(
        "WITH RECURSIVE ancestors(start_id, id) AS (
             SELECT id, parent_group_id
             FROM groups
             WHERE parent_group_id IS NOT NULL
             UNION
             SELECT ancestors.start_id, parent.parent_group_id
             FROM ancestors
             JOIN groups parent ON parent.id = ancestors.id
             WHERE parent.parent_group_id IS NOT NULL
         )
         SELECT start_id
         FROM ancestors
         WHERE start_id = id
         LIMIT 1",
    )
    .fetch_optional(&mut *tx)
    .await?
    {
        bail!(
            "inventory integrity error: group {} participates in a cycle",
            row.try_get::<i64, _>("start_id")?
        );
    }
    if let Some(row) = sqlx::query(
        "WITH RECURSIVE ancestors(start_id, id, depth) AS (
             SELECT id, id, 1 FROM groups
             UNION ALL
             SELECT ancestors.start_id, parent.parent_group_id, ancestors.depth + 1
             FROM ancestors
             JOIN groups parent ON parent.id = ancestors.id
             WHERE parent.parent_group_id IS NOT NULL
               AND ancestors.depth <= 256
         )
         SELECT start_id
         FROM ancestors
         WHERE depth > 256
         LIMIT 1",
    )
    .fetch_optional(&mut *tx)
    .await?
    {
        bail!(
            "inventory integrity error: group {} exceeds depth 256",
            row.try_get::<i64, _>("start_id")?
        );
    }
    if let Some(row) = sqlx::query(
        "SELECT device.id
         FROM devices device
         JOIN groups grouped ON grouped.id = device.group_id
         WHERE device.owner_user_id IS NULL
            OR device.owner_user_id <> grouped.owner_user_id
         LIMIT 1",
    )
    .fetch_optional(&mut *tx)
    .await?
    {
        bail!(
            "inventory integrity error: device row {} has a cross-owner group",
            row.try_get::<i64, _>("id")?
        );
    }
    if let Some(row) = sqlx::query(
        "SELECT id
         FROM devices
         WHERE management_generation IS NULL
            OR length(management_generation) <> 32
            OR management_generation <> lower(management_generation)
            OR management_generation GLOB '*[^0-9a-f]*'
         LIMIT 1",
    )
    .fetch_optional(&mut *tx)
    .await?
    {
        bail!(
            "inventory integrity error: device row {} has an invalid management generation",
            row.try_get::<i64, _>("id")?
        );
    }
    if let Some(row) = sqlx::query(
        "SELECT management_generation
         FROM devices
         GROUP BY management_generation
         HAVING COUNT(*) > 1
         LIMIT 1",
    )
    .fetch_optional(&mut *tx)
    .await?
    {
        bail!(
            "inventory integrity error: duplicate management generation {}",
            row.try_get::<String, _>("management_generation")?
        );
    }
    if let Some(row) = sqlx::query(
        "SELECT relation.device_row_id, relation.tag_id
         FROM device_tags relation
         JOIN devices device ON device.id = relation.device_row_id
         JOIN tags tag ON tag.id = relation.tag_id
         WHERE device.owner_user_id IS NULL
            OR device.owner_user_id <> tag.owner_user_id
         LIMIT 1",
    )
    .fetch_optional(&mut *tx)
    .await?
    {
        bail!(
            "inventory integrity error: device_tag ({}, {}) crosses owners",
            row.try_get::<i64, _>("device_row_id")?,
            row.try_get::<i64, _>("tag_id")?
        );
    }
    if let Some(row) = sqlx::query("PRAGMA foreign_key_check")
        .fetch_optional(&mut *tx)
        .await?
    {
        let table = row.try_get::<String, _>("table")?;
        let row_id = row.try_get::<Option<i64>, _>("rowid")?;
        bail!(
            "inventory integrity error: foreign key violation in {} row {:?}",
            table,
            row_id
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        future::Future,
        path::Path,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn run<F>(future: F)
    where
        F: Future<Output = ()>,
    {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(future);
    }

    fn temp_db_path(label: &str) -> String {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir()
            .join(format!("hbbs-inventory-{label}-{unique}.db"))
            .to_string_lossy()
            .into_owned()
    }

    fn cleanup(path: &str) {
        for candidate in [
            path.to_owned(),
            format!("{path}-wal"),
            format!("{path}-shm"),
            format!("{path}.migration.lock"),
        ] {
            if Path::new(&candidate).exists() {
                let _ = std::fs::remove_file(candidate);
            }
        }
    }

    async fn create_user(db: &Database, username: &str) -> i64 {
        db.create_user(username, "test-password-hash", None, "user")
            .await
            .unwrap()
            .id
    }

    async fn insert_device(
        db: &Database,
        device_id: &str,
        owner_user_id: Option<i64>,
    ) -> (Vec<u8>, String) {
        let guid = uuid::Uuid::new_v4().as_bytes().to_vec();
        let mut connection = db.pool.get().await.unwrap();
        sqlx::query(
            "INSERT INTO devices(
                 guid, uuid, pk, device_id, info, status, last_seen
             )
             VALUES($1, $2, $3, $4, '{}', 'offline', current_timestamp)",
        )
        .bind(&guid)
        .bind(b"test-uuid".as_slice())
        .bind(b"test-public-key".as_slice())
        .bind(device_id)
        .execute(connection.deref_mut())
        .await
        .unwrap();
        let generation = sqlx::query_scalar::<_, String>(
            "SELECT management_generation FROM devices WHERE device_id = $1",
        )
        .bind(device_id)
        .fetch_one(connection.deref_mut())
        .await
        .unwrap();
        drop(connection);
        if let Some(owner_user_id) = owner_user_id {
            db.update_managed_device(
                OwnerScope::All,
                device_id,
                &DeviceUpdate {
                    owner_user_id: Some(Some(owner_user_id)),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        }
        (guid, generation)
    }

    #[test]
    fn migration_generates_immutable_generation_and_enables_foreign_keys() {
        run(async {
            let path = temp_db_path("migration");
            let db = Database::new(&path).await.unwrap();
            let owner = create_user(&db, "migration-owner").await;
            let (_, generation) = insert_device(&db, "migration-device", Some(owner)).await;
            assert_eq!(generation.len(), 32);
            assert!(generation
                .chars()
                .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase()));

            let mut connection = db.pool.get().await.unwrap();
            let foreign_keys = sqlx::query_scalar::<_, i64>("PRAGMA foreign_keys")
                .fetch_one(connection.deref_mut())
                .await
                .unwrap();
            assert_eq!(foreign_keys, 1);
            let replacement = "0123456789abcdef0123456789abcdef";
            let error =
                sqlx::query("UPDATE devices SET management_generation = $1 WHERE device_id = $2")
                    .bind(replacement)
                    .bind("migration-device")
                    .execute(connection.deref_mut())
                    .await
                    .unwrap_err();
            assert!(error
                .to_string()
                .contains("device_management_generation_immutable"));
            let mut parent_group_id = None;
            for depth in 1..=256 {
                let inserted = sqlx::query_scalar::<_, i64>(
                    "INSERT INTO groups(name, owner_user_id, parent_group_id)
                     VALUES($1, $2, $3)
                     RETURNING id",
                )
                .bind(format!("depth-{depth}"))
                .bind(owner)
                .bind(parent_group_id)
                .fetch_one(connection.deref_mut())
                .await
                .unwrap();
                parent_group_id = Some(inserted);
            }
            let depth_error = sqlx::query(
                "INSERT INTO groups(name, owner_user_id, parent_group_id)
                 VALUES('depth-257', $1, $2)",
            )
            .bind(owner)
            .bind(parent_group_id)
            .execute(connection.deref_mut())
            .await
            .unwrap_err();
            assert!(depth_error.to_string().contains("group_depth_exceeded"));
            drop(connection);
            drop(db);
            cleanup(&path);
        });
    }

    #[test]
    fn groups_are_scoped_cycle_safe_and_force_delete_only_ungroups_devices() {
        run(async {
            let path = temp_db_path("groups");
            let db = Database::new(&path).await.unwrap();
            let owner = create_user(&db, "group-owner").await;
            let other_owner = create_user(&db, "group-other").await;
            let other_group = db
                .create_group(OwnerScope::Owner(other_owner), other_owner, "Other", None)
                .await
                .unwrap();
            db.deactivate_user(other_owner).await.unwrap();
            assert_eq!(
                db.create_group(OwnerScope::All, other_owner, "Inactive owner", None)
                    .await,
                Err(InventoryError::NotFound)
            );
            let root = db
                .create_group(OwnerScope::Owner(owner), owner, "Root", None)
                .await
                .unwrap();
            let child = db
                .create_group(OwnerScope::Owner(owner), owner, "Child", Some(root.id))
                .await
                .unwrap();
            let grandchild = db
                .create_group(
                    OwnerScope::Owner(owner),
                    owner,
                    "Grandchild",
                    Some(child.id),
                )
                .await
                .unwrap();
            let cycle = db
                .update_group(
                    OwnerScope::Owner(owner),
                    root.id,
                    &GroupUpdate {
                        name: None,
                        parent_group_id: Some(Some(grandchild.id)),
                    },
                )
                .await;
            assert_eq!(
                cycle,
                Err(InventoryError::Conflict("group_cycle".to_owned()))
            );
            assert!(db
                .get_group(OwnerScope::Owner(other_owner), root.id)
                .await
                .unwrap()
                .is_none());

            insert_device(&db, "group-device", Some(owner)).await;
            {
                let mut connection = db.pool.get().await.unwrap();
                let error = sqlx::query(
                    "UPDATE devices SET group_id = $1 WHERE device_id = 'group-device'",
                )
                .bind(other_group.id)
                .execute(connection.deref_mut())
                .await
                .unwrap_err();
                assert!(error.to_string().contains("device_group_owner_mismatch"));
            }
            let batch = db
                .add_devices_to_group(
                    OwnerScope::Owner(owner),
                    grandchild.id,
                    &["group-device".to_owned()],
                )
                .await
                .unwrap();
            assert_eq!(batch.matched, 1);
            assert_eq!(batch.changed, 1);
            assert_eq!(
                db.delete_group(OwnerScope::Owner(owner), root.id)
                    .await
                    .unwrap(),
                GroupDeleteOutcome::NotEmpty
            );

            let forced = db
                .force_delete_group(OwnerScope::Owner(owner), root.id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(forced.deleted_groups, 3);
            assert_eq!(forced.ungrouped_devices, 1);
            let device = db
                .get_managed_device(OwnerScope::Owner(owner), "group-device")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(device.group_id, None);
            drop(db);
            cleanup(&path);
        });
    }

    #[test]
    fn oversized_group_subtree_update_rolls_back() {
        run(async {
            let path = temp_db_path("group-update-too-large");
            let db = Database::new(&path).await.unwrap();
            let owner = create_user(&db, "large-group-owner").await;
            let root = db
                .create_group(OwnerScope::Owner(owner), owner, "Original", None)
                .await
                .unwrap();
            {
                let mut connection = db.pool.get().await.unwrap();
                sqlx::query(
                    "WITH digits(value) AS (
                         VALUES(0),(1),(2),(3),(4),(5),(6),(7),(8),(9)
                     )
                     INSERT INTO groups(name, owner_user_id, parent_group_id)
                     SELECT printf(
                                'child-%05d',
                                thousands.value * 1000
                                  + hundreds.value * 100
                                  + tens.value * 10
                                  + ones.value
                            ),
                            $1, $2
                     FROM digits thousands
                     CROSS JOIN digits hundreds
                     CROSS JOIN digits tens
                     CROSS JOIN digits ones",
                )
                .bind(owner)
                .bind(root.id)
                .execute(connection.deref_mut())
                .await
                .unwrap();
            }

            assert_eq!(
                db.update_group(
                    OwnerScope::Owner(owner),
                    root.id,
                    &GroupUpdate {
                        name: Some("Changed".to_owned()),
                        parent_group_id: None,
                    },
                )
                .await,
                Err(InventoryError::TooLarge)
            );
            let unchanged = db
                .get_group(OwnerScope::Owner(owner), root.id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(unchanged.name, "Original");
            drop(db);
            cleanup(&path);
        });
    }

    #[test]
    fn tag_batch_and_owner_transfer_are_atomic() {
        run(async {
            let path = temp_db_path("tags");
            let db = Database::new(&path).await.unwrap();
            let owner = create_user(&db, "tag-owner").await;
            let new_owner = create_user(&db, "tag-new-owner").await;
            insert_device(&db, "tag-device", Some(owner)).await;
            insert_device(&db, "tag-second", Some(owner)).await;
            db.update_managed_device(
                OwnerScope::Owner(owner),
                "tag-device",
                &DeviceUpdate {
                    alias: Some(Some("Front%_Desk".to_owned())),
                    ..DeviceUpdate::default()
                },
            )
            .await
            .unwrap();

            let result = db
                .batch_update_device_tags(
                    OwnerScope::Owner(owner),
                    &["tag-device".to_owned()],
                    &["Production".to_owned(), "Linux".to_owned()],
                    &[],
                )
                .await
                .unwrap();
            assert_eq!(result.devices, 1);
            assert_eq!(result.added, 2);
            let tagged = db
                .get_managed_device(OwnerScope::Owner(owner), "tag-device")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(tagged.tags, vec!["Linux", "Production"]);
            db.batch_update_device_tags(
                OwnerScope::Owner(owner),
                &["tag-second".to_owned()],
                &["Testing".to_owned()],
                &[],
            )
            .await
            .unwrap();
            let (production, production_total) = db
                .list_managed_devices(
                    OwnerScope::Owner(owner),
                    &DeviceListFilter {
                        tag: Some("production".to_owned()),
                        page: 1,
                        page_size: 1,
                        ..DeviceListFilter::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(production_total, 1);
            assert_eq!(production.len(), 1);
            assert_eq!(production[0].device_id, "tag-device");
            let (literal_search, literal_total) = db
                .list_managed_devices(
                    OwnerScope::Owner(owner),
                    &DeviceListFilter {
                        query: Some("%_".to_owned()),
                        page: 1,
                        page_size: 50,
                        ..DeviceListFilter::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(literal_total, 1);
            assert_eq!(literal_search[0].device_id, "tag-device");
            let (first_page, total) = db
                .list_managed_devices(
                    OwnerScope::Owner(owner),
                    &DeviceListFilter {
                        page: 1,
                        page_size: 1,
                        ..DeviceListFilter::default()
                    },
                )
                .await
                .unwrap();
            let (second_page, second_total) = db
                .list_managed_devices(
                    OwnerScope::Owner(owner),
                    &DeviceListFilter {
                        page: 2,
                        page_size: 1,
                        ..DeviceListFilter::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(total, 2);
            assert_eq!(second_total, 2);
            assert_eq!(first_page.len(), 1);
            assert_eq!(second_page.len(), 1);
            assert_ne!(first_page[0].device_id, second_page[0].device_id);
            let removed = db
                .batch_update_device_tags(
                    OwnerScope::Owner(owner),
                    &["tag-device".to_owned()],
                    &[],
                    &["linux".to_owned()],
                )
                .await
                .unwrap();
            assert_eq!(removed.removed, 1);

            let transferred = db
                .update_managed_device(
                    OwnerScope::All,
                    "tag-device",
                    &DeviceUpdate {
                        alias: None,
                        note: None,
                        group_id: None,
                        owner_user_id: Some(Some(new_owner)),
                    },
                )
                .await
                .unwrap()
                .unwrap();
            assert_eq!(transferred.owner_user_id, Some(new_owner));
            assert!(transferred.tags.is_empty());
            assert_eq!(transferred.alias, None);
            assert!(db
                .get_managed_device(OwnerScope::Owner(owner), "tag-device")
                .await
                .unwrap()
                .is_none());
            let tag_count = {
                let mut connection = db.pool.get().await.unwrap();
                sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM tags")
                    .fetch_one(connection.deref_mut())
                    .await
                    .unwrap()
            };
            assert_eq!(tag_count, 1);
            drop(db);
            cleanup(&path);
        });
    }

    #[test]
    fn delete_and_pending_receipt_commit_together_and_lease_is_fenced() {
        run(async {
            let path = temp_db_path("outbox");
            let db = Database::new(&path).await.unwrap();
            let owner = create_user(&db, "delete-owner").await;
            let (_, generation) = insert_device(&db, "delete-device", Some(owner)).await;

            let deleted = db
                .delete_managed_device(
                    owner,
                    OwnerScope::Owner(owner),
                    "delete-device",
                    &generation,
                )
                .await
                .unwrap();
            let receipt = match deleted {
                DeviceDeleteOutcome::DeletedAndPending(receipt) => receipt,
                other => panic!("unexpected delete outcome: {other:?}"),
            };
            assert_eq!(receipt.state, DeletionReceiptState::Pending);
            assert!(db
                .get_managed_device(OwnerScope::Owner(owner), "delete-device")
                .await
                .unwrap()
                .is_none());
            assert!(matches!(
                db.delete_managed_device(
                    owner,
                    OwnerScope::Owner(owner),
                    "delete-device",
                    &generation,
                )
                .await
                .unwrap(),
                DeviceDeleteOutcome::Pending(_)
            ));
            let (_, new_generation) = insert_device(&db, "delete-device", Some(owner)).await;
            assert_ne!(new_generation, generation);
            assert!(matches!(
                db.delete_managed_device(
                    owner,
                    OwnerScope::Owner(owner),
                    "delete-device",
                    &generation,
                )
                .await
                .unwrap(),
                DeviceDeleteOutcome::Pending(_)
            ));
            let current = db
                .get_managed_device(OwnerScope::Owner(owner), "delete-device")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(current.management_generation, new_generation);

            let claimed = db
                .claim_deletion_receipt(owner, "delete-device", &generation, 5)
                .await
                .unwrap()
                .unwrap();
            let lease_token = claimed.lease_token.clone().unwrap();
            assert!(db
                .claim_deletion_receipt(owner, "delete-device", &generation, 5)
                .await
                .unwrap()
                .is_none());
            assert!(!db
                .complete_deletion_receipt(claimed.id, "stale-token", 300)
                .await
                .unwrap());
            assert!(db
                .complete_deletion_receipt(claimed.id, &lease_token, 300)
                .await
                .unwrap());
            assert!(matches!(
                db.delete_managed_device(
                    owner,
                    OwnerScope::Owner(owner),
                    "delete-device",
                    &generation,
                )
                .await
                .unwrap(),
                DeviceDeleteOutcome::Completed
            ));
            assert!(matches!(
                db.delete_managed_device(
                    owner,
                    OwnerScope::Owner(owner),
                    "delete-device",
                    &generation,
                )
                .await
                .unwrap(),
                DeviceDeleteOutcome::Completed
            ));
            assert!(db
                .get_managed_device(OwnerScope::Owner(owner), "delete-device")
                .await
                .unwrap()
                .is_some());

            {
                let mut connection = db.pool.get().await.unwrap();
                sqlx::query(
                    "WITH RECURSIVE sequence(value) AS (
                         SELECT 1
                         UNION ALL
                         SELECT value + 1 FROM sequence WHERE value < 4095
                     )
                     INSERT INTO device_deletion_outbox(
                         actor_user_id, device_id, management_generation, deleted_guid
                     )
                     SELECT $1, 'capacity-' || value, printf('%032x', value), randomblob(16)
                     FROM sequence",
                )
                .bind(owner)
                .execute(connection.deref_mut())
                .await
                .unwrap();
            }
            assert!(matches!(
                db.delete_managed_device(
                    owner,
                    OwnerScope::Owner(owner),
                    "delete-device",
                    &new_generation,
                )
                .await
                .unwrap(),
                DeviceDeleteOutcome::CapacityFull
            ));
            assert!(db
                .get_managed_device(OwnerScope::Owner(owner), "delete-device")
                .await
                .unwrap()
                .is_some());
            drop(db);
            cleanup(&path);
        });
    }

    #[test]
    fn concurrent_same_key_delete_creates_exactly_one_durable_receipt() {
        run(async {
            let path = temp_db_path("outbox-concurrent");
            let db = Database::new(&path).await.unwrap();
            let second_db = Database::new(&path).await.unwrap();
            let owner = create_user(&db, "concurrent-delete-owner").await;
            let (_, generation) = insert_device(&db, "concurrent-delete-device", Some(owner)).await;

            let first_database = db.clone();
            let first_generation = generation.clone();
            let first = tokio::spawn(async move {
                first_database
                    .delete_managed_device(
                        owner,
                        OwnerScope::Owner(owner),
                        "concurrent-delete-device",
                        &first_generation,
                    )
                    .await
            });
            let second_generation = generation.clone();
            let second = tokio::spawn(async move {
                second_db
                    .delete_managed_device(
                        owner,
                        OwnerScope::Owner(owner),
                        "concurrent-delete-device",
                        &second_generation,
                    )
                    .await
            });
            let outcomes = [first.await.unwrap(), second.await.unwrap()];
            let mut committed = 0;
            for outcome in outcomes {
                match outcome {
                    Ok(DeviceDeleteOutcome::DeletedAndPending(_)) => committed += 1,
                    Ok(DeviceDeleteOutcome::Pending(_)) => {}
                    Err(InventoryError::Busy) => {
                        assert!(matches!(
                            db.delete_managed_device(
                                owner,
                                OwnerScope::Owner(owner),
                                "concurrent-delete-device",
                                &generation,
                            )
                            .await
                            .unwrap(),
                            DeviceDeleteOutcome::Pending(_)
                        ));
                    }
                    other => panic!("unexpected concurrent delete outcome: {other:?}"),
                }
            }
            assert_eq!(committed, 1);
            let mut connection = db.pool.get().await.unwrap();
            let receipt_count = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM device_deletion_outbox
                 WHERE actor_user_id = $1
                   AND device_id = $2
                   AND management_generation = $3",
            )
            .bind(owner)
            .bind("concurrent-delete-device")
            .bind(&generation)
            .fetch_one(connection.deref_mut())
            .await
            .unwrap();
            assert_eq!(receipt_count, 1);
            drop(connection);
            drop(db);
            cleanup(&path);
        });
    }

    #[test]
    fn concurrent_claims_are_fenced_to_one_worker() {
        run(async {
            let path = temp_db_path("outbox-claim");
            let db = Database::new(&path).await.unwrap();
            let second_db = Database::new(&path).await.unwrap();
            let owner = create_user(&db, "claim-owner").await;
            let (_, generation) = insert_device(&db, "claim-device", Some(owner)).await;
            assert!(matches!(
                db.delete_managed_device(
                    owner,
                    OwnerScope::Owner(owner),
                    "claim-device",
                    &generation,
                )
                .await
                .unwrap(),
                DeviceDeleteOutcome::DeletedAndPending(_)
            ));

            let first_database = db.clone();
            let first_generation = generation.clone();
            let first = tokio::spawn(async move {
                first_database
                    .claim_deletion_receipt(owner, "claim-device", &first_generation, 5)
                    .await
            });
            let second_generation = generation.clone();
            let second = tokio::spawn(async move {
                second_db
                    .claim_deletion_receipt(owner, "claim-device", &second_generation, 5)
                    .await
            });
            let outcomes = [first.await.unwrap(), second.await.unwrap()];
            let mut claimed = Vec::new();
            for outcome in outcomes {
                match outcome {
                    Ok(Some(receipt)) => claimed.push(receipt),
                    Ok(None) => {}
                    Err(InventoryError::Busy) => {
                        assert!(db
                            .claim_deletion_receipt(owner, "claim-device", &generation, 5)
                            .await
                            .unwrap()
                            .is_none());
                    }
                    other => panic!("unexpected concurrent claim outcome: {other:?}"),
                }
            }
            assert_eq!(claimed.len(), 1);
            assert!(claimed[0].lease_token.is_some());
            assert_eq!(claimed[0].attempt_count, 1);
            let current = db
                .get_deletion_receipt(owner, "claim-device", &generation)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(current.attempt_count, 1);
            assert_eq!(current.lease_token, claimed[0].lease_token);
            drop(db);
            cleanup(&path);
        });
    }

    #[test]
    fn delete_and_owner_transfer_follow_one_inventory_linearization() {
        run(async {
            let path = temp_db_path("delete-owner-transfer");
            let db = Database::new(&path).await.unwrap();
            let owner = create_user(&db, "transfer-old-owner").await;
            let new_owner = create_user(&db, "transfer-new-owner").await;
            let (_, generation) = insert_device(&db, "transfer-device", Some(owner)).await;
            let deleting_database = Database::new(&path).await.unwrap();

            let mut holder = db.pool.get().await.unwrap();
            let mut transfer_tx = holder.begin().await.unwrap();
            lock_inventory(&mut transfer_tx).await.unwrap();
            let (entered_sender, entered_receiver) = tokio::sync::oneshot::channel();
            let (continue_sender, continue_receiver) = tokio::sync::oneshot::channel();
            let deleting_generation = generation.clone();
            let deleting = tokio::spawn(async move {
                deleting_database
                    .delete_managed_device_with_hooks(
                        owner,
                        OwnerScope::Owner(owner),
                        "transfer-device",
                        &deleting_generation,
                        move || async move {
                            let _ = entered_sender.send(());
                            let _ = continue_receiver.await;
                        },
                        || async {},
                    )
                    .await
            });
            entered_receiver.await.unwrap();
            sqlx::query(
                "UPDATE devices
                 SET owner_user_id = $1, updated_at = current_timestamp
                 WHERE device_id = 'transfer-device'",
            )
            .bind(new_owner)
            .execute(&mut transfer_tx)
            .await
            .unwrap();
            let _ = continue_sender.send(());
            tokio::task::yield_now().await;
            assert!(!deleting.is_finished());
            transfer_tx.commit().await.unwrap();
            drop(holder);
            assert!(matches!(
                deleting.await.unwrap().unwrap(),
                DeviceDeleteOutcome::ScopedMiss
            ));
            let transferred = db
                .get_managed_device(OwnerScope::Owner(new_owner), "transfer-device")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(transferred.owner_user_id, Some(new_owner));
            assert!(db
                .get_deletion_receipt(owner, "transfer-device", &generation)
                .await
                .unwrap()
                .is_none());

            let (_, delete_first_generation) =
                insert_device(&db, "delete-first-device", Some(owner)).await;
            assert!(matches!(
                db.delete_managed_device(
                    owner,
                    OwnerScope::Owner(owner),
                    "delete-first-device",
                    &delete_first_generation,
                )
                .await
                .unwrap(),
                DeviceDeleteOutcome::DeletedAndPending(_)
            ));
            assert!(db
                .update_managed_device(
                    OwnerScope::All,
                    "delete-first-device",
                    &DeviceUpdate {
                        owner_user_id: Some(Some(new_owner)),
                        ..DeviceUpdate::default()
                    },
                )
                .await
                .unwrap()
                .is_none());
            drop(db);
            cleanup(&path);
        });
    }

    #[test]
    fn committed_delete_and_pending_receipt_survive_handler_cancellation() {
        run(async {
            let path = temp_db_path("outbox-cancel-after-commit");
            let db = Database::new(&path).await.unwrap();
            let observer = Database::new(&path).await.unwrap();
            let owner = create_user(&db, "cancel-delete-owner").await;
            let (_, generation) = insert_device(&db, "cancel-delete-device", Some(owner)).await;
            let (committed_sender, committed_receiver) = tokio::sync::oneshot::channel();
            let deleting_database = db.clone();
            let deleting_generation = generation.clone();
            let deleting = tokio::spawn(async move {
                deleting_database
                    .delete_managed_device_with_hooks(
                        owner,
                        OwnerScope::Owner(owner),
                        "cancel-delete-device",
                        &deleting_generation,
                        || async {},
                        move || async move {
                            let _ = committed_sender.send(());
                            std::future::pending::<()>().await;
                        },
                    )
                    .await
            });
            committed_receiver.await.unwrap();
            deleting.abort();
            let _ = deleting.await;

            assert!(observer
                .get_managed_device(OwnerScope::Owner(owner), "cancel-delete-device")
                .await
                .unwrap()
                .is_none());
            let receipt = observer
                .get_deletion_receipt(owner, "cancel-delete-device", &generation)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(receipt.state, DeletionReceiptState::Pending);
            drop(observer);
            drop(db);
            cleanup(&path);
        });
    }

    #[test]
    fn heartbeat_requires_the_expected_guid() {
        run(async {
            let path = temp_db_path("heartbeat-guid");
            let db = Database::new(&path).await.unwrap();
            let owner = create_user(&db, "heartbeat-owner").await;
            let (guid, _) = insert_device(&db, "heartbeat-device", Some(owner)).await;
            assert!(!db
                .touch_admitted_device("heartbeat-device", b"wrong-generation")
                .await
                .unwrap());
            assert!(db
                .touch_admitted_device("heartbeat-device", &guid)
                .await
                .unwrap());
            drop(db);
            cleanup(&path);
        });
    }
}
