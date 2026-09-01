use crate::common::*;
use crate::database;
use hbb_common::{
    bytes::Bytes,
    log,
    tokio::sync::{mpsc, oneshot, Mutex, RwLock},
    ResultType,
};
use serde_derive::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    collections::HashSet,
    future::Future,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex as StdMutex,
    },
    time::{Duration, Instant},
};

type IpBlockMap = HashMap<String, ((u32, Instant), (HashSet<String>, Instant))>;
type UserStatusMap = HashMap<Vec<u8>, Arc<(Option<Vec<u8>>, bool)>>;
type IpChangesMap = HashMap<String, (Instant, HashMap<String, i32>)>;
lazy_static::lazy_static! {
    pub(crate) static ref IP_BLOCKER: Mutex<IpBlockMap> = Default::default();
    pub(crate) static ref USER_STATUS: RwLock<UserStatusMap> = Default::default();
    pub(crate) static ref IP_CHANGES: Mutex<IpChangesMap> = Default::default();
}
pub const IP_CHANGE_DUR: u64 = 180;
pub const IP_CHANGE_DUR_X2: u64 = IP_CHANGE_DUR * 2;
pub const DAY_SECONDS: u64 = 3600 * 24;
pub const IP_BLOCK_DUR: u64 = 60;
pub const PENDING_REGISTRATION_WINDOW: Duration = Duration::from_secs(6);
pub const PENDING_REGISTRATION_TTL: Duration = Duration::from_secs(60);
pub const PENDING_REGISTRATION_CAPACITY: usize = 65_536;

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub(crate) struct PeerInfo {
    #[serde(default)]
    pub(crate) ip: String,
}

pub(crate) struct Peer {
    pub(crate) socket_addr: SocketAddr,
    pub(crate) last_reg_time: Instant,
    pub(crate) guid: Vec<u8>,
    pub(crate) uuid: Bytes,
    pub(crate) pk: Bytes,
    // pub(crate) user: Option<Vec<u8>>,
    pub(crate) info: PeerInfo,
    // pub(crate) disabled: bool,
    pub(crate) reg_pk: (u32, Instant), // how often register_pk
    pub(crate) admitted: bool,
}

impl Default for Peer {
    fn default() -> Self {
        Self {
            socket_addr: "0.0.0.0:0".parse().unwrap(),
            last_reg_time: get_expired_time(),
            guid: Vec::new(),
            uuid: Bytes::new(),
            pk: Bytes::new(),
            info: Default::default(),
            // user: None,
            // disabled: false,
            reg_pk: (0, get_expired_time()),
            admitted: false,
        }
    }
}

pub(crate) type LockPeer = Arc<RwLock<Peer>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidationResult {
    Removed,
    AlreadyAbsent,
    Replaced,
    NoLongerInactive,
    GenerationStillPresent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceInvalidationPredicate {
    StillInactive,
    DeletedGeneration { guid: Vec<u8> },
}

pub struct DeviceInvalidationCommand {
    pub device_id: String,
    pub predicate: DeviceInvalidationPredicate,
    pub ack: oneshot::Sender<Result<InvalidationResult, ()>>,
}

pub const DEVICE_INVALIDATION_CHANNEL_CAPACITY: usize = 1_024;
pub type DeviceInvalidationSender = mpsc::Sender<DeviceInvalidationCommand>;
pub type DeviceInvalidationReceiver = mpsc::Receiver<DeviceInvalidationCommand>;

#[derive(Debug, Clone, Copy)]
struct PendingRegistration {
    count: u32,
    last_seen: Instant,
}

#[derive(Debug)]
pub(crate) struct PendingRegistrationLimiter {
    entries: HashMap<(String, String), PendingRegistration>,
    capacity: usize,
    ttl: Duration,
    window: Duration,
}

impl Default for PendingRegistrationLimiter {
    fn default() -> Self {
        Self::new(
            PENDING_REGISTRATION_CAPACITY,
            PENDING_REGISTRATION_TTL,
            PENDING_REGISTRATION_WINDOW,
        )
    }
}

impl PendingRegistrationLimiter {
    fn new(capacity: usize, ttl: Duration, window: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            capacity,
            ttl,
            window,
        }
    }

    pub(crate) fn record(&mut self, device_id: &str, source_ip: &str) -> Option<(u32, Instant)> {
        let now = Instant::now();
        self.evict_expired(now);
        let key = normalize_pending_key(device_id, source_ip);
        if !self.entries.contains_key(&key) && self.entries.len() >= self.capacity {
            if let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_seen)
                .map(|(key, _)| key.clone())
            {
                self.entries.remove(&oldest);
            }
        }
        let entry = self.entries.entry(key).or_insert(PendingRegistration {
            count: 0,
            last_seen: now,
        });
        if now.duration_since(entry.last_seen) >= self.window {
            entry.count = 0;
        }
        if entry.count >= 3 {
            entry.last_seen = now;
            return None;
        }
        entry.count += 1;
        entry.last_seen = now;
        Some((entry.count, entry.last_seen))
    }

    pub(crate) fn take(&mut self, device_id: &str, source_ip: &str) -> Option<(u32, Instant)> {
        self.entries
            .remove(&normalize_pending_key(device_id, source_ip))
            .map(|entry| (entry.count, entry.last_seen))
    }

    fn evict_expired(&mut self, now: Instant) {
        self.entries
            .retain(|_, entry| now.duration_since(entry.last_seen) < self.ttl);
    }
}

fn normalize_pending_key(device_id: &str, source_ip: &str) -> (String, String) {
    (device_id.trim().to_owned(), source_ip.trim().to_owned())
}

#[derive(Clone)]
pub(crate) struct PeerMap {
    state: Arc<RwLock<PeerMapState>>,
    pub(crate) db: database::Database,
}

#[derive(Default)]
struct PeerMapState {
    peers: HashMap<String, LockPeer>,
    epochs: Arc<StdMutex<HashMap<String, Arc<AtomicU64>>>>,
}

struct EpochLease {
    epochs: Arc<StdMutex<HashMap<String, Arc<AtomicU64>>>>,
    id: String,
    token: Arc<AtomicU64>,
    captured_epoch: u64,
}

impl EpochLease {
    fn acquire(state: &PeerMapState, id: &str) -> Self {
        let epochs = state.epochs.clone();
        let token = {
            let mut registry = epochs
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            registry
                .entry(id.to_owned())
                .or_insert_with(|| Arc::new(AtomicU64::new(0)))
                .clone()
        };
        let captured_epoch = token.load(Ordering::Acquire);
        Self {
            epochs,
            id: id.to_owned(),
            token,
            captured_epoch,
        }
    }

    fn has_advanced(&self) -> bool {
        self.token.load(Ordering::Acquire) != self.captured_epoch
    }
}

impl Drop for EpochLease {
    fn drop(&mut self) {
        // future 在数据库或其他 await 点被取消时也会走 Drop；同步短锁让 token
        // 无需依赖异步清理任务，且 Arc 指针校验可隔离同一设备后续创建的新 token。
        let mut registry = self
            .epochs
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let is_last_lease = registry.get(&self.id).is_some_and(|current| {
            Arc::ptr_eq(current, &self.token) && Arc::strong_count(&self.token) == 2
        });
        if is_last_lease {
            registry.remove(&self.id);
        }
    }
}

impl PeerMap {
    pub(crate) async fn new() -> ResultType<Self> {
        let db = selected_db_path(std::env::var("DB_URL").ok(), configured_db_path());
        log::info!("DB_URL={}", db);
        let pm = Self {
            state: Default::default(),
            db: database::Database::new(&db).await?,
        };
        Ok(pm)
    }

    #[cfg(test)]
    pub(crate) fn from_database(db: database::Database) -> Self {
        Self {
            state: Default::default(),
            db,
        }
    }

    #[cfg(test)]
    async fn has_epoch(&self, id: &str) -> bool {
        let epochs = self.state.read().await.epochs.clone();
        let registry = epochs
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        registry.contains_key(id)
    }

    #[inline]
    pub(crate) async fn get_for_rendezvous(&self, id: &str) -> Option<LockPeer> {
        self.get_for_rendezvous_with_hook(id, || std::future::ready(()))
            .await
    }

    async fn get_for_rendezvous_with_hook<F, Fut>(
        &self,
        id: &str,
        mut after_database_query: F,
    ) -> Option<LockPeer>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = ()>,
    {
        loop {
            // Arc 指针只能发现 map 中已经发生的替换。epoch 还会记录“map 当时为空”
            // 或“当前是别的 guid”时完成的失效，阻止迟到的数据库快照在 ACK 后回写。
            let (captured, epoch_lease) = {
                let state = self.state.write().await;
                let captured = state.peers.get(id).cloned();
                let epoch_lease = EpochLease::acquire(&state, id);
                (captured, epoch_lease)
            };
            let captured_guid = match captured.as_ref() {
                Some(peer) => Some(peer.read().await.guid.clone()),
                None => None,
            };
            let database_result = self.db.get_peer_for_rendezvous(id).await;
            after_database_query().await;
            match database_result {
                Ok(Some(row)) => {
                    let database_guid = row.guid.clone();
                    let mut state = self.state.write().await;
                    if epoch_lease.has_advanced() {
                        continue;
                    }
                    let result = match (captured.as_ref(), state.peers.get(id)) {
                        (Some(captured), Some(current)) if Arc::ptr_eq(captured, current) => {
                            if captured_guid.as_deref() == Some(database_guid.as_slice()) {
                                Some(current.clone())
                            } else {
                                let peer = peer_from_database(row);
                                state.peers.insert(id.to_owned(), peer.clone());
                                Some(peer)
                            }
                        }
                        (None, None) => {
                            let peer = peer_from_database(row);
                            state.peers.insert(id.to_owned(), peer.clone());
                            Some(peer)
                        }
                        _ => None,
                    };
                    if let Some(peer) = result {
                        return Some(peer);
                    }
                }
                Ok(None) => {
                    self.remove_captured(id, captured).await;
                    return None;
                }
                Err(err) => {
                    log::error!("查询设备 {} 的准入状态失败: {:#}", id, err);
                    return None;
                }
            }
        }
    }

    fn advance_epoch_locked(state: &mut PeerMapState, id: &str) {
        let mut registry = state
            .epochs
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let remove_after_advance = {
            let epoch = registry
                .entry(id.to_owned())
                .or_insert_with(|| Arc::new(AtomicU64::new(0)));
            epoch.fetch_add(1, Ordering::AcqRel);
            Arc::strong_count(epoch) == 1
        };
        // 没有查询持有该 token 时可立即回收；之后的新查询尚未读取数据库，
        // 即使新建 token 从 0 开始，也不可能携带本次失效之前的快照。
        if remove_after_advance {
            registry.remove(id);
        }
    }

    async fn advance_epoch(&self, id: &str) {
        let mut state = self.state.write().await;
        Self::advance_epoch_locked(&mut state, id);
    }

    pub(crate) async fn insert_admitted(
        &self,
        id: String,
        row: database::Peer,
        socket_addr: SocketAddr,
        reg_pk: (u32, Instant),
    ) -> Option<LockPeer> {
        self.insert_admitted_with_hook(id, row, socket_addr, reg_pk, || std::future::ready(()))
            .await
    }

    async fn insert_admitted_with_hook<F, Fut>(
        &self,
        id: String,
        admitted_row: database::Peer,
        socket_addr: SocketAddr,
        reg_pk: (u32, Instant),
        mut after_database_query: F,
    ) -> Option<LockPeer>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = ()>,
    {
        let expected_guid = admitted_row.guid;
        loop {
            let epoch_lease = {
                let state = self.state.write().await;
                EpochLease::acquire(&state, &id)
            };
            let database_result = self.db.get_peer_for_rendezvous(&id).await;
            after_database_query().await;
            let row = match database_result {
                Ok(Some(row)) if row.guid == expected_guid => row,
                Ok(_) => return None,
                Err(err) => {
                    log::error!("设备 {} 准入结果二次校验失败: {:#}", id, err);
                    return None;
                }
            };

            let mut state = self.state.write().await;
            if epoch_lease.has_advanced() {
                continue;
            }
            let peer = Arc::new(RwLock::new(Peer {
                socket_addr,
                last_reg_time: Instant::now(),
                guid: row.guid,
                uuid: row.uuid.into(),
                pk: row.pk.into(),
                info: serde_json::from_str::<PeerInfo>(&row.info).unwrap_or_default(),
                reg_pk,
                admitted: true,
            }));
            state.peers.insert(id.clone(), peer.clone());
            Self::advance_epoch_locked(&mut state, &id);
            return Some(peer);
        }
    }

    #[inline]
    pub(crate) async fn get_in_memory(&self, id: &str) -> Option<LockPeer> {
        let peer = self.state.read().await.peers.get(id).cloned()?;
        if peer.read().await.admitted {
            Some(peer)
        } else {
            None
        }
    }

    #[inline]
    pub(crate) async fn is_in_memory(&self, id: &str) -> bool {
        self.get_in_memory(id).await.is_some()
    }

    pub(crate) async fn invalidate_if_still_inactive(
        &self,
        id: &str,
    ) -> ResultType<InvalidationResult> {
        let captured = self.state.read().await.peers.get(id).cloned();
        let captured_guid = match captured.as_ref() {
            Some(peer) => Some(peer.read().await.guid.clone()),
            None => None,
        };
        match self.db.get_peer(id).await? {
            Some(row)
                if row.status != database::DeviceStatus::Inactive.as_str()
                    && captured_guid
                        .as_deref()
                        .is_none_or(|guid| guid == row.guid.as_slice()) =>
            {
                self.advance_epoch(id).await;
                Ok(InvalidationResult::NoLongerInactive)
            }
            // missing、inactive 或活动行已是另一 guid 时，只条件删除捕获的旧 Arc。
            // 若 map 已换成新 Arc，remove_captured 会返回 Replaced 并保留它。
            _ => Ok(self.remove_captured(id, captured).await),
        }
    }

    pub(crate) async fn invalidate(
        &self,
        id: &str,
        predicate: DeviceInvalidationPredicate,
    ) -> ResultType<InvalidationResult> {
        match predicate {
            DeviceInvalidationPredicate::StillInactive => {
                self.invalidate_if_still_inactive(id).await
            }
            DeviceInvalidationPredicate::DeletedGeneration { guid } => {
                self.invalidate_deleted_generation(id, &guid).await
            }
        }
    }

    pub(crate) async fn invalidate_deleted_generation(
        &self,
        id: &str,
        deleted_guid: &[u8],
    ) -> ResultType<InvalidationResult> {
        if self
            .db
            .get_peer(id)
            .await?
            .is_some_and(|row| row.guid == deleted_guid)
        {
            self.advance_epoch(id).await;
            return Ok(InvalidationResult::GenerationStillPresent);
        }
        Ok(self.remove_generation(id, deleted_guid).await)
    }

    pub(crate) async fn invalidate_if_not_admitted(
        &self,
        id: &str,
        expected_guid: &[u8],
    ) -> ResultType<InvalidationResult> {
        if self
            .db
            .get_peer_for_rendezvous(id)
            .await?
            .is_some_and(|row| row.guid == expected_guid)
        {
            self.advance_epoch(id).await;
            return Ok(InvalidationResult::GenerationStillPresent);
        }
        Ok(self.remove_generation(id, expected_guid).await)
    }

    async fn remove_generation(&self, id: &str, expected_guid: &[u8]) -> InvalidationResult {
        loop {
            let current = self.state.read().await.peers.get(id).cloned();
            let current_guid = match current.as_ref() {
                Some(peer) => Some(peer.read().await.guid.clone()),
                None => None,
            };

            // epoch 推进与最终 map 判定/删除在同一写锁内；Peer 锁读取则在锁外完成，
            // 避免慢 Peer writer 阻塞所有设备的 state。
            let mut state = self.state.write().await;
            Self::advance_epoch_locked(&mut state, id);
            match (current.as_ref(), state.peers.get(id)) {
                (None, None) => return InvalidationResult::AlreadyAbsent,
                (Some(current), Some(latest)) if Arc::ptr_eq(current, latest) => {
                    if current_guid.as_deref() != Some(expected_guid) {
                        return InvalidationResult::Replaced;
                    }
                    state.peers.remove(id);
                    return InvalidationResult::Removed;
                }
                (Some(_), None) => return InvalidationResult::AlreadyAbsent,
                _ => continue,
            }
        }
    }

    async fn remove_captured(&self, id: &str, captured: Option<LockPeer>) -> InvalidationResult {
        let mut state = self.state.write().await;
        Self::advance_epoch_locked(&mut state, id);
        match (captured, state.peers.get(id)) {
            (Some(captured), Some(current)) if Arc::ptr_eq(&captured, current) => {
                state.peers.remove(id);
                InvalidationResult::Removed
            }
            (Some(_), Some(_)) | (None, Some(_)) => InvalidationResult::Replaced,
            (_, None) => InvalidationResult::AlreadyAbsent,
        }
    }
}

fn peer_from_database(row: database::Peer) -> LockPeer {
    Arc::new(RwLock::new(Peer {
        guid: row.guid,
        uuid: row.uuid.into(),
        pk: row.pk.into(),
        info: serde_json::from_str::<PeerInfo>(&row.info).unwrap_or_default(),
        admitted: true,
        ..Default::default()
    }))
}

fn configured_db_path() -> Option<String> {
    crate::config::global_config().and_then(|cfg_lock| {
        let cfg = cfg_lock.read().ok()?;
        let path = cfg.database_url().to_string();
        if path.is_empty() {
            None
        } else {
            Some(path)
        }
    })
}

fn legacy_default_db_path() -> String {
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
        "db_v2.sqlite3".to_owned()
    }
    #[cfg(not(windows))]
    {
        "./db_v2.sqlite3".to_owned()
    }
}

fn selected_db_path(db_url: Option<String>, configured: Option<String>) -> String {
    db_url.or(configured).unwrap_or_else(legacy_default_db_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::{Connection, Executor, SqliteConnection};
    use std::{
        sync::atomic::AtomicBool,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn test_default_db_path_is_legacy_compatible() {
        assert_eq!(selected_db_path(None, None), legacy_default_db_path());
    }

    #[test]
    fn test_config_db_path_is_used() {
        assert_eq!(
            selected_db_path(None, Some("custom.sqlite3".to_string())),
            "custom.sqlite3"
        );
    }

    #[test]
    fn test_explicit_var_lib_db_path_is_used() {
        assert_eq!(
            selected_db_path(None, Some("/var/lib/rustdesk/db.sqlite3".to_string())),
            "/var/lib/rustdesk/db.sqlite3"
        );
    }

    #[test]
    fn test_db_url_overrides_config_db_path() {
        assert_eq!(
            selected_db_path(
                Some("env.sqlite3".to_string()),
                Some("custom.sqlite3".to_string())
            ),
            "env.sqlite3"
        );
    }

    #[test]
    fn pending_limiter_keeps_three_attempts_per_six_second_window() {
        let mut limiter =
            PendingRegistrationLimiter::new(8, Duration::from_secs(60), Duration::from_secs(6));
        assert!(limiter.record("device-a", "10.0.0.1").is_some());
        assert!(limiter.record("device-a", "10.0.0.1").is_some());
        assert!(limiter.record("device-a", "10.0.0.1").is_some());
        assert!(limiter.record("device-a", "10.0.0.1").is_none());
        assert!(limiter.record("device-a", "10.0.0.2").is_some());
        assert!(limiter.record("device-b", "10.0.0.1").is_some());
    }

    #[test]
    fn pending_limiter_expires_and_evicts_oldest_at_capacity() {
        let mut limiter =
            PendingRegistrationLimiter::new(2, Duration::from_millis(5), Duration::from_secs(6));
        limiter.record("device-a", "10.0.0.1").unwrap();
        limiter.record("device-b", "10.0.0.1").unwrap();
        limiter
            .entries
            .get_mut(&normalize_pending_key("device-a", "10.0.0.1"))
            .unwrap()
            .last_seen = Instant::now() - Duration::from_millis(2);
        limiter.record("device-c", "10.0.0.1").unwrap();
        assert!(!limiter
            .entries
            .contains_key(&normalize_pending_key("device-a", "10.0.0.1")));
        for entry in limiter.entries.values_mut() {
            entry.last_seen = Instant::now() - Duration::from_millis(6);
        }
        limiter.record("device-d", "10.0.0.1").unwrap();
        assert_eq!(limiter.entries.len(), 1);
    }

    #[test]
    fn inactive_rendezvous_lookup_never_caches_peer() {
        let rt = hbb_common::tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("inactive-lookup");
            let db = database::Database::new(&path).await.unwrap();
            db.insert_peer("inactive-device", b"uuid", b"pk", "{}")
                .await
                .unwrap();
            db.set_device_inactive("inactive-device").await.unwrap();
            let pm = PeerMap {
                state: Default::default(),
                db,
            };
            assert!(pm.get_for_rendezvous("inactive-device").await.is_none());
            assert!(!pm.is_in_memory("inactive-device").await);
            cleanup(&path);
        });
    }

    #[test]
    fn conditional_removal_preserves_replacement_instance() {
        let rt = hbb_common::tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("conditional-removal");
            let db = database::Database::new(&path).await.unwrap();
            let pm = PeerMap {
                state: Default::default(),
                db,
            };
            let old = Arc::new(RwLock::new(Peer {
                admitted: true,
                ..Default::default()
            }));
            let replacement = Arc::new(RwLock::new(Peer {
                admitted: true,
                ..Default::default()
            }));
            pm.state
                .write()
                .await
                .peers
                .insert("device-a".to_string(), replacement.clone());
            assert_eq!(
                pm.remove_captured("device-a", Some(old)).await,
                InvalidationResult::Replaced
            );
            assert!(Arc::ptr_eq(
                &pm.get_in_memory("device-a").await.unwrap(),
                &replacement
            ));
            cleanup(&path);
        });
    }

    #[test]
    fn deleted_generation_removes_matching_cached_peer() {
        let rt = hbb_common::tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("deleted-generation");
            let db = database::Database::new(&path).await.unwrap();
            let guid = db
                .insert_peer("deleted-device", b"uuid-old", b"pk-old", "{}")
                .await
                .unwrap();
            let pm = PeerMap::from_database(db);
            let cached = pm.get_for_rendezvous("deleted-device").await.unwrap();
            assert_eq!(cached.read().await.guid, guid);

            let mut conn = SqliteConnection::connect(&path).await.unwrap();
            conn.execute("DELETE FROM devices WHERE device_id = 'deleted-device'")
                .await
                .unwrap();
            drop(conn);

            assert_eq!(
                pm.invalidate(
                    "deleted-device",
                    DeviceInvalidationPredicate::DeletedGeneration { guid }
                )
                .await
                .unwrap(),
                InvalidationResult::Removed
            );
            assert!(pm.get_in_memory("deleted-device").await.is_none());
            cleanup(&path);
        });
    }

    #[test]
    fn deleted_generation_preserves_generation_still_in_database() {
        let rt = hbb_common::tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("generation-still-present");
            let db = database::Database::new(&path).await.unwrap();
            let guid = db
                .insert_peer("present-device", b"uuid", b"pk", "{}")
                .await
                .unwrap();
            let pm = PeerMap::from_database(db);
            let cached = pm.get_for_rendezvous("present-device").await.unwrap();

            assert_eq!(
                pm.invalidate_deleted_generation("present-device", &guid)
                    .await
                    .unwrap(),
                InvalidationResult::GenerationStillPresent
            );
            assert!(Arc::ptr_eq(
                &cached,
                &pm.get_in_memory("present-device").await.unwrap()
            ));
            cleanup(&path);
        });
    }

    #[test]
    fn deleted_generation_removes_old_arc_after_new_database_generation_commits() {
        let rt = hbb_common::tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("deleted-generation-reregister");
            let db = database::Database::new(&path).await.unwrap();
            let old_guid = db
                .insert_peer("reused-device", b"uuid-old", b"pk-old", "{}")
                .await
                .unwrap();
            let pm = PeerMap::from_database(db.clone());
            let old = pm.get_for_rendezvous("reused-device").await.unwrap();

            let mut conn = SqliteConnection::connect(&path).await.unwrap();
            conn.execute("DELETE FROM devices WHERE device_id = 'reused-device'")
                .await
                .unwrap();
            drop(conn);
            let new_guid = db
                .insert_peer("reused-device", b"uuid-new", b"pk-new", "{}")
                .await
                .unwrap();

            assert!(Arc::ptr_eq(
                &old,
                &pm.get_in_memory("reused-device").await.unwrap()
            ));
            assert_eq!(
                pm.invalidate_deleted_generation("reused-device", &old_guid)
                    .await
                    .unwrap(),
                InvalidationResult::Removed
            );
            let current = pm.get_for_rendezvous("reused-device").await.unwrap();
            assert_eq!(current.read().await.guid, new_guid);
            assert!(!Arc::ptr_eq(&old, &current));
            cleanup(&path);
        });
    }

    #[test]
    fn rendezvous_lookup_replaces_stale_generation() {
        let rt = hbb_common::tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("lookup-generation-reregister");
            let db = database::Database::new(&path).await.unwrap();
            db.insert_peer("lookup-device", b"uuid-old", b"pk-old", "{}")
                .await
                .unwrap();
            let pm = PeerMap::from_database(db.clone());
            let old = pm.get_for_rendezvous("lookup-device").await.unwrap();

            let mut conn = SqliteConnection::connect(&path).await.unwrap();
            conn.execute("DELETE FROM devices WHERE device_id = 'lookup-device'")
                .await
                .unwrap();
            drop(conn);
            let new_guid = db
                .insert_peer("lookup-device", b"uuid-new", b"pk-new", "{}")
                .await
                .unwrap();

            let current = pm.get_for_rendezvous("lookup-device").await.unwrap();
            assert_eq!(current.read().await.guid, new_guid);
            assert!(!Arc::ptr_eq(&old, &current));
            cleanup(&path);
        });
    }

    #[test]
    fn still_inactive_preserves_reactivated_same_generation() {
        let rt = hbb_common::tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("inactive-reactivated");
            let db = database::Database::new(&path).await.unwrap();
            db.insert_peer("reactivated-device", b"uuid", b"pk", "{}")
                .await
                .unwrap();
            let pm = PeerMap::from_database(db.clone());
            let cached = pm.get_for_rendezvous("reactivated-device").await.unwrap();
            db.set_device_inactive("reactivated-device").await.unwrap();

            let mut conn = SqliteConnection::connect(&path).await.unwrap();
            conn.execute(
                "UPDATE devices SET status = 'offline' WHERE device_id = 'reactivated-device'",
            )
            .await
            .unwrap();
            drop(conn);

            assert_eq!(
                pm.invalidate(
                    "reactivated-device",
                    DeviceInvalidationPredicate::StillInactive
                )
                .await
                .unwrap(),
                InvalidationResult::NoLongerInactive
            );
            assert!(Arc::ptr_eq(
                &cached,
                &pm.get_in_memory("reactivated-device").await.unwrap()
            ));
            cleanup(&path);
        });
    }

    #[test]
    fn still_inactive_removes_cached_generation() {
        let rt = hbb_common::tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("still-inactive");
            let db = database::Database::new(&path).await.unwrap();
            db.insert_peer("still-inactive-device", b"uuid", b"pk", "{}")
                .await
                .unwrap();
            let pm = PeerMap::from_database(db.clone());
            pm.get_for_rendezvous("still-inactive-device")
                .await
                .unwrap();
            db.set_device_inactive("still-inactive-device")
                .await
                .unwrap();

            assert_eq!(
                pm.invalidate(
                    "still-inactive-device",
                    DeviceInvalidationPredicate::StillInactive
                )
                .await
                .unwrap(),
                InvalidationResult::Removed
            );
            assert!(pm.get_in_memory("still-inactive-device").await.is_none());
            cleanup(&path);
        });
    }

    #[test]
    fn still_inactive_removes_captured_peer_when_database_row_is_missing() {
        let rt = hbb_common::tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("still-inactive-missing");
            let db = database::Database::new(&path).await.unwrap();
            db.insert_peer("missing-device", b"uuid", b"pk", "{}")
                .await
                .unwrap();
            let pm = PeerMap::from_database(db);
            pm.get_for_rendezvous("missing-device").await.unwrap();

            let mut conn = SqliteConnection::connect(&path).await.unwrap();
            conn.execute("DELETE FROM devices WHERE device_id = 'missing-device'")
                .await
                .unwrap();
            drop(conn);

            assert_eq!(
                pm.invalidate_if_still_inactive("missing-device")
                    .await
                    .unwrap(),
                InvalidationResult::Removed
            );
            assert!(pm.get_in_memory("missing-device").await.is_none());
            cleanup(&path);
        });
    }

    #[test]
    fn still_inactive_drops_old_arc_when_database_has_a_new_active_guid() {
        let rt = hbb_common::tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("still-inactive-new-guid");
            let db = database::Database::new(&path).await.unwrap();
            db.insert_peer("new-guid-device", b"uuid-old", b"pk-old", "{}")
                .await
                .unwrap();
            let pm = PeerMap::from_database(db.clone());
            let old = pm.get_for_rendezvous("new-guid-device").await.unwrap();

            let mut conn = SqliteConnection::connect(&path).await.unwrap();
            conn.execute("DELETE FROM devices WHERE device_id = 'new-guid-device'")
                .await
                .unwrap();
            drop(conn);
            let new_guid = db
                .insert_peer("new-guid-device", b"uuid-new", b"pk-new", "{}")
                .await
                .unwrap();

            assert_eq!(
                pm.invalidate_if_still_inactive("new-guid-device")
                    .await
                    .unwrap(),
                InvalidationResult::Removed
            );
            let current = pm.get_for_rendezvous("new-guid-device").await.unwrap();
            assert_eq!(current.read().await.guid, new_guid);
            assert!(!Arc::ptr_eq(&old, &current));
            cleanup(&path);
        });
    }

    #[test]
    fn deleted_generation_epoch_rejects_a_late_database_snapshot_after_ack() {
        let rt = hbb_common::tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("deleted-generation-late-lookup");
            let db = database::Database::new(&path).await.unwrap();
            let guid = db
                .insert_peer("late-deleted-device", b"uuid-old", b"pk-old", "{}")
                .await
                .unwrap();
            let pm = PeerMap::from_database(db);
            let query_barrier = Arc::new(tokio::sync::Barrier::new(2));
            let resume_barrier = Arc::new(tokio::sync::Barrier::new(2));
            let first_query = Arc::new(AtomicBool::new(true));
            let lookup_pm = pm.clone();
            let lookup = tokio::spawn({
                let query_barrier = query_barrier.clone();
                let resume_barrier = resume_barrier.clone();
                async move {
                    lookup_pm
                        .get_for_rendezvous_with_hook("late-deleted-device", move || {
                            let query_barrier = query_barrier.clone();
                            let resume_barrier = resume_barrier.clone();
                            let should_pause = first_query.swap(false, Ordering::SeqCst);
                            async move {
                                if should_pause {
                                    query_barrier.wait().await;
                                    resume_barrier.wait().await;
                                }
                            }
                        })
                        .await
                }
            });

            query_barrier.wait().await;
            let mut conn = SqliteConnection::connect(&path).await.unwrap();
            conn.execute("DELETE FROM devices WHERE device_id = 'late-deleted-device'")
                .await
                .unwrap();
            drop(conn);
            assert_eq!(
                pm.invalidate_deleted_generation("late-deleted-device", &guid)
                    .await
                    .unwrap(),
                InvalidationResult::AlreadyAbsent
            );
            resume_barrier.wait().await;

            assert!(lookup.await.unwrap().is_none());
            let state = pm.state.read().await;
            assert!(!state.peers.contains_key("late-deleted-device"));
            drop(state);
            assert!(!pm.has_epoch("late-deleted-device").await);
            cleanup(&path);
        });
    }

    #[test]
    fn still_inactive_epoch_rejects_a_late_active_snapshot_after_ack() {
        let rt = hbb_common::tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("still-inactive-late-lookup");
            let db = database::Database::new(&path).await.unwrap();
            db.insert_peer("late-inactive-device", b"uuid", b"pk", "{}")
                .await
                .unwrap();
            let pm = PeerMap::from_database(db.clone());
            let query_barrier = Arc::new(tokio::sync::Barrier::new(2));
            let resume_barrier = Arc::new(tokio::sync::Barrier::new(2));
            let first_query = Arc::new(AtomicBool::new(true));
            let lookup_pm = pm.clone();
            let lookup = tokio::spawn({
                let query_barrier = query_barrier.clone();
                let resume_barrier = resume_barrier.clone();
                async move {
                    lookup_pm
                        .get_for_rendezvous_with_hook("late-inactive-device", move || {
                            let query_barrier = query_barrier.clone();
                            let resume_barrier = resume_barrier.clone();
                            let should_pause = first_query.swap(false, Ordering::SeqCst);
                            async move {
                                if should_pause {
                                    query_barrier.wait().await;
                                    resume_barrier.wait().await;
                                }
                            }
                        })
                        .await
                }
            });

            query_barrier.wait().await;
            db.set_device_inactive("late-inactive-device")
                .await
                .unwrap();
            assert_eq!(
                pm.invalidate_if_still_inactive("late-inactive-device")
                    .await
                    .unwrap(),
                InvalidationResult::AlreadyAbsent
            );
            resume_barrier.wait().await;

            assert!(lookup.await.unwrap().is_none());
            let state = pm.state.read().await;
            assert!(!state.peers.contains_key("late-inactive-device"));
            drop(state);
            assert!(!pm.has_epoch("late-inactive-device").await);
            cleanup(&path);
        });
    }

    #[test]
    fn admitted_row_epoch_rejects_cache_insert_after_delete_ack() {
        let rt = hbb_common::tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("admission-result-late-insert");
            let db = database::Database::new(&path).await.unwrap();
            let guid = db
                .insert_peer("late-admission-device", b"uuid", b"pk", "{}")
                .await
                .unwrap();
            let admitted_row = db
                .get_peer_for_rendezvous("late-admission-device")
                .await
                .unwrap()
                .unwrap();
            let pm = PeerMap::from_database(db);
            let query_barrier = Arc::new(tokio::sync::Barrier::new(2));
            let resume_barrier = Arc::new(tokio::sync::Barrier::new(2));
            let first_query = Arc::new(AtomicBool::new(true));
            let inserting_pm = pm.clone();
            let inserting = tokio::spawn({
                let query_barrier = query_barrier.clone();
                let resume_barrier = resume_barrier.clone();
                async move {
                    inserting_pm
                        .insert_admitted_with_hook(
                            "late-admission-device".to_owned(),
                            admitted_row,
                            "127.0.0.1:21116".parse().unwrap(),
                            (1, Instant::now()),
                            move || {
                                let query_barrier = query_barrier.clone();
                                let resume_barrier = resume_barrier.clone();
                                let should_pause = first_query.swap(false, Ordering::SeqCst);
                                async move {
                                    if should_pause {
                                        query_barrier.wait().await;
                                        resume_barrier.wait().await;
                                    }
                                }
                            },
                        )
                        .await
                }
            });

            query_barrier.wait().await;
            let mut conn = SqliteConnection::connect(&path).await.unwrap();
            conn.execute("DELETE FROM devices WHERE device_id = 'late-admission-device'")
                .await
                .unwrap();
            drop(conn);
            assert_eq!(
                pm.invalidate_deleted_generation("late-admission-device", &guid)
                    .await
                    .unwrap(),
                InvalidationResult::AlreadyAbsent
            );
            resume_barrier.wait().await;

            assert!(inserting.await.unwrap().is_none());
            let state = pm.state.read().await;
            assert!(!state.peers.contains_key("late-admission-device"));
            drop(state);
            assert!(!pm.has_epoch("late-admission-device").await);
            cleanup(&path);
        });
    }

    #[test]
    fn admitted_row_epoch_rejects_cache_insert_after_inactive_ack() {
        let rt = hbb_common::tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("admission-result-inactive");
            let db = database::Database::new(&path).await.unwrap();
            db.insert_peer("inactive-admission-device", b"uuid", b"pk", "{}")
                .await
                .unwrap();
            let admitted_row = db
                .get_peer_for_rendezvous("inactive-admission-device")
                .await
                .unwrap()
                .unwrap();
            let pm = PeerMap::from_database(db.clone());
            let query_barrier = Arc::new(tokio::sync::Barrier::new(2));
            let resume_barrier = Arc::new(tokio::sync::Barrier::new(2));
            let first_query = Arc::new(AtomicBool::new(true));
            let inserting_pm = pm.clone();
            let inserting = tokio::spawn({
                let query_barrier = query_barrier.clone();
                let resume_barrier = resume_barrier.clone();
                async move {
                    inserting_pm
                        .insert_admitted_with_hook(
                            "inactive-admission-device".to_owned(),
                            admitted_row,
                            "127.0.0.1:21116".parse().unwrap(),
                            (1, Instant::now()),
                            move || {
                                let query_barrier = query_barrier.clone();
                                let resume_barrier = resume_barrier.clone();
                                let should_pause = first_query.swap(false, Ordering::SeqCst);
                                async move {
                                    if should_pause {
                                        query_barrier.wait().await;
                                        resume_barrier.wait().await;
                                    }
                                }
                            },
                        )
                        .await
                }
            });

            query_barrier.wait().await;
            db.set_device_inactive("inactive-admission-device")
                .await
                .unwrap();
            assert_eq!(
                pm.invalidate_if_still_inactive("inactive-admission-device")
                    .await
                    .unwrap(),
                InvalidationResult::AlreadyAbsent
            );
            resume_barrier.wait().await;

            assert!(inserting.await.unwrap().is_none());
            let state = pm.state.read().await;
            assert!(!state.peers.contains_key("inactive-admission-device"));
            drop(state);
            assert!(!pm.has_epoch("inactive-admission-device").await);
            cleanup(&path);
        });
    }

    #[test]
    fn cancelled_rendezvous_lookup_releases_epoch_lease() {
        let rt = hbb_common::tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("cancelled-rendezvous-lookup");
            let db = database::Database::new(&path).await.unwrap();
            db.insert_peer("cancelled-lookup-device", b"uuid", b"pk", "{}")
                .await
                .unwrap();
            let pm = PeerMap::from_database(db);
            let query_barrier = Arc::new(tokio::sync::Barrier::new(2));
            let lookup_pm = pm.clone();
            let lookup = tokio::spawn({
                let query_barrier = query_barrier.clone();
                async move {
                    lookup_pm
                        .get_for_rendezvous_with_hook("cancelled-lookup-device", move || {
                            let query_barrier = query_barrier.clone();
                            async move {
                                query_barrier.wait().await;
                                std::future::pending::<()>().await;
                            }
                        })
                        .await
                }
            });

            query_barrier.wait().await;
            lookup.abort();
            assert!(matches!(lookup.await, Err(err) if err.is_cancelled()));
            assert!(!pm.has_epoch("cancelled-lookup-device").await);
            cleanup(&path);
        });
    }

    #[test]
    fn cancelled_admitted_insert_releases_epoch_lease() {
        let rt = hbb_common::tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("cancelled-admitted-insert");
            let db = database::Database::new(&path).await.unwrap();
            db.insert_peer("cancelled-insert-device", b"uuid", b"pk", "{}")
                .await
                .unwrap();
            let admitted_row = db
                .get_peer_for_rendezvous("cancelled-insert-device")
                .await
                .unwrap()
                .unwrap();
            let pm = PeerMap::from_database(db);
            let query_barrier = Arc::new(tokio::sync::Barrier::new(2));
            let inserting_pm = pm.clone();
            let inserting = tokio::spawn({
                let query_barrier = query_barrier.clone();
                async move {
                    inserting_pm
                        .insert_admitted_with_hook(
                            "cancelled-insert-device".to_owned(),
                            admitted_row,
                            "127.0.0.1:21116".parse().unwrap(),
                            (1, Instant::now()),
                            move || {
                                let query_barrier = query_barrier.clone();
                                async move {
                                    query_barrier.wait().await;
                                    std::future::pending::<()>().await;
                                }
                            },
                        )
                        .await
                }
            });

            query_barrier.wait().await;
            inserting.abort();
            assert!(matches!(inserting.await, Err(err) if err.is_cancelled()));
            assert!(!pm.has_epoch("cancelled-insert-device").await);
            assert!(!pm.is_in_memory("cancelled-insert-device").await);
            cleanup(&path);
        });
    }

    fn temp_db_path(name: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir()
            .join(format!("rustdesk-peer-{name}-{nanos}.sqlite3"))
            .to_string_lossy()
            .to_string()
    }

    fn cleanup(path: &str) {
        std::fs::remove_file(path).ok();
        std::fs::remove_file(format!("{path}-shm")).ok();
        std::fs::remove_file(format!("{path}-wal")).ok();
    }
}
