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
    net::SocketAddr,
    sync::Arc,
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
}

pub struct DeviceInvalidationCommand {
    pub device_id: String,
    pub ack: oneshot::Sender<Result<InvalidationResult, ()>>,
}

pub type DeviceInvalidationSender = mpsc::UnboundedSender<DeviceInvalidationCommand>;
pub type DeviceInvalidationReceiver = mpsc::UnboundedReceiver<DeviceInvalidationCommand>;

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
    map: Arc<RwLock<HashMap<String, LockPeer>>>,
    pub(crate) db: database::Database,
}

impl PeerMap {
    pub(crate) async fn new() -> ResultType<Self> {
        let db = selected_db_path(std::env::var("DB_URL").ok(), configured_db_path());
        log::info!("DB_URL={}", db);
        let pm = Self {
            map: Default::default(),
            db: database::Database::new(&db).await?,
        };
        Ok(pm)
    }

    #[cfg(test)]
    pub(crate) fn from_database(db: database::Database) -> Self {
        Self {
            map: Default::default(),
            db,
        }
    }

    #[inline]
    pub(crate) async fn get_for_rendezvous(&self, id: &str) -> Option<LockPeer> {
        // 先捕获实例，再查数据库；数据库已 inactive 时只条件删除该实例。
        let captured = self.map.read().await.get(id).cloned();
        match self.db.get_peer_for_rendezvous(id).await {
            Ok(Some(row)) => {
                let mut map = self.map.write().await;
                if let Some(current) = map.get(id) {
                    return Some(current.clone());
                }
                let peer = peer_from_database(row);
                map.insert(id.to_owned(), peer.clone());
                Some(peer)
            }
            Ok(None) => {
                self.remove_captured(id, captured).await;
                None
            }
            Err(err) => {
                log::error!("查询设备 {} 的准入状态失败: {:#}", id, err);
                None
            }
        }
    }

    pub(crate) async fn insert_admitted(
        &self,
        id: String,
        row: database::Peer,
        socket_addr: SocketAddr,
        reg_pk: (u32, Instant),
    ) -> LockPeer {
        let peer = Arc::new(RwLock::new(Peer {
            socket_addr,
            last_reg_time: Instant::now(),
            uuid: row.uuid.into(),
            pk: row.pk.into(),
            info: serde_json::from_str::<PeerInfo>(&row.info).unwrap_or_default(),
            reg_pk,
            admitted: true,
        }));
        self.map.write().await.insert(id, peer.clone());
        peer
    }

    #[inline]
    pub(crate) async fn get_in_memory(&self, id: &str) -> Option<LockPeer> {
        let peer = self.map.read().await.get(id).cloned()?;
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
        let captured = self.map.read().await.get(id).cloned();
        if !self.db.is_device_inactive(id).await? {
            return Ok(InvalidationResult::NoLongerInactive);
        }
        Ok(self.remove_captured(id, captured).await)
    }

    async fn remove_captured(&self, id: &str, captured: Option<LockPeer>) -> InvalidationResult {
        let mut map = self.map.write().await;
        match (captured, map.get(id)) {
            (Some(captured), Some(current)) if Arc::ptr_eq(&captured, current) => {
                map.remove(id);
                InvalidationResult::Removed
            }
            (Some(_), Some(_)) | (None, Some(_)) => InvalidationResult::Replaced,
            (_, None) => InvalidationResult::AlreadyAbsent,
        }
    }
}

fn peer_from_database(row: database::Peer) -> LockPeer {
    Arc::new(RwLock::new(Peer {
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
        let path = cfg.server.db_path.clone();
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
    use std::time::{SystemTime, UNIX_EPOCH};

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
                map: Default::default(),
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
                map: Default::default(),
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
            pm.map
                .write()
                .await
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
