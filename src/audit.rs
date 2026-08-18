use crate::{database::Database, security::SecurityPolicyState};
use chrono::{NaiveDateTime, Utc};
use data_encoding::HEXLOWER;
use hbb_common::log;
use lru::LruCache;
use serde_derive::Serialize;
use serde_json::{Map, Value};
use sodiumoxide::crypto::hash::sha256;
use std::{
    net::IpAddr,
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::mpsc;

const AUDIT_QUEUE_CAPACITY: usize = 1024;
const MAX_ACTION_CHARS: usize = 100;
const MAX_TARGET_TYPE_CHARS: usize = 50;
const MAX_TARGET_ID_CHARS: usize = 255;
const MAX_DETAIL_BYTES: usize = 16 * 1024;
const AUDIT_DEDUPE_CAPACITY: usize = 4096;

#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub user_id: Option<i64>,
    pub action: String,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub detail: Value,
    pub ip_address: Option<String>,
    pub occurred_at: NaiveDateTime,
}

impl AuditEvent {
    pub fn new(action: impl Into<String>) -> Self {
        Self {
            user_id: None,
            action: action.into(),
            target_type: None,
            target_id: None,
            detail: Value::Object(Map::new()),
            ip_address: None,
            occurred_at: Utc::now().naive_utc(),
        }
    }

    pub fn actor(mut self, user_id: i64) -> Self {
        self.user_id = Some(user_id);
        self
    }

    pub fn target(mut self, target_type: impl Into<String>, target_id: impl Into<String>) -> Self {
        self.target_type = Some(target_type.into());
        self.target_id = Some(target_id.into());
        self
    }

    pub fn detail(mut self, detail: Value) -> Self {
        self.detail = detail;
        self
    }

    pub fn ip(mut self, ip: IpAddr) -> Self {
        self.ip_address = Some(ip.to_string());
        self
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuditLogRow {
    pub id: i64,
    pub user_id: Option<i64>,
    pub action: String,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub detail: Option<String>,
    pub ip_address: Option<String>,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Clone, Default)]
pub struct AuditLogFilter {
    pub action: Option<String>,
    pub target_type: Option<String>,
    pub user_id: Option<i64>,
    pub from: Option<NaiveDateTime>,
    pub to: Option<NaiveDateTime>,
    pub page: i64,
    pub page_size: i64,
}

#[derive(Clone)]
pub struct AuditService {
    sender: mpsc::Sender<AuditEvent>,
    dedupe: Arc<Mutex<LruCache<String, Instant>>>,
}

impl AuditService {
    pub fn start(db: Database, retention: Option<SecurityPolicyState>) -> Self {
        let (sender, receiver) = mpsc::channel(AUDIT_QUEUE_CAPACITY);
        tokio::spawn(run_worker(db, retention, receiver));
        Self {
            sender,
            dedupe: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(AUDIT_DEDUPE_CAPACITY).unwrap(),
            ))),
        }
    }

    pub fn record(&self, mut event: AuditEvent) {
        event.detail = redact_value(event.detail);
        if let Err(reason) = validate_event(&event) {
            log::error!(
                "audit event rejected before enqueue: action={} reason={}",
                safe_action_for_log(&event.action),
                reason
            );
            return;
        }
        let action = safe_action_for_log(&event.action);
        if self.sender.try_send(event).is_err() {
            log::error!("audit event enqueue failed: action={}", action);
        }
    }

    pub fn record_rate_limited(&self, event: AuditEvent, window: Duration) {
        let key = format!(
            "{}:{}",
            event.action,
            event.target_id.as_deref().unwrap_or_default()
        );
        let now = Instant::now();
        let should_record = match self.dedupe.lock() {
            Ok(mut seen) => {
                let recent = seen
                    .peek(&key)
                    .is_some_and(|at| now.duration_since(*at) < window);
                if !recent {
                    seen.put(key, now);
                }
                !recent
            }
            Err(_) => {
                log::error!("audit rate-limit state unavailable");
                false
            }
        };
        if should_record {
            self.record(event);
        }
    }
}

async fn run_worker(
    db: Database,
    retention: Option<SecurityPolicyState>,
    mut receiver: mpsc::Receiver<AuditEvent>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(24 * 60 * 60));
    loop {
        tokio::select! {
            event = receiver.recv() => {
                let Some(event) = event else { return; };
                let action = safe_action_for_log(&event.action);
                if db.insert_audit_event(&event).await.is_err() {
                    log::error!("audit event database write failed: action={}", action);
                }
            }
            _ = interval.tick(), if retention.is_some() => {
                let Some(state) = retention.as_ref() else { continue; };
                let days = match state.snapshot() {
                    Ok(config) => config.audit_retention_days,
                    Err(_) => {
                        log::error!("audit retention policy read failed");
                        continue;
                    }
                };
                if db.delete_expired_audit_logs(days).await.is_err() {
                    log::error!("audit retention cleanup failed");
                }
            }
        }
    }
}

fn validate_event(event: &AuditEvent) -> Result<(), &'static str> {
    if event.action.is_empty()
        || event.action.chars().count() > MAX_ACTION_CHARS
        || event.action.chars().any(char::is_control)
    {
        return Err("invalid action");
    }
    if let Some(target_type) = &event.target_type {
        if target_type.is_empty()
            || target_type.chars().count() > MAX_TARGET_TYPE_CHARS
            || target_type.chars().any(char::is_control)
        {
            return Err("invalid target type");
        }
    }
    if let Some(target_id) = &event.target_id {
        if target_id.is_empty()
            || target_id.chars().count() > MAX_TARGET_ID_CHARS
            || target_id.chars().any(char::is_control)
        {
            return Err("invalid target id");
        }
    }
    if event.ip_address.as_ref().is_some_and(|ip| ip.len() > 45) {
        return Err("invalid IP address");
    }
    let detail = serde_json::to_vec(&event.detail).map_err(|_| "detail serialization failed")?;
    if detail.len() > MAX_DETAIL_BYTES {
        return Err("detail exceeds size limit");
    }
    Ok(())
}

pub fn redact_value(value: Value) -> Value {
    match value {
        Value::Object(values) => Value::Object(
            values
                .into_iter()
                .map(|(key, value)| {
                    let value = if is_sensitive_key(&key) {
                        Value::String("<redacted>".to_string())
                    } else {
                        redact_value(value)
                    };
                    (key, value)
                })
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.into_iter().map(redact_value).collect()),
        other => other,
    }
}

fn is_sensitive_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("password")
        || key.contains("token")
        || key.contains("jwt")
        || key.contains("secret")
        || key.contains("authorization")
        || key.contains("cookie")
        || (key.contains("license") && key.contains("key"))
}

fn safe_action_for_log(action: &str) -> String {
    action
        .chars()
        .filter(|ch| !ch.is_control())
        .take(MAX_ACTION_CHARS)
        .collect()
}

pub fn resource_fingerprint(value: &str) -> String {
    let digest = sha256::hash(value.as_bytes());
    HEXLOWER.encode(&digest.0[..16])
}

#[derive(Debug, Serialize)]
pub struct AuditLogItem {
    pub id: i64,
    pub user_id: Option<i64>,
    pub action: String,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub detail: Value,
    pub ip_address: Option<String>,
    pub created_at: NaiveDateTime,
}

impl From<AuditLogRow> for AuditLogItem {
    fn from(row: AuditLogRow) -> Self {
        let detail = row
            .detail
            .as_deref()
            .and_then(|detail| serde_json::from_str::<Value>(detail).ok())
            .filter(|detail| detail.is_object() || detail.is_array())
            .map(redact_value)
            .unwrap_or(Value::Null);
        Self {
            id: row.id,
            user_id: row.user_id,
            action: row.action,
            target_type: row.target_type,
            target_id: row.target_id,
            detail,
            ip_address: row.ip_address,
            created_at: row.created_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn recursive_redaction_removes_sensitive_values() {
        let sentinel = "sentinel-secret-value";
        let redacted = redact_value(json!({
            "password": sentinel,
            "nested": [{"refresh_token": sentinel}, {"license_key": sentinel}],
            "safe": "visible"
        }));
        let text = serde_json::to_string(&redacted).unwrap();
        assert!(!text.contains(sentinel));
        assert!(text.contains("visible"));
    }

    #[test]
    fn resource_fingerprint_is_fixed_length_and_irreversible_output() {
        let source = "device-and-user-secret";
        let fingerprint = resource_fingerprint(source);
        assert_eq!(fingerprint.len(), 32);
        assert!(!fingerprint.contains(source));
    }

    #[test]
    fn legacy_scalar_details_are_not_returned() {
        let row = AuditLogRow {
            id: 1,
            user_id: None,
            action: "legacy".to_string(),
            target_type: None,
            target_id: None,
            detail: Some("\"unstructured-secret\"".to_string()),
            ip_address: None,
            created_at: Utc::now().naive_utc(),
        };
        assert_eq!(AuditLogItem::from(row).detail, Value::Null);
    }

    #[test]
    fn audit_filter_redaction_and_retention_work_together() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir()
                .join(format!("hbbs-audit-{nonce}.sqlite"))
                .to_string_lossy()
                .into_owned();
            let db = Database::new(&path).await.unwrap();
            let actor = db
                .create_user("audit-actor", "test-hash", None, "admin")
                .await
                .unwrap();
            let sentinel = "sentinel-plain-password";
            let mut old = AuditEvent::new("auth.login.failure")
                .target("user", "old")
                .detail(json!({"password": sentinel}));
            old.occurred_at = (Utc::now() - chrono::Duration::days(200)).naive_utc();
            db.insert_audit_event(&old).await.unwrap();
            let recent = AuditEvent::new("user.create")
                .actor(actor.id)
                .target("user", "8")
                .detail(redact_value(json!({"password": sentinel, "role": "user"})));
            db.insert_audit_event(&recent).await.unwrap();

            let (rows, total) = db
                .list_audit_logs(&AuditLogFilter {
                    action: Some("user.create".to_string()),
                    target_type: Some("user".to_string()),
                    user_id: Some(actor.id),
                    page: 1,
                    page_size: 50,
                    ..AuditLogFilter::default()
                })
                .await
                .unwrap();
            assert_eq!(total, 1);
            let item = AuditLogItem::from(rows.into_iter().next().unwrap());
            assert!(!serde_json::to_string(&item).unwrap().contains(sentinel));

            assert_eq!(db.delete_expired_audit_logs(180).await.unwrap(), 1);
            let (_, total) = db
                .list_audit_logs(&AuditLogFilter {
                    page: 1,
                    page_size: 50,
                    ..AuditLogFilter::default()
                })
                .await
                .unwrap();
            assert_eq!(total, 1);
            drop(db);
            for suffix in ["", "-shm", "-wal", ".migration.lock"] {
                let _ = std::fs::remove_file(format!("{path}{suffix}"));
            }
        });
    }
}
