-- Issue #7：设备状态是配额唯一真值。重建表以确保历史库也获得 NOT NULL 与 CHECK 约束。
CREATE TABLE devices_quota_v2 (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    guid BLOB NOT NULL UNIQUE,
    uuid BLOB NOT NULL,
    pk BLOB NOT NULL,
    device_id VARCHAR(100) NOT NULL UNIQUE,
    owner_user_id INTEGER REFERENCES users(id),
    group_id INTEGER REFERENCES groups(id),
    device_name VARCHAR(200),
    os VARCHAR(100),
    note VARCHAR(300),
    info TEXT NOT NULL,
    features TEXT,
    token_version INTEGER NOT NULL DEFAULT 0,
    is_online BOOLEAN NOT NULL DEFAULT 0,
    last_online_at DATETIME,
    status TEXT NOT NULL DEFAULT 'offline'
        CHECK(status IN ('online', 'offline', 'inactive')),
    last_seen DATETIME NOT NULL DEFAULT (current_timestamp),
    created_at DATETIME NOT NULL DEFAULT (current_timestamp),
    updated_at DATETIME NOT NULL DEFAULT (current_timestamp)
);

INSERT INTO devices_quota_v2 (
    id, guid, uuid, pk, device_id, owner_user_id, group_id, device_name, os,
    note, info, features, token_version, is_online, last_online_at,
    status, last_seen, created_at, updated_at
)
SELECT
    id, guid, uuid, pk, device_id, owner_user_id, group_id, device_name, os,
    note, info, features, token_version, 0, last_online_at,
    'offline', current_timestamp, created_at, updated_at
FROM devices;

DROP TABLE devices;
ALTER TABLE devices_quota_v2 RENAME TO devices;

CREATE UNIQUE INDEX idx_devices_guid ON devices (guid);
CREATE UNIQUE INDEX idx_devices_device_id ON devices (device_id);
CREATE INDEX idx_devices_owner_user_id ON devices (owner_user_id);
CREATE INDEX idx_devices_group_id ON devices (group_id);
CREATE INDEX idx_devices_created_at ON devices (created_at);
CREATE INDEX idx_devices_status_last_seen ON devices (status, last_seen);

-- SQLite 设备配额及许可证切换共用的单行写锁。
CREATE TABLE device_quota_lock (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    version INTEGER NOT NULL DEFAULT 0
);
INSERT INTO device_quota_lock(id, version) VALUES(1, 0);
