-- Issue #9：服务端权威地址簿、共享状态机与连续增量日志。
ALTER TABLE users ADD COLUMN address_book_version INTEGER NOT NULL DEFAULT 0
    CHECK(
        typeof(address_book_version) = 'integer'
        AND address_book_version BETWEEN 0 AND 9007199254740991
    );

-- device_shares 通过复合外键同时绑定设备行、外部 ID 与生命周期。
CREATE UNIQUE INDEX idx_devices_address_book_identity
    ON devices(id, management_generation, device_id);

CREATE TABLE device_shares (
    id INTEGER PRIMARY KEY AUTOINCREMENT
        CHECK(id BETWEEN 1 AND 9007199254740991),
    device_row_id INTEGER NOT NULL,
    device_lifecycle TEXT NOT NULL
        CHECK(length(device_lifecycle) = 32
              AND device_lifecycle = lower(device_lifecycle)
              AND device_lifecycle NOT GLOB '*[^0-9a-f]*'),
    device_id TEXT NOT NULL
        CHECK(length(device_id) BETWEEN 1 AND 100),
    from_user_id INTEGER NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,
    to_user_id INTEGER NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,
    permission TEXT NOT NULL
        CHECK(permission IN ('view_only', 'full_control')),
    status TEXT NOT NULL
        CHECK(status IN ('pending', 'accepted', 'rejected')),
    created_at DATETIME NOT NULL DEFAULT current_timestamp,
    updated_at DATETIME NOT NULL DEFAULT current_timestamp,
    UNIQUE(device_row_id, to_user_id),
    CHECK(from_user_id <> to_user_id),
    FOREIGN KEY(device_row_id, device_lifecycle, device_id)
        REFERENCES devices(id, management_generation, device_id)
        ON UPDATE CASCADE ON DELETE CASCADE
);

CREATE INDEX idx_device_shares_recipient_status_id
    ON device_shares(to_user_id, status, id);
CREATE INDEX idx_device_shares_owner_device_status
    ON device_shares(from_user_id, device_row_id, status);
CREATE INDEX idx_device_shares_device_recipient
    ON device_shares(device_id, to_user_id);

CREATE TABLE address_book_changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,
    version INTEGER NOT NULL
        CHECK(
            typeof(version) = 'integer'
            AND version BETWEEN 1 AND 9007199254740991
        ),
    device_row_id INTEGER
        REFERENCES devices(id) ON DELETE SET NULL,
    device_lifecycle TEXT NOT NULL
        CHECK(length(device_lifecycle) = 32
              AND device_lifecycle = lower(device_lifecycle)
              AND device_lifecycle NOT GLOB '*[^0-9a-f]*'),
    device_id TEXT NOT NULL
        CHECK(length(device_id) BETWEEN 1 AND 100),
    share_id INTEGER
        CHECK(share_id IS NULL OR share_id BETWEEN 1 AND 9007199254740991),
    operation TEXT NOT NULL
        CHECK(operation IN ('upsert', 'delete')),
    payload TEXT,
    created_at DATETIME NOT NULL DEFAULT current_timestamp,
    UNIQUE(user_id, version),
    CHECK(
        (operation = 'upsert' AND payload IS NOT NULL)
        OR (operation = 'delete' AND payload IS NULL)
    )
);

CREATE INDEX idx_ab_changes_user_lifecycle_version
    ON address_book_changes(user_id, device_lifecycle, version DESC);

CREATE TABLE address_book_backfill_state (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    completed INTEGER NOT NULL DEFAULT 0 CHECK(completed IN (0, 1))
);

INSERT INTO address_book_backfill_state(id, completed) VALUES(1, 0);

-- share 的 owner 必须始终等于设备当前 owner。
CREATE TRIGGER device_share_owner_insert
BEFORE INSERT ON device_shares
WHEN NOT EXISTS (
    SELECT 1
    FROM devices
    WHERE id = NEW.device_row_id
      AND management_generation = NEW.device_lifecycle
      AND device_id = NEW.device_id
      AND owner_user_id = NEW.from_user_id
)
BEGIN
    SELECT RAISE(ABORT, 'device_share_owner_mismatch');
END;

CREATE TRIGGER device_share_owner_update
BEFORE UPDATE OF device_row_id, device_lifecycle, device_id, from_user_id
ON device_shares
WHEN NOT EXISTS (
    SELECT 1
    FROM devices
    WHERE id = NEW.device_row_id
      AND management_generation = NEW.device_lifecycle
      AND device_id = NEW.device_id
      AND owner_user_id = NEW.from_user_id
)
BEGIN
    SELECT RAISE(ABORT, 'device_share_owner_mismatch');
END;

-- 变化日志不可修改；每条新日志必须紧跟用户版本并保持从 1 连续。
CREATE TRIGGER address_book_change_insert_valid
BEFORE INSERT ON address_book_changes
WHEN NOT EXISTS (
        SELECT 1
        FROM users
        WHERE id = NEW.user_id
          AND address_book_version = NEW.version
    )
 OR COALESCE(
        (
            SELECT MAX(version)
            FROM address_book_changes
            WHERE user_id = NEW.user_id
        ),
        0
    ) <> NEW.version - 1
BEGIN
    SELECT RAISE(ABORT, 'address_book_change_not_contiguous');
END;

CREATE TRIGGER address_book_change_immutable_update
BEFORE UPDATE ON address_book_changes
WHEN NOT (
       OLD.device_row_id IS NOT NULL
   AND NEW.device_row_id IS NULL
   AND NEW.id IS OLD.id
   AND NEW.user_id IS OLD.user_id
   AND NEW.version IS OLD.version
   AND NEW.device_lifecycle IS OLD.device_lifecycle
   AND NEW.device_id IS OLD.device_id
   AND NEW.share_id IS OLD.share_id
   AND NEW.operation IS OLD.operation
   AND NEW.payload IS OLD.payload
   AND NEW.created_at IS OLD.created_at
)
BEGIN
    SELECT RAISE(ABORT, 'address_book_change_immutable');
END;

CREATE TRIGGER address_book_change_immutable_delete
BEFORE DELETE ON address_book_changes
BEGIN
    SELECT RAISE(ABORT, 'address_book_change_immutable');
END;

-- 既有 users 表无法补表级 CHECK，因此用触发器封住后续越界写。
CREATE TRIGGER users_wire_range_insert
AFTER INSERT ON users
WHEN typeof(NEW.id) <> 'integer'
 OR NEW.id NOT BETWEEN 1 AND 9007199254740991
 OR typeof(NEW.token_version) <> 'integer'
 OR NEW.token_version NOT BETWEEN 0 AND 9007199254740991
 OR typeof(NEW.address_book_version) <> 'integer'
 OR NEW.address_book_version NOT BETWEEN 0 AND 9007199254740991
BEGIN
    SELECT RAISE(ABORT, 'user_wire_integer_out_of_range');
END;

CREATE TRIGGER users_wire_range_update
BEFORE UPDATE OF id, token_version, address_book_version ON users
WHEN typeof(NEW.id) <> 'integer'
 OR NEW.id NOT BETWEEN 1 AND 9007199254740991
 OR typeof(NEW.token_version) <> 'integer'
 OR NEW.token_version NOT BETWEEN 0 AND 9007199254740991
 OR typeof(NEW.address_book_version) <> 'integer'
 OR NEW.address_book_version NOT BETWEEN 0 AND 9007199254740991
BEGIN
    SELECT RAISE(ABORT, 'user_wire_integer_out_of_range');
END;
