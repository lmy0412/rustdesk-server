-- Issue #8：设备分组、标签、公开生命周期令牌与 durable 删除回执。
ALTER TABLE devices ADD COLUMN alias TEXT;
ALTER TABLE devices ADD COLUMN management_generation TEXT;

UPDATE devices
SET management_generation = lower(hex(randomblob(16)))
WHERE management_generation IS NULL;

CREATE UNIQUE INDEX idx_devices_management_generation
    ON devices(management_generation);

CREATE TABLE tags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_user_id INTEGER NOT NULL REFERENCES users(id),
    name TEXT NOT NULL COLLATE NOCASE
        CHECK(name = trim(name) AND length(name) BETWEEN 1 AND 64),
    created_at DATETIME NOT NULL DEFAULT current_timestamp,
    updated_at DATETIME NOT NULL DEFAULT current_timestamp
);

CREATE UNIQUE INDEX idx_tags_owner_name
    ON tags(owner_user_id, name COLLATE NOCASE);

CREATE TABLE device_tags (
    device_row_id INTEGER NOT NULL
        REFERENCES devices(id) ON DELETE CASCADE,
    tag_id INTEGER NOT NULL
        REFERENCES tags(id) ON DELETE CASCADE,
    created_at DATETIME NOT NULL DEFAULT current_timestamp,
    PRIMARY KEY(device_row_id, tag_id)
);

CREATE INDEX idx_device_tags_tag_device
    ON device_tags(tag_id, device_row_id);

CREATE TABLE device_deletion_outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_user_id INTEGER NOT NULL REFERENCES users(id),
    device_id TEXT NOT NULL,
    management_generation TEXT NOT NULL
        CHECK(length(management_generation) = 32
              AND management_generation = lower(management_generation)
              AND management_generation NOT GLOB '*[^0-9a-f]*'),
    deleted_guid BLOB NOT NULL CHECK(length(deleted_guid) = 16),
    state TEXT NOT NULL DEFAULT 'pending'
        CHECK(state IN ('pending', 'completed')),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0),
    next_attempt_at DATETIME NOT NULL DEFAULT current_timestamp,
    lease_token TEXT,
    lease_until DATETIME,
    completed_at DATETIME,
    expires_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT current_timestamp,
    updated_at DATETIME NOT NULL DEFAULT current_timestamp,
    UNIQUE(actor_user_id, device_id, management_generation)
);

CREATE INDEX idx_device_deletion_outbox_due
    ON device_deletion_outbox(state, next_attempt_at, id);
CREATE INDEX idx_device_deletion_outbox_expiry
    ON device_deletion_outbox(expires_at, id);

CREATE TABLE inventory_write_lock (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    version INTEGER NOT NULL DEFAULT 0
);

INSERT INTO inventory_write_lock(id, version) VALUES(1, 0);

CREATE INDEX idx_groups_owner_parent_id
    ON groups(owner_user_id, parent_group_id, id);
CREATE INDEX idx_devices_owner_group_id
    ON devices(owner_user_id, group_id, id);
CREATE INDEX idx_devices_owner_status_id
    ON devices(owner_user_id, status, id);

-- 每次新插入的设备都获得新的公开生命周期令牌。
CREATE TRIGGER device_management_generation_fill
AFTER INSERT ON devices
WHEN NEW.management_generation IS NULL
BEGIN
    UPDATE devices
    SET management_generation = lower(hex(randomblob(16)))
    WHERE id = NEW.id;
END;

CREATE TRIGGER device_management_generation_insert_valid
BEFORE INSERT ON devices
WHEN NEW.management_generation IS NOT NULL
 AND (length(NEW.management_generation) <> 32
      OR NEW.management_generation <> lower(NEW.management_generation)
      OR NEW.management_generation GLOB '*[^0-9a-f]*')
BEGIN
    SELECT RAISE(ABORT, 'device_management_generation_invalid');
END;

CREATE TRIGGER device_management_generation_update_valid
BEFORE UPDATE OF management_generation ON devices
WHEN OLD.management_generation IS NULL
 AND NEW.management_generation IS NOT NULL
 AND (length(NEW.management_generation) <> 32
      OR NEW.management_generation <> lower(NEW.management_generation)
      OR NEW.management_generation GLOB '*[^0-9a-f]*')
BEGIN
    SELECT RAISE(ABORT, 'device_management_generation_invalid');
END;

CREATE TRIGGER device_management_generation_immutable
BEFORE UPDATE OF management_generation ON devices
WHEN OLD.management_generation IS NOT NULL
 AND OLD.management_generation IS NOT NEW.management_generation
BEGIN
    SELECT RAISE(ABORT, 'device_management_generation_immutable');
END;

-- group owner 创建后不可修改。
CREATE TRIGGER group_owner_immutable
BEFORE UPDATE OF owner_user_id ON groups
WHEN OLD.owner_user_id IS NOT NEW.owner_user_id
BEGIN
    SELECT RAISE(ABORT, 'group_owner_immutable');
END;

CREATE TRIGGER group_parent_owner_insert
BEFORE INSERT ON groups
WHEN NEW.parent_group_id IS NOT NULL
 AND NOT EXISTS (
     SELECT 1
     FROM groups parent
     WHERE parent.id = NEW.parent_group_id
       AND parent.owner_user_id = NEW.owner_user_id
 )
BEGIN
    SELECT RAISE(ABORT, 'group_parent_owner_mismatch');
END;

CREATE TRIGGER group_parent_owner_update
BEFORE UPDATE OF parent_group_id, owner_user_id ON groups
WHEN OLD.owner_user_id IS NEW.owner_user_id
 AND NEW.parent_group_id IS NOT NULL
 AND NOT EXISTS (
     SELECT 1
     FROM groups parent
     WHERE parent.id = NEW.parent_group_id
       AND parent.owner_user_id = NEW.owner_user_id
 )
BEGIN
    SELECT RAISE(ABORT, 'group_parent_owner_mismatch');
END;

CREATE TRIGGER group_cycle
BEFORE UPDATE OF parent_group_id ON groups
WHEN NEW.parent_group_id IS NOT NULL
 AND EXISTS (
     WITH RECURSIVE descendants(id) AS (
         SELECT NEW.id
         UNION
         SELECT child.id
         FROM groups child
         JOIN descendants current ON child.parent_group_id = current.id
     )
     SELECT 1
     FROM descendants
     WHERE id = NEW.parent_group_id
 )
BEGIN
    SELECT RAISE(ABORT, 'group_cycle');
END;

CREATE TRIGGER group_depth_insert
BEFORE INSERT ON groups
WHEN (
    1 + (
        WITH RECURSIVE ancestors(id) AS (
            SELECT NEW.parent_group_id
            WHERE NEW.parent_group_id IS NOT NULL
            UNION
            SELECT parent.parent_group_id
            FROM groups parent
            JOIN ancestors current ON parent.id = current.id
            WHERE parent.parent_group_id IS NOT NULL
        )
        SELECT COUNT(*) FROM ancestors
    )
) > 256
BEGIN
    SELECT RAISE(ABORT, 'group_depth_exceeded');
END;

CREATE TRIGGER group_depth_update
BEFORE UPDATE OF parent_group_id ON groups
WHEN NEW.parent_group_id IS NOT OLD.parent_group_id
 AND NOT EXISTS (
     WITH RECURSIVE descendants(id) AS (
         SELECT NEW.id
         UNION
         SELECT child.id
         FROM groups child
         JOIN descendants current ON child.parent_group_id = current.id
     )
     SELECT 1
     FROM descendants
     WHERE id = NEW.parent_group_id
 )
 AND (
    (
        WITH RECURSIVE ancestors(id) AS (
            SELECT NEW.parent_group_id
            WHERE NEW.parent_group_id IS NOT NULL
            UNION
            SELECT parent.parent_group_id
            FROM groups parent
            JOIN ancestors current ON parent.id = current.id
            WHERE parent.parent_group_id IS NOT NULL
        )
        SELECT COUNT(*) FROM ancestors
    )
    +
    (
        WITH RECURSIVE descendants(id, depth) AS (
            SELECT NEW.id, 1
            UNION ALL
            SELECT child.id, current.depth + 1
            FROM groups child
            JOIN descendants current ON child.parent_group_id = current.id
            WHERE current.depth <= 256
        )
        SELECT COALESCE(MAX(depth), 1) FROM descendants
    )
 ) > 256
BEGIN
    SELECT RAISE(ABORT, 'group_depth_exceeded');
END;

CREATE TRIGGER device_group_owner_insert
BEFORE INSERT ON devices
WHEN NEW.group_id IS NOT NULL
 AND (
     NEW.owner_user_id IS NULL
     OR NOT EXISTS (
         SELECT 1
         FROM groups
         WHERE id = NEW.group_id
           AND owner_user_id = NEW.owner_user_id
     )
 )
BEGIN
    SELECT RAISE(ABORT, 'device_group_owner_mismatch');
END;

CREATE TRIGGER device_group_owner_update
BEFORE UPDATE OF group_id, owner_user_id ON devices
WHEN NEW.group_id IS NOT NULL
 AND (
     OLD.owner_user_id IS NEW.owner_user_id
     OR NOT EXISTS (
         SELECT 1 FROM device_tags WHERE device_row_id = OLD.id
     )
 )
 AND (
     NEW.owner_user_id IS NULL
     OR NOT EXISTS (
         SELECT 1
         FROM groups
         WHERE id = NEW.group_id
           AND owner_user_id = NEW.owner_user_id
     )
 )
BEGIN
    SELECT RAISE(ABORT, 'device_group_owner_mismatch');
END;

CREATE TRIGGER device_owner_change_with_tags
BEFORE UPDATE OF owner_user_id ON devices
WHEN OLD.owner_user_id IS NOT NEW.owner_user_id
 AND EXISTS (
     SELECT 1 FROM device_tags WHERE device_row_id = OLD.id
 )
BEGIN
    SELECT RAISE(ABORT, 'device_owner_change_with_tags');
END;

CREATE TRIGGER tag_owner_immutable
BEFORE UPDATE OF owner_user_id ON tags
WHEN OLD.owner_user_id IS NOT NEW.owner_user_id
BEGIN
    SELECT RAISE(ABORT, 'tag_owner_immutable');
END;

CREATE TRIGGER device_tag_unowned_insert
BEFORE INSERT ON device_tags
WHEN NOT EXISTS (
    SELECT 1
    FROM devices
    WHERE id = NEW.device_row_id
      AND owner_user_id IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'device_tag_unowned_device');
END;

CREATE TRIGGER device_tag_owner_insert
BEFORE INSERT ON device_tags
WHEN EXISTS (
    SELECT 1
    FROM devices
    WHERE id = NEW.device_row_id
      AND owner_user_id IS NOT NULL
)
 AND NOT EXISTS (
    SELECT 1
    FROM devices device
    JOIN tags tag ON tag.id = NEW.tag_id
    WHERE device.id = NEW.device_row_id
      AND device.owner_user_id = tag.owner_user_id
)
BEGIN
    SELECT RAISE(ABORT, 'device_tag_owner_mismatch');
END;

CREATE TRIGGER device_tag_unowned_update
BEFORE UPDATE OF device_row_id, tag_id ON device_tags
WHEN NOT EXISTS (
    SELECT 1
    FROM devices
    WHERE id = NEW.device_row_id
      AND owner_user_id IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'device_tag_unowned_device');
END;

CREATE TRIGGER device_tag_owner_update
BEFORE UPDATE OF device_row_id, tag_id ON device_tags
WHEN EXISTS (
    SELECT 1
    FROM devices
    WHERE id = NEW.device_row_id
      AND owner_user_id IS NOT NULL
)
 AND NOT EXISTS (
    SELECT 1
    FROM devices device
    JOIN tags tag ON tag.id = NEW.tag_id
    WHERE device.id = NEW.device_row_id
      AND device.owner_user_id = tag.owner_user_id
)
BEGIN
    SELECT RAISE(ABORT, 'device_tag_owner_mismatch');
END;
