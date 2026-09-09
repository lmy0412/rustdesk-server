CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    role VARCHAR(50) NOT NULL DEFAULT 'user',
    is_active BOOLEAN NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT (current_timestamp),
    updated_at DATETIME NOT NULL DEFAULT (current_timestamp)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users (username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);

CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(200) NOT NULL,
    owner_user_id INTEGER NOT NULL REFERENCES users(id),
    parent_group_id INTEGER REFERENCES groups(id),
    created_at DATETIME NOT NULL DEFAULT (current_timestamp),
    updated_at DATETIME NOT NULL DEFAULT (current_timestamp)
);

CREATE INDEX IF NOT EXISTS idx_groups_owner_user_id ON groups (owner_user_id);
CREATE INDEX IF NOT EXISTS idx_groups_parent_group_id ON groups (parent_group_id);

CREATE TABLE IF NOT EXISTS devices (
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
    created_at DATETIME NOT NULL DEFAULT (current_timestamp),
    updated_at DATETIME NOT NULL DEFAULT (current_timestamp)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_guid ON devices (guid);
CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_device_id ON devices (device_id);
CREATE INDEX IF NOT EXISTS idx_devices_owner_user_id ON devices (owner_user_id);
CREATE INDEX IF NOT EXISTS idx_devices_group_id ON devices (group_id);
CREATE INDEX IF NOT EXISTS idx_devices_created_at ON devices (created_at);
