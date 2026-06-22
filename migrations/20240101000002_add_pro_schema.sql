CREATE TABLE IF NOT EXISTS licenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_key VARCHAR(255) NOT NULL UNIQUE,
    user_id INTEGER REFERENCES users(id),
    device_limit INTEGER NOT NULL DEFAULT 5,
    issued_at DATETIME NOT NULL DEFAULT (current_timestamp),
    expires_at DATETIME,
    is_active BOOLEAN NOT NULL DEFAULT 1,
    features TEXT,
    created_at DATETIME NOT NULL DEFAULT (current_timestamp)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_licenses_license_key ON licenses (license_key);
CREATE INDEX IF NOT EXISTS idx_licenses_user_id ON licenses (user_id);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(255),
    detail TEXT,
    ip_address VARCHAR(45),
    created_at DATETIME NOT NULL DEFAULT (current_timestamp)
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs (user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs (action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs (created_at);
