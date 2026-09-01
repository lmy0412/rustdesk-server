ALTER TABLE users ADD COLUMN failed_login_count INTEGER NOT NULL DEFAULT 0
    CHECK (failed_login_count >= 0);
ALTER TABLE users ADD COLUMN locked_until DATETIME;

CREATE INDEX IF NOT EXISTS idx_users_locked_until
    ON users (locked_until)
    WHERE locked_until IS NOT NULL;

CREATE TABLE IF NOT EXISTS security_policies (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    password_min_length INTEGER NOT NULL CHECK (password_min_length BETWEEN 1 AND 1024),
    password_require_number BOOLEAN NOT NULL,
    password_require_symbol BOOLEAN NOT NULL,
    login_max_failures INTEGER NOT NULL CHECK (login_max_failures BETWEEN 1 AND 100),
    login_lock_minutes INTEGER NOT NULL CHECK (login_lock_minutes BETWEEN 1 AND 10080),
    session_timeout_minutes INTEGER NOT NULL CHECK (session_timeout_minutes BETWEEN 1 AND 525600),
    allowed_admin_cidrs TEXT NOT NULL CHECK (json_valid(allowed_admin_cidrs)),
    audit_retention_days INTEGER NOT NULL CHECK (audit_retention_days BETWEEN 1 AND 3650),
    updated_at DATETIME NOT NULL DEFAULT (current_timestamp)
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_resource_created_at
    ON audit_logs (resource_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_created_at
    ON audit_logs (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action_created_at
    ON audit_logs (action, created_at DESC);
