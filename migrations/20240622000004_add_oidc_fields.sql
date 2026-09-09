ALTER TABLE users ADD COLUMN oauth_provider VARCHAR(100);
ALTER TABLE users ADD COLUMN oauth_subject VARCHAR(255);
ALTER TABLE users ADD COLUMN last_login_at DATETIME;

CREATE INDEX IF NOT EXISTS idx_users_oauth ON users (oauth_provider, oauth_subject);
CREATE INDEX IF NOT EXISTS idx_users_last_login_at ON users (last_login_at);
