-- SQLite 不支持通用可靠的 ADD COLUMN IF NOT EXISTS。
-- users.token_version 由 Database::ensure_users_token_version_column 做应用层幂等补齐。
SELECT 1;
