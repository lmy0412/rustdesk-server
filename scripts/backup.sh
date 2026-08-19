#!/bin/sh
set -eu

umask 077

usage() {
    cat <<'EOF'
用法：backup.sh [选项]
  --output FILE          备份包路径，默认 ./rustdesk-pro-UTC时间.tar.gz
  --database-url URL     PostgreSQL URL；省略时备份 SQLite
  --database-path FILE   SQLite 文件，默认 /var/lib/rustdesk-server/db_v2.sqlite3
  --config FILE          配置文件，默认 /etc/rustdesk-server/config.toml
  --license FILE         可选许可证文件，默认 /var/lib/rustdesk-server/license
  --key FILE             可重复，默认备份 id_ed25519 与 id_ed25519.pub
EOF
}

OUTPUT=""
DATABASE_URL=${RUSTDESK_DATABASE_URL:-}
DATABASE_PATH=${RUSTDESK_DATABASE_PATH:-/var/lib/rustdesk-server/db_v2.sqlite3}
CONFIG_FILE=${RUSTDESK_CONFIG_FILE:-/etc/rustdesk-server/config.toml}
LICENSE_FILE=${RUSTDESK_LICENSE_FILE:-/var/lib/rustdesk-server/license}
KEY_FILES=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --output) OUTPUT=${2:?--output 缺少值}; shift 2 ;;
        --database-url) DATABASE_URL=${2:?--database-url 缺少值}; shift 2 ;;
        --database-path) DATABASE_PATH=${2:?--database-path 缺少值}; shift 2 ;;
        --config) CONFIG_FILE=${2:?--config 缺少值}; shift 2 ;;
        --license) LICENSE_FILE=${2:?--license 缺少值}; shift 2 ;;
        --key) KEY_FILES="${KEY_FILES}${KEY_FILES:+
}${2:?--key 缺少值}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "未知参数：$1" >&2; usage >&2; exit 2 ;;
    esac
done

if [ -z "$OUTPUT" ]; then
    OUTPUT="./rustdesk-pro-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
fi

case "$OUTPUT" in
    *.tar.gz) ;;
    *) echo "输出文件必须以 .tar.gz 结尾" >&2; exit 2 ;;
esac

if [ ! -f "$CONFIG_FILE" ]; then
    echo "配置文件不存在：$CONFIG_FILE" >&2
    exit 1
fi

OUTPUT_DIR=$(dirname "$OUTPUT")
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR=$(CDPATH= cd -- "$OUTPUT_DIR" && pwd)
OUTPUT="$OUTPUT_DIR/$(basename "$OUTPUT")"
LOCK_DIR="$OUTPUT.lock"
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    echo "已有备份任务或残留锁：$LOCK_DIR" >&2
    exit 1
fi

STAGING=$(mktemp -d "${TMPDIR:-/tmp}/rustdesk-pro-backup.XXXXXX")
TEMP_ARCHIVE="$OUTPUT.tmp.$$"
cleanup() {
    rm -rf "$STAGING"
    rm -f "$TEMP_ARCHIVE"
    rmdir "$LOCK_DIR" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$STAGING/database" "$STAGING/config" "$STAGING/license" "$STAGING/keys"

BACKEND=sqlite
if [ -n "$DATABASE_URL" ]; then
    case "$DATABASE_URL" in
        postgres://*|postgresql://*) BACKEND=postgresql ;;
        *) echo "仅支持 postgres:// 或 postgresql:// 数据库 URL" >&2; exit 2 ;;
    esac
fi

if [ "$BACKEND" = sqlite ]; then
    command -v sqlite3 >/dev/null 2>&1 || { echo "缺少 sqlite3" >&2; exit 1; }
    [ -f "$DATABASE_PATH" ] || { echo "SQLite 文件不存在：$DATABASE_PATH" >&2; exit 1; }
    case "$STAGING" in *"'"*) echo "临时目录包含不受支持的单引号" >&2; exit 1 ;; esac
    sqlite3 "$DATABASE_PATH" ".timeout 5000" ".backup '$STAGING/database/sqlite.db'"
    printf '%s\n' sqlite > "$STAGING/database/backend"
else
    command -v pg_dump >/dev/null 2>&1 || { echo "缺少 pg_dump" >&2; exit 1; }
    pg_dump --format=custom --no-owner --no-privileges --file="$STAGING/database/postgresql.dump" "$DATABASE_URL"
    printf '%s\n' postgresql > "$STAGING/database/backend"
fi

cp -p "$CONFIG_FILE" "$STAGING/config/config.toml"
if [ -f "$LICENSE_FILE" ]; then
    cp -p "$LICENSE_FILE" "$STAGING/license/$(basename "$LICENSE_FILE")"
fi

if [ -z "$KEY_FILES" ]; then
    KEY_FILES="/var/lib/rustdesk-server/id_ed25519
/var/lib/rustdesk-server/id_ed25519.pub"
fi
OLD_IFS=$IFS
IFS='
'
for key_file in $KEY_FILES; do
    [ -n "$key_file" ] || continue
    if [ -f "$key_file" ]; then
        cp -p "$key_file" "$STAGING/keys/$(basename "$key_file")"
    fi
done
IFS=$OLD_IFS

cat > "$STAGING/manifest.txt" <<EOF
format=rustdesk-pro-backup-v1
created_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
database_backend=$BACKEND
config_included=true
license_included=$([ -f "$LICENSE_FILE" ] && echo true || echo false)
EOF

(
    cd "$STAGING"
    find database config license keys -type f -print | LC_ALL=C sort | xargs sha256sum > checksums.sha256
)

tar -C "$STAGING" -czf "$TEMP_ARCHIVE" .
chmod 0600 "$TEMP_ARCHIVE"
mv "$TEMP_ARCHIVE" "$OUTPUT"
trap - EXIT HUP INT TERM
cleanup
echo "$OUTPUT"
