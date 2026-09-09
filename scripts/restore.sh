#!/bin/sh
set -eu

umask 077

usage() {
    cat <<'EOF'
用法：restore.sh --archive FILE [选项]
  --target-dir DIR       配置、许可证、密钥和 SQLite 的恢复根目录
                         默认 /var/lib/rustdesk-server
  --database-url URL     将 PostgreSQL dump 恢复到此 URL
  --health-url URL       恢复并启动服务后检查，默认 http://127.0.0.1:21114/api/health
  --start-services       恢复后通过 systemctl 启动 hbbs/hbbr 并执行健康检查
  --allow-running        跳过 systemd 服务停止检查（仅限隔离环境）
EOF
}

ARCHIVE=""
TARGET_DIR=${RUSTDESK_RESTORE_DIR:-/var/lib/rustdesk-server}
DATABASE_URL=${RUSTDESK_DATABASE_URL:-}
HEALTH_URL=${RUSTDESK_HEALTH_URL:-http://127.0.0.1:21114/api/health}
START_SERVICES=false
ALLOW_RUNNING=false

while [ "$#" -gt 0 ]; do
    case "$1" in
        --archive) ARCHIVE=${2:?--archive 缺少值}; shift 2 ;;
        --target-dir) TARGET_DIR=${2:?--target-dir 缺少值}; shift 2 ;;
        --database-url) DATABASE_URL=${2:?--database-url 缺少值}; shift 2 ;;
        --health-url) HEALTH_URL=${2:?--health-url 缺少值}; shift 2 ;;
        --start-services) START_SERVICES=true; shift ;;
        --allow-running) ALLOW_RUNNING=true; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "未知参数：$1" >&2; usage >&2; exit 2 ;;
    esac
done

[ -n "$ARCHIVE" ] || { echo "必须提供 --archive" >&2; exit 2; }
[ -f "$ARCHIVE" ] || { echo "备份包不存在：$ARCHIVE" >&2; exit 1; }

if command -v systemctl >/dev/null 2>&1 && [ "$ALLOW_RUNNING" != true ]; then
    for service in rustdesk-hbbs-pro.service rustdesk-hbbr-pro.service; do
        if systemctl is-active --quiet "$service"; then
            echo "$service 仍在运行；请先停止服务" >&2
            exit 1
        fi
    done
fi

if tar -tzf "$ARCHIVE" | awk '
    BEGIN { bad=0 }
    /^\// { bad=1 }
    { n=split($0,p,"/"); for(i=1;i<=n;i++) if(p[i]=="..") bad=1 }
    END { exit bad ? 0 : 1 }
'; then
    echo "备份包包含绝对路径或路径穿越条目" >&2
    exit 1
fi
if tar -tvzf "$ARCHIVE" | awk 'substr($1,1,1) == "l" || substr($1,1,1) == "h" { found=1 } END { exit found ? 0 : 1 }'; then
    echo "备份包包含链接条目，拒绝恢复" >&2
    exit 1
fi

STAGING=$(mktemp -d "${TMPDIR:-/tmp}/rustdesk-pro-restore.XXXXXX")
SNAPSHOT=""
SNAPSHOT_TEMP=""
cleanup() {
    rm -rf "$STAGING"
    [ -z "$SNAPSHOT_TEMP" ] || rm -f "$SNAPSHOT_TEMP"
}
trap cleanup EXIT HUP INT TERM

tar -C "$STAGING" -xzf "$ARCHIVE" --no-same-owner --no-same-permissions
[ -f "$STAGING/manifest.txt" ] || { echo "缺少 manifest.txt" >&2; exit 1; }
[ -f "$STAGING/checksums.sha256" ] || { echo "缺少 checksums.sha256" >&2; exit 1; }
grep -qx 'format=rustdesk-pro-backup-v1' "$STAGING/manifest.txt" || { echo "不支持的备份格式" >&2; exit 1; }
(
    cd "$STAGING"
    sha256sum -c checksums.sha256
)
[ -f "$STAGING/config/config.toml" ] || { echo "缺少 config/config.toml" >&2; exit 1; }

BACKEND=$(sed -n 's/^database_backend=//p' "$STAGING/manifest.txt")
case "$BACKEND" in
    sqlite|postgresql) ;;
    *) echo "未知数据库后端：$BACKEND" >&2; exit 1 ;;
esac

mkdir -p "$TARGET_DIR"
TARGET_DIR=$(CDPATH= cd -- "$TARGET_DIR" && pwd)
SNAPSHOT="$TARGET_DIR/.pre-restore-$(date -u +%Y%m%dT%H%M%SZ)-$$.tar.gz"
SNAPSHOT_TEMP=$(mktemp "${TMPDIR:-/tmp}/rustdesk-pro-pre-restore.XXXXXX.tar.gz")
tar -C "$TARGET_DIR" -czf "$SNAPSHOT_TEMP" \
    --exclude='.pre-restore-*.tar.gz' \
    --exclude='./.pre-restore-*.tar.gz' .
chmod 0600 "$SNAPSHOT_TEMP"
mv "$SNAPSHOT_TEMP" "$SNAPSHOT"
SNAPSHOT_TEMP=""

if [ "$BACKEND" = sqlite ]; then
    [ -f "$STAGING/database/sqlite.db" ] || { echo "缺少 SQLite 备份" >&2; exit 1; }
    command -v sqlite3 >/dev/null 2>&1 || { echo "缺少 sqlite3" >&2; exit 1; }
    sqlite3 "$STAGING/database/sqlite.db" 'PRAGMA quick_check;' | grep -qx ok || { echo "SQLite 完整性检查失败" >&2; exit 1; }
    install -m 0600 "$STAGING/database/sqlite.db" "$TARGET_DIR/db_v2.sqlite3.new"
    mv "$TARGET_DIR/db_v2.sqlite3.new" "$TARGET_DIR/db_v2.sqlite3"
else
    [ -n "$DATABASE_URL" ] || { echo "PostgreSQL 恢复必须提供 --database-url" >&2; exit 2; }
    command -v pg_restore >/dev/null 2>&1 || { echo "缺少 pg_restore" >&2; exit 1; }
    pg_restore --clean --if-exists --no-owner --no-privileges --exit-on-error --dbname="$DATABASE_URL" "$STAGING/database/postgresql.dump"
fi

install -m 0640 "$STAGING/config/config.toml" "$TARGET_DIR/config.toml.new"
mv "$TARGET_DIR/config.toml.new" "$TARGET_DIR/config.toml"
for source_dir in license keys; do
    if [ -d "$STAGING/$source_dir" ]; then
        find "$STAGING/$source_dir" -maxdepth 1 -type f -print | while IFS= read -r file; do
            install -m 0600 "$file" "$TARGET_DIR/$(basename "$file").new"
            mv "$TARGET_DIR/$(basename "$file").new" "$TARGET_DIR/$(basename "$file")"
        done
    fi
done

if [ "$START_SERVICES" = true ]; then
    command -v systemctl >/dev/null 2>&1 || { echo "无法启动服务：缺少 systemctl" >&2; exit 1; }
    systemctl start rustdesk-hbbr-pro.service rustdesk-hbbs-pro.service
    command -v curl >/dev/null 2>&1 || { echo "无法检查健康状态：缺少 curl" >&2; exit 1; }
    attempt=0
    until curl --fail --silent --show-error "$HEALTH_URL" >/dev/null; do
        attempt=$((attempt + 1))
        [ "$attempt" -lt 30 ] || { echo "恢复后健康检查失败；恢复前快照：$SNAPSHOT" >&2; exit 1; }
        sleep 2
    done
fi

trap - EXIT HUP INT TERM
cleanup
echo "恢复完成；恢复前快照：$SNAPSHOT"
