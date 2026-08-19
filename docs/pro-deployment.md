# RustDesk Server Pro 生产部署与运维

本文覆盖 Docker Compose 与 systemd 两种部署方式，以及 SQLite/PostgreSQL、TLS、备份恢复、监控和故障处理。生产变更前请先在隔离环境演练备份和回滚。

## 1. 端口与目录

| 端口 | 协议 | 用途 |
| --- | --- | --- |
| 21114 | TCP/HTTP | Web 控制台、API、健康检查；只应向反向代理或管理网开放 |
| 21115 | TCP | NAT 类型测试 |
| 21116 | TCP/UDP | ID/心跳服务 |
| 21117 | TCP | Relay 服务 |
| 21118/21119 | TCP | WebSocket |

建议目录：配置 `/etc/rustdesk-server/config.toml`，环境变量 `/etc/rustdesk-server/rustdesk.env`，数据、密钥和可选许可证文件 `/var/lib/rustdesk-server/`。文件权限应为 `rustdesk:rustdesk`，目录 0750，秘密文件 0600。

## 2. Docker Compose

### 2.1 SQLite（默认）

```sh
cd docker
cp .env.example .env
# 编辑 .env，至少设置随机 JWT secret 和首次管理员密码
docker compose -f docker-compose.pro.yml config
docker compose -f docker-compose.pro.yml up -d --build hbbs hbbr
docker compose -f docker-compose.pro.yml ps
curl -fsS http://127.0.0.1:21114/api/health
```

健康响应中的 `db` 必须为 `sqlite`。首次管理员创建成功后，从 `.env` 删除 `RUSTDESK_INITIAL_ADMIN_PASSWORD` 并重建 hbbs 容器。

### 2.2 PostgreSQL

在 `.env` 中同时设置 `POSTGRES_PASSWORD` 与 URL 编码后的 `RUSTDESK_DATABASE_URL`：

```dotenv
POSTGRES_DB=rustdesk
POSTGRES_USER=rustdesk
POSTGRES_PASSWORD=use-a-secret-manager-in-production
RUSTDESK_DATABASE_URL=postgresql://rustdesk:use-a-url-encoded-password@postgres:5432/rustdesk
```

```sh
docker compose -f docker-compose.pro.yml --profile postgres config
docker compose -f docker-compose.pro.yml --profile postgres up -d postgres
docker compose -f docker-compose.pro.yml --profile postgres up -d --build hbbs hbbr
curl -fsS http://127.0.0.1:21114/api/health
```

健康响应中的 `db` 必须为 `postgresql`。Compose profile 只负责启动 PostgreSQL；未设置 `POSTGRES_PASSWORD` 时 PostgreSQL 容器会拒绝启动，未设置数据库 URL 时 hbbs 会继续使用 SQLite，因此必须检查容器状态和健康响应。PostgreSQL 模式可按容量提高 `MAX_DATABASE_CONNECTIONS`（例如 8），SQLite 应保持 1。生产环境建议使用 Docker secret、编排平台 secret 或独立托管 PostgreSQL，不要把真实密码提交到 `.env`。

## 3. systemd

```sh
sudo install -o root -g root -m 0755 target/release/hbbs target/release/hbbr /usr/local/bin/
sudo useradd --system --home /var/lib/rustdesk-server --shell /usr/sbin/nologin rustdesk || true
sudo install -d -o rustdesk -g rustdesk -m 0750 /var/lib/rustdesk-server
sudo install -d -o root -g rustdesk -m 0750 /etc/rustdesk-server
sudo install -o root -g rustdesk -m 0640 systemd/config.pro.toml /etc/rustdesk-server/config.toml
sudo install -o root -g root -m 0644 systemd/rustdesk-hbbs-pro.service systemd/rustdesk-hbbr-pro.service /etc/systemd/system/
```

两个 unit 都要求存在环境文件 `/etc/rustdesk-server/rustdesk.env`（权限 0640，禁止提交），至少设置稳定的 JWT secret：

```dotenv
RUSTDESK_PRO__JWT_SECRET=至少32字节的随机值
RUSTDESK_INITIAL_ADMIN_PASSWORD=仅首次启动设置
# PostgreSQL 才设置：
# RUSTDESK_SERVER__DATABASE_URL=postgresql://user:password@db.example.com/rustdesk
# SQLite 保持 1；PostgreSQL 可按容量调整，例如 8
MAX_DATABASE_CONNECTIONS=1
RUST_LOG=info
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now rustdesk-hbbr-pro rustdesk-hbbs-pro
systemctl status rustdesk-hbbs-pro rustdesk-hbbr-pro
curl -fsS http://127.0.0.1:21114/api/health
```

配置使用 `--config /etc/rustdesk-server/config.toml` 明确指定。数据库 URL、监听端口、密钥路径等冷配置修改后需要重启。首次管理员创建后删除初始密码并执行 `systemctl restart rustdesk-hbbs-pro`。

## 4. TLS 与反向代理

复制 `docker/nginx.pro.conf` 或 `docker/Caddyfile.pro`，替换域名和证书路径，再验证：

```sh
nginx -t
caddy validate --config /etc/caddy/Caddyfile
```

21114 默认只绑定宿主机 `127.0.0.1`。公网只开放反向代理的 443；RustDesk 协议端口按客户端需求开放。服务端安全策略使用实际 TCP peer IP，不信任 `X-Forwarded-For`；代理后的管理端 IP 限制应在 Nginx/Caddy 防火墙层实现。

## 5. 备份

脚本要求 tar、sha256sum；SQLite 模式要求 `sqlite3`，PostgreSQL 模式要求与服务端兼容的 `pg_dump`。生产镜像已包含这些工具和 `/usr/local/libexec/rustdesk-server/{backup,restore}.sh`。

```sh
sudo scripts/backup.sh \
  --output /srv/backups/rustdesk-$(date -u +%Y%m%d).tar.gz \
  --database-path /var/lib/rustdesk-server/db_v2.sqlite3 \
  --config /etc/rustdesk-server/config.toml \
  --key /var/lib/rustdesk-server/id_ed25519 \
  --key /var/lib/rustdesk-server/id_ed25519.pub
```

PostgreSQL：

```sh
PGPASSFILE=/run/secrets/pgpass scripts/backup.sh \
  --database-url 'postgresql://rustdesk@db.example.com/rustdesk' \
  --output /srv/backups/rustdesk-postgres.tar.gz
```

Docker SQLite 示例（备份先写入持久化数据卷，再复制到加密的离机存储）：

```sh
docker compose -f docker/docker-compose.pro.yml exec -T hbbs \
  /usr/local/libexec/rustdesk-server/backup.sh \
  --output /var/lib/rustdesk/rustdesk-pro.tar.gz \
  --database-path /var/lib/rustdesk/db_v2.sqlite3 \
  --config /etc/rustdesk-server/config.toml \
  --key /var/lib/rustdesk/id_ed25519 \
  --key /var/lib/rustdesk/id_ed25519.pub
```

产物权限为 0600，包含数据库、配置、可选许可证/密钥、manifest 和 SHA-256 校验。备份包包含高敏感数据，必须加密后离机保存并定期做恢复演练。

## 6. 恢复

恢复会拒绝绝对路径、`..` 和链接条目，校验 checksum，并在目标目录生成 `.pre-restore-*.tar.gz` 快照。

```sh
sudo systemctl stop rustdesk-hbbs-pro rustdesk-hbbr-pro
sudo scripts/restore.sh \
  --archive /srv/backups/rustdesk-20260819.tar.gz \
  --target-dir /var/lib/rustdesk-server
sudo systemctl start rustdesk-hbbr-pro rustdesk-hbbs-pro
curl -fsS http://127.0.0.1:21114/api/health
```

也可传 `--start-services` 让脚本启动服务并等待健康检查。PostgreSQL 恢复必须额外传 `--database-url`，建议先恢复到新数据库并完成健康验证，再切换生产 URL。不要在运行中的 hbbs 上恢复。

## 7. 日志、监控与告警

systemd 默认写 journald：

```sh
journalctl -u rustdesk-hbbs-pro -u rustdesk-hbbr-pro --since today
journalctl -u rustdesk-hbbs-pro -p warning
```

如改为文件日志，安装 `systemd/rustdesk-server-pro.logrotate`。日志和监控中不得记录 JWT secret、数据库 URL 密码、许可证私钥或初始管理员密码。

最小监控项：

- 每 30 秒请求 `/api/health`，非 200 或后端值变化立即告警；
- hbbs/hbbr 进程重启次数和端口可用性；
- PostgreSQL 连接、锁等待、磁盘与备份年龄；SQLite 文件系统剩余空间和写锁错误；
- 21114 的 5xx、认证失败和限流增长；
- 证书剩余有效期、备份任务失败和恢复演练结果。

## 8. 常见故障

- `health db=unavailable`：检查数据库 URL、网络、凭据和迁移日志；不要反复重启覆盖首个错误。
- PostgreSQL 容器健康但 hbbs 报 `sqlite`：未向 hbbs 注入 `RUSTDESK_SERVER__DATABASE_URL`。
- SQLite `database is locked`：确认只运行一个迁移版本，旧/新二进制不可共享同一库滚动混跑；再检查长事务和磁盘 I/O。
- 登录令牌重启后全部失效：JWT secret 没有持久注入，进程使用了随机默认值。
- 反向代理 502：先直连 `127.0.0.1:21114/api/health`，再检查代理 upstream 与防火墙。
- 恢复健康失败：保持服务停止，使用脚本输出的 `.pre-restore-*` 快照回滚，然后检查 checksum、数据库版本和日志。
