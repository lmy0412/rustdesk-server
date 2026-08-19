# OSS 升级到 RustDesk Server Pro

升级是停写操作。开始前记录当前二进制版本、配置、端口、密钥、公钥和数据库大小，并完成一次可验证的离机备份。任何阶段失败都先停止新服务，再按本文回滚，禁止让新旧版本同时写同一 SQLite 文件。

## 1. 升级前检查

1. 确认客户端连接使用的 ID/Relay 地址和服务端公钥不变。
2. 关闭自动升级或滚动发布，安排维护窗口。
3. 用 `scripts/backup.sh` 备份 OSS SQLite、配置、`id_ed25519`、`id_ed25519.pub` 和许可证文件。
4. 在另一目录执行一次 `restore.sh --allow-running` 恢复演练，并运行 `sqlite3 restored/db_v2.sqlite3 'PRAGMA integrity_check;'`。
5. 准备稳定 JWT secret、首次管理员密码和 TLS 证书；不得复用示例值。

## 2. OSS SQLite 就地升级为 Pro SQLite

```sh
sudo systemctl stop rustdesk-hbbs rustdesk-hbbr
sudo systemctl stop rustdesk-hbbs-pro rustdesk-hbbr-pro 2>/dev/null || true
sudo scripts/backup.sh --output /srv/backups/rustdesk-pre-pro.tar.gz \
  --database-path /var/lib/rustdesk-server/db_v2.sqlite3 \
  --config /etc/rustdesk-server/config.toml
```

安装 Pro 二进制和 unit，保留原密钥与数据库路径。先在只允许管理员访问的网络启动 hbbs；启动时 SQLx 会顺序执行 SQLite migrations。确认日志显示迁移完成、`/api/health` 为 200 且 `db=sqlite`，再启动 hbbr 和开放流量。

验证：原设备能重连、服务端公钥未变化、管理员能登录、设备数量/用户数量与升级前一致、地址簿和审计页可读。

### SQLite 回滚

1. 停止全部 Pro 服务。
2. 保存失败后的数据库和日志用于分析。
3. 使用 `restore.sh` 恢复升级前备份，或解开 `.pre-restore-*` 快照。
4. 恢复原 OSS 二进制、unit 和配置，启动后验证公钥、设备连接和数据库完整性。

迁移可能增加表、列和触发器，不能假设旧二进制能安全读取已升级数据库；回滚必须恢复升级前数据库快照。

## 3. SQLite 迁移到 PostgreSQL

该路径不是滚动复制。采用“停写 → 导出 → 转换导入 → 校验 → 切换”的一次性迁移：

1. 停止 OSS/Pro hbbs 和所有会写数据库的辅助进程。
2. 执行最终 SQLite 备份与 `PRAGMA integrity_check`。
3. 启动指向空 PostgreSQL 数据库的同版本 Pro hbbs，让 `migrations/postgres` 建立 schema；成功后立即停止。
4. 用受控 ETL 工具按外键顺序复制业务数据：`users`、`groups`、`devices`、`licenses`、`audit_logs`、安全策略、标签、地址簿和 outbox。BLOB 映射为 `BYTEA`，SQLite UTC `DATETIME` 映射为 PostgreSQL 的无时区 `TIMESTAMP`（值仍统一按 UTC 解释），布尔值映射为 `BOOLEAN`。
5. 对每张表比较行数；抽样比对设备 GUID/公钥、用户、许可证、地址簿版本。同步 identity/sequence 到各表最大 ID。
6. 在隔离端口启动指向 PostgreSQL 的 hbbs，确认 `/api/health` 返回 `db=postgresql`，执行登录、设备列表、地址簿、许可证和审计冒烟测试。
7. 再次确认服务端密钥文件未变化，切换生产数据库 URL 和流量，最后启动 hbbr。

禁止用通用文本替换把 SQLite migration 直接喂给 PostgreSQL；两端的 identity、触发器、时间函数和锁语义不同。大库应先在生产快照上测量 ETL 时长。

### PostgreSQL 切换回滚

在确认成功前保留原 SQLite 文件只读且不做任何新写入。若切换失败：停止 Pro 服务，撤回数据库 URL，恢复升级前 SQLite 快照和原二进制，再启动 OSS。切换后若 PostgreSQL 已接收生产写入，不能直接回到旧 SQLite；必须先评估增量数据并安排反向 ETL 或接受明确的数据丢失点。

## 4. 版本升级通用步骤

1. 阅读 release notes，确认配置字段和迁移要求。
2. 停止写入，备份数据库/配置/许可证/密钥并验证 checksum。
3. 先升级隔离实例并跑健康/API 冒烟测试。
4. 生产停止 hbbs/hbbr，替换二进制或镜像，运行新版本迁移。
5. 先启动 hbbs，确认健康和日志，再启动 hbbr、开放流量。
6. 观察错误率、认证失败、设备在线数和数据库锁；完成验收后才清理旧镜像与快照。

SQLite 不支持新旧 schema 版本共享写入，不能使用多副本滚动升级。PostgreSQL 即使支持多连接，也只有在 release notes 明确声明向后兼容时才能滚动升级；默认仍按停写升级处理。
