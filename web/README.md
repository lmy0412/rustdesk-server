# RustDesk Web 管理控制台

开发环境要求 Node.js 20.19 或更高版本。

```powershell
npm ci
npm run dev
```

生产构建会写入 `dist/`。该目录随仓库提交并由 Rust 的 `pro` feature 嵌入二进制，因此每次修改前端源代码后都必须重新执行：

```powershell
npm run typecheck
npm test
npm run build
```

开发服务器默认把 `/api` 代理到 `http://127.0.0.1:21114`。
