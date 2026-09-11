# Phase 10：Admin Console 部署

1. `cd iam-admin-ui && npm ci && npm run build` → `iam-admin-ui/dist`（`base=/admin/`）。
2. 将 `dist` 放到授权服务器静态目录（例如 `classpath:/static/admin/` 或 Nginx `location /admin/`）。
3. **不要**用 SPA 覆盖 `GET /admin/login`、`GET /admin/callback`、`POST /admin/logout`。
4. CORS：`iam.cors.allowed-origins` 已含 `http://localhost:5173`；生产应只保留真实 Admin Origin，且 Cookie `SameSite=Lax` + CSRF。
5. 改 `iam.*` 必须重启进程。Admin Config UI 不能热更新 issuer/JWT/CORS。
6. 前端构建与 Java 模块解耦；本仓库未把 `dist` 打进 `iam-authorization-server` 的 jar（避免未审核的前端产物进入后端制品）。
