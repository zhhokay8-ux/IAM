# Phase 10：Admin Console

Vue 3 + TypeScript + Vite + Vue Router + Pinia + Axios + Element Plus + ECharts。目录：`iam-admin-ui/`。路由 base=`/admin/`，对应需求路径 `/admin/login` … `/admin/config`。

开发：`npm run dev`（Vite `:5173`）。`/api`、`/admin/oauth-login`（rewrite 到 `/admin/login`）、`/admin/callback`、`/admin/logout`、`/sso`、`/oauth2` 代理到授权服务器 `:8080`。登录页先 `POST /sso/login`（username + password）再建 SSO Cookie，再整页跳转 BFF `/admin/oauth-login`。`iam.admin.oauth.redirect-uri` / `post-login-uri` 默认指向 `http://localhost:5173/admin/**`，Cookie 与 SPA 同域。生产同域时由 Spring 占用 `GET /admin/login`，并把 redirect/post-login 配成授权服务器 Origin。

Axios 统一封装：`withCredentials`、CSRF cookie `IAM_CSRF` → 头 `X-CSRF-Token`、解析 `ApiErrorResponse{traceId,code,message}`。401 回登录；403 提示无权限；400/409/500 分别展示业务错误/冲突/系统异常。菜单按 `admin.*` 权限隐藏按钮，**安全仍由后端 RBAC 执行**。

Introspection / 一次性 `client_secret` 只在组件/Pinia 内存；路由离开 `tokenMemory.clear()`。禁止 LocalStorage 存 Token/Secret。
