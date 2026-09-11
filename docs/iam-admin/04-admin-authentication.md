# Phase 2：Admin Authentication

Admin Console 使用现有 IAM **Authorization Code + PKCE**，BFF 跑在授权服务器同进程（`iam-admin` 已嵌入 `iam-authorization-server`）。**没有** AdminUser+Password 第二套账号。

## 架构选择

当前没有独立 Admin 后端进程，Confidential Client + 同进程 BFF 可行：

- Client：`iam-admin`（confidential，`pkce_required=true`，`client_secret_basic`）
- 浏览器：**不得**持有 `client_secret`、`refresh_token`、长期 `access_token`
- 浏览器只持有现有 **HttpOnly / Secure / SameSite** SSO Cookie（`IAM_SSO_SESSION`）
- Access/Refresh 在 `/admin/callback` 校验完 id_token 后由 BFF **立即 revoke 并丢弃**

Redirect URI 必须精确匹配，禁止 `*`。校验走现有 `IamRedirectUriValidator`。

## DEVELOPMENT ONLY 风险

`POST /sso/login` **校验 BCrypt 密码**（`iam_user.password_hash`）。Admin OAuth 的 `/oauth2/authorize` 依赖这条 SSO Session。仍无限流/MFA。

因此 Phase 2 **不是**生产级管理员认证。生产必须先补真正的 IdP/口令/MFA，再让 Admin 走同一套 OAuth。文档与启动日志均标明 DEVELOPMENT ONLY。不得把 `/sso/login` 称为生产管理员登录。

## 端点

| 方法 | 路径 | 作用 |
|---|---|---|
| GET | `/admin/login` | 生成 state/nonce/PKCE，302 到 `/oauth2/authorize` |
| GET | `/admin/callback` | 用 BFF secret 换 token，校验 nonce，绑定 `IamSession`，302 到 post-login；响应/URL **不含 token** |
| POST | `/admin/logout` | 复用 `LogoutService` global：删 Redis session、撤销 refresh、Back-Channel Logout、清 Cookie。须 CSRF |

`/api/admin/**` 仍走 Phase 1 Cookie/Bearer/Legacy 过滤器。登录页本身不在 `/api/admin/**`。

## CSRF / CORS

Cookie 存在时，POST/PUT/PATCH/DELETE 仍走现有 `CsrfValidationFilter`（**未关闭**）。Admin Origin 已加入 `iam.cors.allowed-origins`（含 `http://localhost:8080`、`http://localhost:5173`）。禁止 `Access-Control-Allow-Origin: *`。

## 反向验证说明

本阶段 **不是** Client CRUD。未实现 Disable Client，不能标该功能完成。本阶段完成的是登录协议链路（见 `05`/`06` 与集成测试）。
