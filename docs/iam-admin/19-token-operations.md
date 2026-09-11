# Phase 6：Token Introspect / Revoke 运维

浏览器 **禁止** 直打 `/oauth2/introspect` 并携带 `client_secret`。Admin 页面只调 Admin API；服务端包装现有 `TokenIntrospectionService` / `TokenRevocationService`（与 `/oauth2/introspect`、`/oauth2/revoke` 同一实现）。

**高风险警告**：响应固定 `warning`：`High-risk token operation. Do not persist, log, or copy the presented token.` UI 必须展示。Token 不落盘、不写 audit detail、不写日志。DTO `toString` 脱敏；`IamAuditService.sanitize` 额外覆盖 `token=`。

| 方法 | 路径 | 权限 |
|---|---|---|
| POST | `/api/admin/tokens/introspect` `{token}` | `admin.token.read` |
| POST | `/api/admin/tokens/revoke` `{token, token_type_hint}` | `admin.token.revoke` |

## 能力边界（禁止伪造）

`TokenRevocationService` 只接受 **出示的 token**：access → JTI 黑名单；refresh → `revokePresentedToken` / family。

| 操作 | 是否支持 | 原因 |
|---|---|---|
| 按出示的 access/refresh 吊销 | 是 | 包装 `TokenRevocationService.revoke` |
| 按 refresh family / 用户 PK 吊销 refresh | 是 | 现有 `RefreshTokenFamilyService`（见 Refresh Token 文档） |
| 按 Redis SSO sid 吊销 Session | 是 | `IamSessionService`（见 Session 文档） |
| 按用户吊销 **全部 access token** | **否** | 无 JTI 列表，不能假装全量作废未出示的 JWT |

Introspect 不写业务 Audit 事件，避免把 token 带进 `iam_audit_log`。Revoke 成功才记 `TOKEN_REVOKED`（operator `recordAdmin` + Runtime `success`）。

## 反向验证（Revoke Access Token 必须同时成立）

| 环节 | 证据 |
|---|---|
| Admin API | `POST /api/admin/tokens/revoke` 200（AUDITOR 403） |
| 状态 | JTI 黑名单生效（通过 Runtime introspect，不另造表） |
| Runtime | `TokenIntrospectionService.introspect` → `active=false` |
| 协议 | Admin introspect 再调同一服务 → `active=false` |
| Audit | `TOKEN_REVOKED`；全表 `detail` **不含** 出示的 JWT |

Introspect 反向：Admin API 200 + `warning` + body 不含 token；与 `/oauth2/introspect` 同一 `TokenIntrospectionService`。
