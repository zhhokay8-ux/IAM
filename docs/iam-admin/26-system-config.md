# Phase 9：System Configuration（只读）

`GET /api/admin/config` 展示进程内已绑定的 `iam.*`（issuer、JWT、CORS、PKCE state TTL、Session、Redis TTL、Admin / Legacy Token）。**READ_ONLY** + **RESTART_REQUIRED**。本 Phase 不提供危险配置的运行时修改。

| 方法 | 路径 | 权限 |
|---|---|---|
| GET | `/api/admin/config` | `admin.config.read` |
| POST/PUT/PATCH/DELETE | `/api/admin/config` | 同一权限下仍拒绝，`IAM-4030 FORBIDDEN` |

危险项（issuer、`iam.jwt.algorithm`、CORS、`iam.admin.*`、Legacy Token）`dangerous=true`。`iam.admin.access-token`、oauth `client-secret`、password/credential 显示 `***`。`iam.jwt.access-token-ttl` 不脱敏。

PKCE 没有全局开关：客户端 `pkce_required` + Redis `iam.redis.pkce-state-ttl`。改 yaml 后必须重启进程才生效。

## 反向验证

| 环节 | 证据 |
|---|---|
| Admin API | GET 200 且 `readOnly=true`；POST 改 issuer 被拒绝 |
| DB/Redis | 配置不落库；拒绝后 `iam_client` 等业务行不变 |
| Runtime | 响应值来自同一套 `@ConfigurationProperties` / `Environment`，与签发 JWT / CORS 过滤器相同 |
| 协议 | `GET /.well-known/openid-configuration` 的 `issuer` = `iam.issuer` |
| Audit | 无配置变更事件（因为写不进去）；权限不足记 `ADMIN_FORBIDDEN` |

测试：`AdminConfigServiceTest`、`AdminDashboardConfigMvcTest`、`AdminDashboardConfigIntegrationTest`。
