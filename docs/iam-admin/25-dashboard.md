# Phase 9：Dashboard

禁止 `dashboard_statistics` 表。计数来自现有 `iam_client` / `iam_resource_server` / `iam_scope` / `iam_user` / `iam_refresh_token`；趋势来自同一张 `iam_audit_log`（按 UTC 日 + `event_type` + `result` 聚合）。Session 仍在 Redis `session:{sid}`，没有现成 count。

| 方法 | 路径 | 权限 |
|---|---|---|
| GET | `/api/admin/dashboard?days=7` | `admin.audit.read` |

`days` 默认 7，最大 31。响应：`counts`（client / activeClient / resource / scope / user / activeSession / activeRefreshToken）+ `trends`（login=`LOGIN_SUCCESS`+`ADMIN_AUTH_SUCCESS`，tokenIssued=`TOKEN_ISSUED`，tokenExchange=`TOKEN_EXCHANGE`，failure=`result != SUCCESS`）+ `recentAdminOperations`（`operator_name IS NOT NULL` 最近 20 条，已脱敏）。

## Session 计数

`SCAN MATCH session:*`，跳过 `session:subject:*`。结果写入 Redis 短 TTL 缓存 `admin:cache:session-count`（30s），**不是**第二套业务统计库。单次 SCAN 上限 10_000；≤500 时 GET payload 只计 `ACTIVE` 且未过期。Redis Cluster 的 SCAN 可能只覆盖当前节点，多节点计数是近似值（`activeSessionApproximate=true`）。禁止每次 Dashboard 请求全库 SCAN / `KEYS *`。

## 反向验证

| 环节 | 证据 |
|---|---|
| Admin API | `GET /api/admin/dashboard` 200，`clientCount` 与独立 `iam_client` count 一致 |
| DB/Redis | `countByStatus(ACTIVE)`、`session:{sid}` 存在；趋势桶来自 `iam_audit_log` |
| Runtime | 使用现有 Repository / `IamSessionService` / `IamAuditService`，无平行统计实现 |
| 协议 | 本接口只读；配置 issuer 与 `GET /.well-known/openid-configuration` 对照见 `26-system-config.md` |
| Audit | `recentAdminOperations` 能读到刚才的 Admin 写事件（如 `CLIENT_ENABLED`），Dashboard GET 本身不写统计表 |

测试：`AdminDashboardServiceTest`、`AdminDashboardConfigMvcTest`、`IamAuditServiceSearchTest`（聚合）、`SsoSessionServiceTest.countActive*`。集成：`AdminDashboardConfigIntegrationTest`（需 Docker）。
