# Phase 7：Audit Center

Admin 只查询现有 `iam_audit_log`，经 `IamAuditService.search` / `get`。禁止第二套 Audit 表或平行写入器。

| 方法 | 路径 | 权限 |
|---|---|---|
| GET | `/api/admin/audit` | `admin.audit.read` |
| GET | `/api/admin/audit/{id}` | `admin.audit.read` |
| GET | `/api/admin/audit/events` | `admin.audit.read`（枚举目录） |

查询参数：`from` / `to`（ISO Instant）、`operator`、`subject`、`tenant`、`event_type`、`resource_type`、`resource_id`、`success`、`trace_id`、`ip`、分页。默认 `createdAt DESC`。

Admin 写路径走 `recordAdmin`，尽量带齐 `operator_name`、`tenant_id`、`source_ip`、`user_agent`、`trace_id`。协议侧 `success()`/`record()` 仍可能缺 IP/UA（列存在，写入取决于调用方）。

## 实际事件名（按已有写操作）

| 操作 | AuditEvent |
|---|---|
| 创建/改 Client、改 redirect URI | `CLIENT_CREATED` / `CLIENT_UPDATED` |
| 启停 Client | `CLIENT_ENABLED` / `CLIENT_DISABLED` |
| 轮换 Client Secret | `SECRET_ROTATED`（需求别名 CLIENT_SECRET_ROTATED） |
| Resource / Scope | `RESOURCE_*` / `SCOPE_*`（含 DISABLED/ENABLED） |
| Permission 矩阵 | `POLICY_CHANGED` |
| User / mapping | `USER_CREATED` / `USER_UPDATED` / `USER_DISABLED` / `USER_ENABLED` |
| Session | `SESSION_REVOKED` / `SESSION_EXPIRED` |
| Token / refresh | `TOKEN_REVOKED` |
| Phase 1 探测 | `ADMIN_WRITE` |
| 密钥轮换 / Embed policy | 枚举已有 `SIGNING_KEY_ROTATED` / `EMBED_POLICY_CHANGED`，**尚无 Admin 写入口，不伪造写入** |

## 反向验证（Audit 查询必须读到 Runtime 写入）

| 环节 | 证据 |
|---|---|
| Admin API | Disable Client 200；随后 `GET /api/admin/audit?event_type=CLIENT_DISABLED` 200 |
| DB | `iam_client.status=INACTIVE`；`iam_audit_log.event_type=CLIENT_DISABLED` |
| Runtime | `IamPolicyEvaluator.validateClient` → `CLIENT_INACTIVE`；查询走同一 `IamAuditService` |
| 协议 | `GET /oauth2/authorize` → `IAM-4011` |
| Audit | 查询结果含 operator/traceId；body **不含** create 时的 secret |

测试：`AdminAuditCenterIntegrationTest.disableClientThenAuditQueryReadsSameRuntimeRow`；写操作事件覆盖 `AdminAuditWriteCoverageMvcTest`。
