# Phase 3：Client Management

Admin Client API 全部委托现有 `IamClientService` / `IamPermissionService` / `IamClientValidator` / `IamRedirectUriValidator`。不在 Admin 模块复制 ACTIVE 判断或 URI 规则。Runtime 不缓存 Client 行，Admin 提交后立即生效。

默认创建状态为 **INACTIVE**（本项目没有 DISABLE 枚举）。禁止物理删除，避免级联 URI/Permission。启停走独立 `enable` / `disable`；PUT 不改 status。

Secret 由服务端生成，仅出现在 create / rotate-secret 响应的 `client_secret`。GET/列表/审计/日志不含明文或 `client_secret_hash`。Rotate 后旧 hash 立即失效。

## 反向验证（Disable 必须同时成立）

| 环节 | 证据 |
|---|---|
| Admin API | `POST /api/admin/clients/{id}/disable` 200，body `status=INACTIVE` |
| DB | `iam_client.status=INACTIVE` |
| Runtime | `IamPolicyEvaluator.validateClient` → `IAM-4011 CLIENT_INACTIVE` |
| 协议 | `GET /oauth2/authorize` → 401 `IAM-4011` |
| Audit | `AuditEvent.CLIENT_DISABLED`，detail 含 `client_id`，不含 secret |

Enable 后再走授权码成功（Location 含 `code=`），证明同一条链路可恢复。Rotate Secret 用 `/oauth2/token` client_credentials：旧 secret `IAM-4006`，新 secret 200。Redirect URI 变更后旧 URI `IAM-4021`，新 URI 发 code。
