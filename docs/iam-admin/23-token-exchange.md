# Phase 8：Token Exchange（Permission Matrix）

**没有** `TokenExchangePolicy` 表，禁止新建。策略就是 `iam_cli_res_perm.grant_type=TOKEN_EXCHANGE`。

Admin 专用入口 `/api/admin/token-exchange/permissions` 只允许该 grant；底层仍是 `IamPermissionService`。改完立即被 `TokenExchangePolicyService.requireExchangePermission` → `IamPolicyEvaluator.validateTokenExchangePermission` 读取。通用 Permission API 见 `12-permission-matrix.md`。

| 方法 | 路径 | 权限 |
|---|---|---|
| GET | `/api/admin/token-exchange/permissions` | `admin.policy.read` |
| POST | 创建（默认 INACTIVE） | `admin.policy.write` |
| POST | `/enable` `/disable` | `admin.policy.write` |

传入非 `TOKEN_EXCHANGE` 的 grant_type → `IAM-4003`。

## 反向验证

| 环节 | 证据 |
|---|---|
| Admin API | enable 后 exchange 200；disable 200 |
| DB | 对应 `iam_cli_res_perm.status=INACTIVE` |
| Runtime | `TokenExchangePolicyService` / `IamPolicyEvaluator` → `TOKEN_EXCHANGE_NOT_ALLOWED` |
| 协议 | `POST /oauth2/token` token-exchange → `IAM-4032` |
| Audit | `POLICY_CHANGED`，detail 含 `TOKEN_EXCHANGE` |
