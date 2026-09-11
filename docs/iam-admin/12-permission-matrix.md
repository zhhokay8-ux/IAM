# Phase 4：Permission Matrix

权限行在 `iam_cli_res_perm`，唯一键 `(client_id, resource_id, scope_id, grant_type)`。

Grant type（现有枚举，无新表）：

- `AUTHORIZATION_CODE`
- `CLIENT_CREDENTIALS`
- `TOKEN_EXCHANGE`

Admin 创建默认 INACTIVE，再 enable。Disable 将 status 置 INACTIVE，不物理删除。

`IamPolicyEvaluator.validateGrantPermission` 只认 `ACTIVE` 行。Admin 改权限后 Runtime 立即读库。

反向验证：

| Grant | Runtime | 协议 |
|---|---|---|
| CC | `validateClientCredentialsPermission` → `CLIENT_CREDENTIALS_NOT_ALLOWED` | `/oauth2/token` → `IAM-4031`（handler 映射） |
| Token Exchange | `validateTokenExchangePermission` → `TOKEN_EXCHANGE_NOT_ALLOWED` | `/oauth2/token` exchange → `IAM-4032` |
| Authorization Code | `validateAuthorizationCodeScopes` → `PERMISSION_DENIED` | `/oauth2/authorize` → `error=invalid_scope` |

Audit：`POLICY_CHANGED`（禁止用 `ADMIN_WRITE` 冒充）。
