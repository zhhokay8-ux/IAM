# Phase 7：Audit 安全

`IamAuditService.sanitize` 在 **写入**（`record` / `recordAdmin`）和 **读出**（`search` / `get`）两侧执行。禁止 Admin 查询把明文 Secret/Token 送回浏览器。

脱敏关键字：`client_secret`、`access_token`、`refresh_token`、`private_key`、`authorization_code`、`code_verifier`、`cookie`、`token`。匹配 `name=value` / `name: value`，替换为 `name=***`。

查询响应与详情不得出现：

- Client Secret
- Access / Refresh Token
- Private Key
- Authorization Code
- PKCE `code_verifier`
- Cookie / SSO sid 明文（若被误写入 detail，读出亦应 `cookie=***`）

Introspect 出示的 token 不得写入 audit（Phase 6）。Rotate Secret 的 audit 只记 `SECRET_ROTATED`，不含新 secret。

AUDITOR 可查询（`admin.audit.read`），不能做写操作。未认证 `GET /api/admin/audit` → `IAM-4010`。
