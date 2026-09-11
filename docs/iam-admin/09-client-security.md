# Phase 3：Client Security

- 明文 secret 只在 create / rotate 响应出现一次。
- `ClientResponse` 不含 `clientSecret` / `client_secret_hash`。
- Audit `SECRET_ROTATED` / `CLIENT_DISABLED` 的 detail 禁止含 secret；`IamAuditService.sanitize` 仍覆盖 token 类字段。
- Redirect URI 精确匹配，`*` / `{` / `}` 被 `IamRedirectUriValidator` 拒绝。
- PUT 不能改 status，避免绕过 `CLIENT_DISABLED` 审计。
- AUDITOR 无 `admin.client.write`：写接口 403 且数据库不变。
- Runtime 不缓存 Client 行：Admin 提交后 `IamPolicyEvaluator` 与 `/oauth2/authorize`、`/oauth2/token` 立即读库。
