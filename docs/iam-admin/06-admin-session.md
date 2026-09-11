# Phase 2：Admin Session

Admin **没有**第二套 Session 表或 Cookie 名。

| 项 | 实现 |
|---|---|
| 存储 | 现有 Redis `session:{sid}`（`IamSessionService`） |
| Cookie | `iam.sso.cookie-name`（默认 `IAM_SSO_SESSION`），HttpOnly、Secure、SameSite=Lax |
| 识别 | Cookie → Session.subjectId → `IamUserService` → `AdminRbacService` |
| 载荷 | `AdminPrincipal`：subject、username、tenant、roles、permissions、authMethod=COOKIE |

OAuth 换出的 JWT **不**写入 Cookie，也不返回给浏览器。BFF 校验完立即 revoke。

`GET /api/admin/me` 返回当前管理员画像。无 Admin 角色：401 之后的已登录用户得 **403 IAM-4082**。不同角色返回不同 `roles`/`permissions`。

TTL 与普通 SSO 相同（`iam.redis.session-ttl`）。Global logout 删除该 key 后，Admin API 与 `/oauth2/authorize` 均失败。
