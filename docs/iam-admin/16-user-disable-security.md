# Phase 5：User Disable Security

Admin Disable 不能只改 `iam_user.status`。`AdminUserLifecycleService` 同一事务路径内：

1. `IamUserService.disable` → `INACTIVE`
2. `IamSessionService.revokeAllForSubject`（Redis `session:subject:{subjectId}` 索引）
3. `RefreshTokenFamilyService.revokeAllForSubject(iam_user.id)`（refresh 行存的是用户 PK，不是 JWT sub）

Runtime 继续读用户状态，而不是 Admin 再写一套判断：

| 面 | 行为 |
|---|---|
| Token / Refresh / Exchange | `requireActiveForToken` → `IAM-4036 USER_INACTIVE` |
| SSO login | `requireActiveByUsernameAndTenantId` → `USER_INACTIVE` |
| Authorize + 已吊销 Cookie | `SESSION_REVOKED` |
| Introspect Access Token | sub 对应用户 INACTIVE 时 `active=false` |
| Admin Bearer | 已有 `requireActiveForToken`，失败包装为 `IAM-4010` |

Audit：`USER_DISABLED`（禁止用 `ADMIN_WRITE` 冒充）。反向验证见 `AdminUserManagementIntegrationTest`。
