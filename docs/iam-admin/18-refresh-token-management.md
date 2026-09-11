# Phase 6：Refresh Token 元数据

Admin 只展示 `iam_refresh_token` **元数据**。禁止返回 refresh 明文、hash、或任何可重放凭证。列表/详情 JSON 无 `token` / `tokenHash`。

复用 `IamRefreshTokenRepository` 与 `RefreshTokenFamilyService`。行内 `subject_id` 是 **用户主键**，不是 JWT `sub`。Admin 查询参数 `subject_id` 是 JWT subject，内部经 `IamUserService.get` 映射到 PK 再 `findBySubjectId`。`family_id` 对应表字段 `session_id`（family UUID），**不是** Redis SSO sid。不要伪造「用 SSO sid 吊销全部 refresh」除非能关联到 family。

| 方法 | 路径 | 权限 |
|---|---|---|
| GET | `/api/admin/refresh-tokens?subject_id=` 或 `family_id=` | `admin.token.read` |
| GET | `/api/admin/refresh-tokens/{id}` | `admin.token.read` |
| POST | `/api/admin/refresh-tokens/{id}/revoke` | `admin.token.revoke` → `revokeFamily` |
| POST | `/api/admin/refresh-tokens/families/{familyId}/revoke` | `admin.token.revoke` |
| POST | `/api/admin/refresh-tokens/by-subject/{subjectId}/revoke` | `admin.token.revoke` → `revokeAllForSubject(userPk)` |

元数据：id、userPk、subjectId（JWT）、clientId（`iam_client` PK）、familyId、issued/expires/revoked、status、scope、audience。

## 反向验证（Revoke Refresh 必须同时成立）

| 环节 | 证据 |
|---|---|
| Admin API | `POST /api/admin/refresh-tokens/{id}/revoke` 200，`status=REVOKED` |
| DB | `iam_refresh_token.status=REVOKED`（按 hash 查行，测试不把 hash 返回给 Admin） |
| Runtime | `TokenIntrospectionService.introspect(refresh)` → `active=false` |
| 协议 | `POST /oauth2/token` `grant_type=refresh_token` 失败 |
| Audit | `AuditEvent.TOKEN_REVOKED`，detail **不含** refresh 明文 |

AUDITOR 吊销 403，行保持 ACTIVE。
