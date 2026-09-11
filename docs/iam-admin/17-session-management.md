# Phase 6：Session 运维

SSO Session **只存在 Redis**，key 为 `session:{sid}`，按用户枚举走 `session:subject:{subjectId}` 索引。没有 Session SQL 表，Admin 禁止 `SELECT session`。

全部委托现有 `IamSessionService`（`inspect` / `listBySubject` / `revoke` / `expire` / `revokeAllForSubject`）。Admin 不复制 ACTIVE/过期判断；运行时 `require` / authorize 仍读同一 Redis JSON。

| 方法 | 路径 | 权限 |
|---|---|---|
| GET | `/api/admin/sessions?subject_id=` | `admin.session.read` |
| GET | `/api/admin/sessions/{sid}` | `admin.session.read`（含 REVOKED，不抛 `SESSION_REVOKED`） |
| POST | `/api/admin/sessions/{sid}/revoke` | `admin.session.revoke` |
| POST | `/api/admin/sessions/{sid}/expire` | `admin.session.revoke` |
| POST | `/api/admin/sessions/by-subject/{subjectId}/revoke` | `admin.session.revoke` |

记录字段：sid、subject_id、created_at、last_access_at、expires_at、authentication_level、client_id、status（ACTIVE/REVOKED）。AUDITOR 吊销返回 `IAM-4081`。

## 反向验证（Revoke Session 必须同时成立）

| 环节 | 证据 |
|---|---|
| Admin API | `POST /api/admin/sessions/{sid}/revoke` 200，`status=REVOKED` |
| Redis | `session:{sid}` JSON `status=REVOKED`（`IamSessionRepository.get`） |
| Runtime | `IamSessionService.require(sid)` → `IAM-4052 SESSION_REVOKED` |
| 协议 | 带同一 Cookie 的 `GET /oauth2/authorize` → 401 `IAM-4052` |
| Audit | `AuditEvent.SESSION_REVOKED`，detail 含 sid，禁止 `ADMIN_WRITE` 冒充 |

Expire 写过去的 `expires_at`，Runtime 为 `SESSION_EXPIRED`；审计事件为 `SESSION_EXPIRED`。
