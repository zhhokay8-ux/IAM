# Phase 1：Admin RBAC 矩阵

表：`iam_admin_role`、`iam_admin_perm`、`iam_admin_role_perm`、`iam_admin_user_role`（Flyway `V16`）。用户外键：`iam_admin_user_role.subject_id` → `iam_user.subject_id`。

运行时由 `AdminRbacService` 按 `subject_id` 加载 **ACTIVE** 角色及其权限点。后端强制校验；前端只能隐藏按钮。

## 角色

| role_code | 说明 |
|---|---|
| `IAM_ADMIN` | 全部权限点 |
| `IAM_SECURITY_ADMIN` | 除 `admin.user.write` 外全部 |
| `IAM_OPERATOR` | 运维读写用户/令牌/会话，只读 Client/Resource/Scope/Policy/Embed/Audit/Config；无密钥与策略写 |
| `IAM_AUDITOR` | 只读（含 `admin.key.read`，无任何 write/revoke/rotate） |

## 权限点

| permission | ADMIN | SECURITY_ADMIN | OPERATOR | AUDITOR |
|---|---|---|---|---|
| admin.client.read | Y | Y | Y | Y |
| admin.client.write | Y | Y | N | N |
| admin.resource.read | Y | Y | Y | Y |
| admin.resource.write | Y | Y | N | N |
| admin.scope.read | Y | Y | Y | Y |
| admin.scope.write | Y | Y | N | N |
| admin.policy.read | Y | Y | Y | Y |
| admin.policy.write | Y | Y | N | N |
| admin.user.read | Y | Y | Y | Y |
| admin.user.write | Y | N | Y | N |
| admin.token.read | Y | Y | Y | Y |
| admin.token.revoke | Y | Y | Y | N |
| admin.session.read | Y | Y | Y | Y |
| admin.session.revoke | Y | Y | Y | N |
| admin.embed.read | Y | Y | Y | Y |
| admin.embed.write | Y | Y | N | N |
| admin.audit.read | Y | Y | Y | Y |
| admin.key.read | Y | Y | N | Y |
| admin.key.rotate | Y | Y | N | N |
| admin.config.read | Y | Y | Y | Y |

Phase 1 探测接口：

- `GET /api/admin/security/read-probe` → `admin.audit.read`
- `POST /api/admin/security/write-probe` → `admin.client.write`（AUDITOR/OPERATOR 为 403）
- `POST /api/admin/security/token-revoke-probe` → `admin.token.revoke`（OPERATOR 允许）
