# Phase 4：Resource Management

Admin Resource API 委托 `IamResourceService`。字段仅使用 `iam_resource_server` 现有列：`resource_code`、`resource_name`、`audience`、`status`、`owner`、`created_at`。**无 description 列，未新增。**

创建默认 **INACTIVE**。PUT 不改 status。启停走 `enable` / `disable`。无物理删除。

反向验证（Disable Resource）：Admin disable → `iam_resource_server.status=INACTIVE` → `IamPolicyEvaluator.validateAudience` → `IAM-4030 FORBIDDEN` → `POST /oauth2/token` client_credentials 拒绝 → `AuditEvent.RESOURCE_DISABLED`。
