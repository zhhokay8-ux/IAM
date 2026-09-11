# Phase 4：Scope Management

Admin Scope API 委托 `IamScopeService`。Scope 必须绑定 Resource，唯一约束仍是 `(resource_id, scope_code)`。

创建要求 Resource 为 ACTIVE。Admin 创建默认 Scope **INACTIVE**，再 `enable`。PUT 只改 `scope_name` / `description`（表上已有 description），不改绑定、不改 status。

反向验证（Disable Scope）：Admin disable → `iam_scope.status=INACTIVE` → `IamPolicyEvaluator.validateScope` → `IAM-4035 SCOPE_INACTIVE` → `GET /oauth2/authorize` Location `error=invalid_scope` → `AuditEvent.SCOPE_DISABLED`。
