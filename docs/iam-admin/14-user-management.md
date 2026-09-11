# Phase 5：User Management

Admin User API 委托现有 `IamUserService`。**不创建 AdminUser，不建第二套用户表。** `iam_user` 无 `last_login_at` / `roles`，响应与 UI 不得虚构这些字段。无 V17。

`GET /api/admin/users` 按 username / email / tenant / subject 搜索。创建默认 **INACTIVE**。PUT 不改 status。启停走 `enable` / `disable`。

`/api/users/**` 保持不变。
