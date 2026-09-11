# Phase 5：Identity Mapping

`/api/admin/identity-mappings` 与 `/api/admin/users/{subjectId}/identity-mappings` 委托 `IamIdentityMappingService`。

唯一约束仍是 `(system_code, external_user_id)`（V13 `uk_idmap_sys_ext`）。重复创建返回 `IAM-4097`。

支持按 `system_code`、`external_user_id`、`subject_id` 查询，以及更新 / 删除。不新增表。
