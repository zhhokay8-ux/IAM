# Phase 1：Admin Security

本阶段只落地 `/api/admin/**` 的认证、授权、审计与 Legacy Token 兼容。未实现 Client/Resource/Scope CRUD、Dashboard 或前端。

## 默认拒绝

- 路径：`/api/admin/**`
- 未认证：`401`（`IAM-4010`）
- 已认证但没有 Admin 角色：`403`（`IAM-4082`）
- 有角色但缺少权限点：`403`（`IAM-4081`）
- 不使用 `permitAll`

认证在 `AdminAuthenticationFilter`（CSRF 之后，`HIGHEST_PRECEDENCE + 25`）。权限在 `AdminAuthorizationInterceptor` + `@RequireAdminPermission`。未标注权限的接口（如 `GET /api/admin/me`）仍要求至少一个 Admin 角色。

## 认证顺序

1. SSO Cookie（`iam.admin.cookie-name`，默认 `IAM_SSO_SESSION`）→ Redis `IamSessionService` → `IamUserService.requireActiveForToken`
2. 否则 `Authorization: Bearer` → 现有 `JwtSigner.verify`，`sub` 必须是 `iam_user.subject_id`
3. 否则仅当 `iam.admin.legacy-token.enabled=true` 时校验 `X-IAM-Admin-Token`（与 `iam.admin.access-token` 常量时间比较）
4. Cookie/Bearer 无效时不回落到 Legacy

复用现有 TraceId、CORS、CSRF、`GlobalExceptionHandler` / `ApiErrorResponse`。Cookie 的状态变更请求仍走现有 `CsrfValidationFilter`。本阶段探测接口的集成测试使用 Bearer，避免 CSRF。

`/api/users/**` 的 `IamAdminAccessInterceptor` 未改。

## Legacy Token

- 默认 **关闭**：`iam.admin.legacy-token.enabled=false`
- 开启时启动打印 WARN；token 永不入日志或审计 detail
- 成功记 `ADMIN_LEGACY_AUTH`，主体为合成 `legacy-admin`，权限等同 `IAM_ADMIN`（库内全部权限点）
- `access-token` 为空时即使 enabled 也拒绝

## 用户模型

继续使用 `IamUserEntity` / `subject_id`。管理员身份是 `iam_admin_user_role` 绑定，不是第二套账号表。
