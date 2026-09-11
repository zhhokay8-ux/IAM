# 27 Legacy 迁移

**【已实现】** `iam-migration`：`MigrationLoginController`、`MigrationTicketServiceImpl`、`MigrationProperties`。

## 模式

`iam.enabled` + `iam.migration.mode`：

- `dual`：IAM 与 Legacy 都允许（`iamLoginEnabled` 且 `legacyLoginEnabled`）。
- `iam`：只走 IAM。
- `legacy`：关 IAM 登录。
- `iam.enabled=false`：等同关 IAM 登录。

Ticket TTL 强制 30–60 秒。

## 流程

Portal 校验 **自己的** Legacy Session（本仓库 `LegacySessionValidator` 默认未配置实现需接入方提供；有 `UnconfiguredLegacySessionValidator`）。映射 `system_code+external_user_id` → subject。Confidential `POST /api/migration/ticket`，浏览器顶层跳转 **`/migration/login?ticket=` only**。禁止 `?session=`、URL 中 JWT。绑定 cookie `IAM_MIGRATION_BROWSER`、`IAM_MIGRATION_NONCE`。成功写 `IAM_SSO_SESSION`，302 `return_to`。

回滚：`iam.enabled=false` 或 mode=`legacy`，不要先删 mapping 表。
