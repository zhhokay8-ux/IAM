# Phase 1 测试报告

覆盖点与实现位置：

| 场景 | 期望 | 测试 |
|---|---|---|
| 未认证 | 401 IAM-4010 | `AdminSecurityMvcTest`、`AdminAuthenticationServiceTest`、`AdminSecurityIntegrationTest` |
| 普通用户（无 Admin 角色） | 403 IAM-4082 | `AdminAuthenticationServiceTest`、`AdminSecurityIntegrationTest` |
| IAM_ADMIN | 读写探测允许 | `AdminSecurityMvcTest`、`AdminSecurityIntegrationTest` |
| IAM_AUDITOR | read 200 / write 403 IAM-4081 | 同上 |
| IAM_OPERATOR | token.revoke 允许；client.write 403 | 同上 |
| Legacy Token 默认关闭 | 带 `X-IAM-Admin-Token` 仍 401 | `AdminAuthenticationServiceTest`、`AdminSecurityIntegrationTest` |
| Audit | 写探测产生 `ADMIN_WRITE`；失败产生 `ADMIN_AUTH_FAILURE` / `ADMIN_FORBIDDEN`；密钥字段脱敏 | `IamAuditServiceAdminTest`、`AdminSecurityIntegrationTest` |

单元测试（不依赖 Docker）在本机 JDK 21 下 `mvn -pl iam-audit,iam-admin -am test` **通过**，包含：

- `iam-admin`：12 tests（RBAC / 认证 / MockMvc 401·403·ADMIN·AUDITOR·OPERATOR）
- `iam-audit`：`IamAuditServiceAdminTest` 脱敏
- 既有 common / token / policy / user / session / embed / migration 单元测试

`mvn clean verify` 在本环境因 **Testcontainers 找不到 Docker** 失败（`AbstractIamIntegrationTest` 静态启动 Oracle/Redis 容器）。该失败覆盖原有 OAuth/SSO/Embed/Migration 集成测试以及新建的 `AdminSecurityIntegrationTest`，不是协议代码回归。有 Docker 时应再跑一遍 `mvn verify`。

Phase 1 未改 V1–V15，未改 OIDC/OAuth2/SSO/Token Exchange/CC/Embed/Migration 实现。
