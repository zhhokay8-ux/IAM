# IAM Admin 完整功能清单与验收报告

生成于 Phase 10 结束。**禁止把设计写成已实现。** 反向验证五类证据以 Java 集成测试为准；本机无 Docker daemon 时这些集成测试 **未跑过**。

## [已实现]

- Phase 1 Admin RBAC / 认证过滤器 / 权限注解（单元+MVC）
- Phase 2 BFF `/admin/login` `/admin/callback` `/admin/logout`（代码在授权服务器）
- Phase 3–5 Client / Resource / Scope / Permission / User Admin API
- Phase 6 Session Redis 运维、Refresh metadata、Token introspect/revoke 包装
- Phase 7 Audit 查询同一 `iam_audit_log`
- Phase 8 EmbedPolicy / Token Exchange（`iam_cli_res_perm`）/ Signing Key rotate+confirm
- Phase 9 Dashboard 只读聚合 + Config READ_ONLY
- Phase 10 Vue 3 控制台页面、Axios 错误映射、RBAC 菜单隐藏、Secret/Token 内存、Playwright mock E2E、`npm run build`

## [部分实现]

- 全部 Admin CRUD 的 **五类证据集成测试**：测试类已写，Docker/Oracle/Redis **本环境未执行**
- 控制台 **真实** OIDC/BFF 登录 E2E（Playwright 只 mock `/api/admin/me`）
- 多节点 Signing Key（仍是进程内存私钥，文档已说明）
- Session 计数 SCAN 在 Redis Cluster 上为近似值
- 前端 dist **未**打进授权服务器 jar

## [设计存在但代码未实现]

- 危险配置运行时动态修改（明确禁止）
- `dashboard_statistics` 表（明确禁止）
- TokenExchange 第二张策略表（明确禁止）
- Admin 删除仍用于验签的 Signing Key（明确禁止）
- 前端把 Access Token 存 LocalStorage 的“方便方案”（明确禁止）
- OpenAPI 独立文档站点（仓库无 springdoc UI 作为 Admin 控制台依赖）
- 把 Vue dist 自动 copy 到 Spring Boot 静态资源的 Maven 插件

## 协议面回归（验收要求）

下列能力 **Admin 控制台只调用现有 API，没有改协议实现**。本 Phase 未重跑全量 `mvn verify`（Testcontainers）。既有模块单测/MVC 在 Phase 8–9 已绿的部分仍然有效，但不能冒充本 Phase 已重新证明：

OIDC / OAuth2 / PKCE / Client Credentials / Token Exchange / JWT / JWKS / SSO / Logout / Embed / Migration / Resource Server / SDK / Gateway。

## 前端构建

见 `iam-admin-ui`：`npm install`、`npm run build`、`npm test`、`npx playwright install chromium && npm run test:e2e`。
