# Phase 10：E2E 测试报告

工具：Playwright（`iam-admin-ui/e2e`），对 Vite preview 做 **API contract mock**，不启动 Oracle/Redis。本机 **6 passed**。

| 场景 | 结果 | 说明 |
|---|---|---|
| Admin Login 页 | 自动化 PASS（mock 401） | 真实 BFF+OIDC+SSO Cookie **未在本机无 Docker 下联跑** → 协议登录 [部分实现] |
| Dashboard | PASS（mock dashboard） | ECharts 容器渲染 |
| Client Create + Secret 确认 | PASS | 一次性 secret 对话框 |
| Client Disable / Rotate Secret | PASS | mock API |
| Resource Create | PASS | mock API |
| Permission Change | PASS | mock enable |
| User Disable | PASS | mock API |
| Session Revoke | PASS | mock API |
| Token Revoke | PASS | 敏感横幅 + memory |
| Audit 查询 | PASS | mock `CLIENT_DISABLED` |
| Signing Key Rotate | PASS | body `confirm=true` |
| Logout | PASS | 回登录页 |

**不是** IAM Admin 反向验证五类证据（Admin API + DB + Runtime + 协议 + Audit）。那些仍以前端之前的 Java 集成测试为准，且本机无 Docker 时集成测试未执行。
