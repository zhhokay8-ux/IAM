# 17 Portal iframe 集成 SystemN

**【已实现】** `EmbedCodeController`、`EmbedCodeServiceImpl`、静态 `iam-embed.js`、`EmbedExchangeIntegrationTest`。

## 流程

1. Parent client=`portal`，Child=`system-n`，policy 行：origin=`https://portal.example.com`，path 如 `/orders/*`。
2. 浏览器已有 IAM SSO Cookie。
3. Portal 前端 `POST /api/embed/code` JSON：`child_client_id`、`path`、`origin`、`nonce`（CSRF + Origin）。
4. 返回 `code`、`expires_at`（默认 30s）、原样回 nonce。
5. iframe `src` 指向子应用路径（业务 URL，不是 IAM）。
6. 子前端把 code+nonce+origin 交给子后端。
7. 子后端 **confidential** Basic 认证 `POST /api/embed/exchange`：`code`、`origin`、`nonce`、`session_id`。
8. 返回 `EmbedContext`（subject_id、session_id、allowed_path…）。子应用据此建 iframe 内会话。
9. `postMessage`：`IamEmbed.postToChild(iframe, msg, "https://child.example.com")`。禁止 `*`。

错 child / 错 origin / 重放 / 过期 / policy disabled 均有独立错误码 `IAM-406x`。

子后端示例：

```java
// POST /api/embed/exchange with Basic child:secret
```

Policy 无 Admin API，测试里 `policyRepository.save(...)`。
