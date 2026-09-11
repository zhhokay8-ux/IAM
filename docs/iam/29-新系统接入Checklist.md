# 29 新系统接入 IAM Checklist

### IAM 管理员

- □ 创建 Resource（audience）
- □ 创建 Scope
- □ 创建 Client（secret 只显示一次）
- □ LOGIN_CALLBACK redirect 精确匹配
- □ LOGOUT_CALLBACK（若要全局退出）
- □ access/refresh TTL
- □ permission：AUTHORIZATION_CODE 以及需要的 TOKEN_EXCHANGE / CLIENT_CREDENTIALS
- □ iframe：插入 `iam_embed_policy`
- □ CORS Origin
- □ 用户 + identity mapping（迁移时）

> 无 HTTP Client Admin：用 Java Service 或受控 SQL。

### 后端

- □ 依赖 `iam-sdk-spring-boot`
- □ `iam.issuer` / `iam.resource-server.audience`
- □ JWKS 默认同 issuer（勿配错环境）
- □ `@RequireScope` / `@RequireRole`
- □ 高风险接口考虑启用 jti 检查
- □ 不要每请求 introspect

### 前端

- □ Login：SSO + authorize PKCE
- □ Callback 只给 BFF
- □ Logout + CSRF
- □ 401/403/Session 过期处理
- □ 禁止 Refresh Token 进浏览器
- □ iframe 用 `iam-embed.js` 明确 targetOrigin

### 测试

- □ Login
- □ SSO 二次 authorize 免密
- □ JWT iss/aud/exp
- □ Scope / Role
- □ Token Exchange
- □ Client Credentials
- □ iframe 单次 code
- □ Global logout + back-channel
- □ Refresh 轮换与 reuse
- □ redirect 差一字符失败
