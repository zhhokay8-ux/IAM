# 13 Portal → System1 SSO

**【已实现】** `SsoIntegrationTest.portalLoginCreatesSessionAndSystem1ReusesItWithoutLogin`。

## 为什么不用再输密码

IAM 认的是 Redis Session + Cookie `IAM_SSO_SESSION`，不是各系统各自的登录表。Portal 登录后 Cookie 在 IAM 域（或你反代到同一父域）。System1 再跳 `/oauth2/authorize?client_id=system-1&...` 时 `AuthorizationController` 调 `ssoAuthenticationService.subjectFromRequest`，同一 sid 即签发新的 **authorization code**（audience/scope 按 system-1 的 permission）。

```
Browser
  POST IAM /sso/login          → Set-Cookie IAM_SSO_SESSION
  GET  IAM /oauth2/authorize   → 302 Portal callback?code&state
  POST IAM /oauth2/token       → Portal Access Token
  用户点「订单」
  GET  IAM /oauth2/authorize?client_id=system-1&redirect_uri=...&PKCE
       Cookie 仍在 → 不再 login
  302 System1 callback?code&state
  System1 BFF POST /oauth2/token → System1 Access Token（aud=system1 资源）
  System1 建自己的业务 Session
```

HTTP 示例见 [21](21-API参考.md)。`state`/`nonce`/`code_challenge` 每个 client 每次登录都应新生成。
