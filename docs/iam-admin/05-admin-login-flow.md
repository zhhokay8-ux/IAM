# Phase 2：Admin Login Flow

```
浏览器 GET /admin/login
        ↓
BFF 生成 state、nonce、code_verifier（只存 Redis admin:oauth:{state}）
        ↓
302 /oauth2/authorize
  client_id=iam-admin
  redirect_uri=精确注册值
  response_type=code
  scope=openid
  state / nonce
  code_challenge S256
        ↓
【DEVELOPMENT ONLY】若无 SSO Cookie：
  authorize 把 error 送到 /admin/callback（invalid_request）
  用户需先 POST /sso/login（无密码，非生产）
        ↓
已有 IamSession Cookie → AuthorizationService 发 code
        ↓
302 /admin/callback?code&state
        ↓
BFF consume pending（一次性）
  TokenAuthenticationService(client_id, client_secret)  // secret 不出浏览器
  TokenService authorization_code + code_verifier
  校验 id_token.nonce / aud
  丢弃并 revoke access_token + refresh_token
  继续使用（或补写）IamSession Cookie
        ↓
302 iam.admin.oauth.post-login-uri（默认 /admin）
        ↓
后续 GET /api/admin/me 用 Cookie → AdminPrincipal（roles/permissions）
```

Logout：

```
POST /admin/logout
  Cookie + X-CSRF-Token + 允许的 Origin
        ↓
LogoutService.globalLogout
  Redis session 删除
  refresh 按 subject 撤销
  BackChannelLogoutService.notifyClients
  清 SSO Cookie
```

不修改 `/oidc/logout` 与 BCL 协议实现，Admin 只调用现有服务。
