# 18 Logout

**【已实现】** `LogoutController`、`LogoutServiceImpl`、`BackChannelLogoutServiceImpl`。

| 类型 | 何时 | 行为 |
|---|---|---|
| `logout_type=local` | 只离开当前浏览器 IAM Cookie | 清 Cookie，**不**删 Redis Session、不吊销 RT、不通知 RP |
| `logout_type=global` 或默认 | 全站退出 | 删 Session、`revokeAllForSubject` Refresh、向各 client 的 LOGOUT_CALLBACK POST `logout_token` |
| RP `POST /oidc/backchannel-logout` | 业务系统收 IAM 通知 | 校验 logout_token，清本地 Session |
| `/oauth2/revoke` | 客户端主动作废 AT/RT | confidential 认证；AT 按 jti 进 Redis |

```
Portal Logout
  → POST IAM /oidc/logout?logout_type=global   （SSO Cookie + CSRF + Origin）
  → IAM 删 session:{sid}
  → 吊销该用户 refresh family
  → BackChannelLogoutClient POST 各 logout URI
  → System1/SystemN 删自己的 Session
```

GET 与 POST `/oidc/logout` 都支持。响应 204。带 SSO Cookie 的 POST 必须过 CSRF。`/oidc/backchannel-logout` 在 CSRF 白名单中。
