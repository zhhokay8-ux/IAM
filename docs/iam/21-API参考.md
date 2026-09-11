# 21 API 参考

扫描 `src/main/java` 中 `@RestController`。错误体：`ApiErrorResponse`（traceId、code、message、timestamp），HTTP 状态来自 `IamErrorCode`。

| Method | Path | 功能 | 认证 | Request | Response |
|---|---|---|---|---|---|
| GET | `/.well-known/openid-configuration` | OIDC Discovery | 否 | — | issuer、endpoints、grant 列表 |
| GET | `/.well-known/jwks.json` | JWKS | 否 | — | JWK Set |
| GET | `/oauth2/authorize` | 授权码 | SSO Cookie | query：client_id, redirect_uri, response_type=code, scope, state, nonce, code_challenge, code_challenge_method=S256 | 302 Location=redirect?code&state |
| POST | `/oauth2/token` | 发 Token | Client Basic 或 form secret | form grant_type=authorization_code\|refresh_token\|client_credentials | TokenResponse JSON |
| POST | `/oauth2/token` | Token Exchange | 同上 | grant_type=urn:ietf:params:oauth:grant-type:token-exchange 或 token-exchange；subject_token 等 | TokenResponse |
| POST | `/oauth2/introspect` | 内省 | confidential client | form token | `{active, sub, aud, client_id, scope, token_type, exp, iat, jti}` |
| POST | `/oauth2/revoke` | 吊销 | client | form token, token_type_hint | 204 |
| POST | `/sso/login` | SSO | username + password + tenant_id + client_id | JSON | SsoSessionResponse + Set-Cookie |
| GET | `/sso/session` | 当前 SSO | Cookie | — | SsoSessionResponse |
| GET/POST | `/oidc/logout` | 登出 | Cookie；POST 需 CSRF | query logout_type | 204 |
| POST | `/oidc/backchannel-logout` | RP 收 logout_token | logout_token | form | 204 |
| POST | `/api/embed/code` | 发 embed code | SSO Cookie + CSRF | JSON child_client_id, path, origin, nonce | code, expires_at… |
| POST | `/api/embed/exchange` | 兑 embed | confidential child | JSON code, origin, nonce, session_id | EmbedContext |
| POST | `/api/migration/ticket` | 发迁移票 | confidential | JSON camel/snake 见 Controller record：client_id, system_code, external_user_id… | ticket, expiresAt, loginPath |
| GET | `/migration/login` | 兑票建 SSO | ticket + 绑定 cookie | query **仅 ticket**（禁 session/JWT） | 302 return_to |
| GET | `/api/users/{subjectId}` | 查用户 | `X-IAM-Admin-Token` | — | UserResponse |
| POST | `/api/users` | 建用户 | Admin | JSON camelCase | 201 |
| PUT | `/api/users/{subjectId}` | 更新 | Admin | UpdateUserRequest | UserResponse |
| POST | `/api/users/{subjectId}/identity-mappings` | 映射 | Admin | IdentityMappingRequest | 201 |
| GET | `/api/users/{subjectId}/identity-mappings` | 列映射 | Admin | — | list |

**没有**：`/oidc/userinfo`（Discovery 有）、`/health`、`/actuator/**`、Swagger、Client/Resource Admin HTTP。

## 调用示例

Authorize（需已 login）：

```bash
curl -I -b "IAM_SSO_SESSION=sid" \
  "http://localhost:8080/oauth2/authorize?client_id=portal&redirect_uri=https://portal.example.com/login/callback&response_type=code&scope=openid&state=s1&nonce=n1&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"
```

Token 错误时 HTTP 4xx，body `{"traceId":"...","code":"IAM-4013","message":"...","timestamp":"..."}`。

Introspect 无效 token：`{"active":false}`（其余字段 null）。
