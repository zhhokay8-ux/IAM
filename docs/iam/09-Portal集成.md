# 09 Portal 集成 IAM

**【已实现】** IAM 侧 OIDC Code + PKCE、SSO Cookie、Token 端点。  
**【设计存在但代码未实现】** Portal 前端/BFF 工程。以下是按当前 API 应如何写 Portal。

## 为什么用 BFF

授权码出现在浏览器 redirect 的 query 里（`AuthorizationService` 只拼 `code` 与 `state`，没有 `access_token`）。**Token 交换必须在 Portal 后端**完成，否则 `client_secret` 和 `refresh_token` 会进浏览器。【当前项目不支持】纯前端拿 Refresh Token。

```
Browser → Portal UI → IAM /sso/login（Cookie）
Browser → Portal UI → IAM /oauth2/authorize → 302 callback?code&state
Browser → Portal BFF /callback → BFF POST IAM /oauth2/token
Portal BFF 建自己的 Session（本 IAM 不替 Portal 管业务 Session）
```

## 1. 注册 Portal Client

同 [08](08-Client注册.md)：`client_id=portal`，confidential，PKCE 强制，redirect 精确到 `https://portal.example.com/login/callback`。CORS 把该 Origin 加进 `iam.cors.allowed-origins`。

## 2. 登录按钮（前端）

本仓库 SSO 登录是 JSON，不是 HTML 表单：

```javascript
// 1) 建立 IAM SSO（username + password）
await fetch("http://localhost:8080/sso/login", {
  method: "POST",
  credentials: "include",
  headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfFromCookie() },
  body: JSON.stringify({ username: "alice", password: "ChangeMe123!", tenant_id: "tenant-1", client_id: "portal" })
});
```

Cookie `IAM_SSO_SESSION` HttpOnly、SameSite=Lax、Secure 视配置。跨站调用必须 CORS allowlist + credentials。随后 CSRF：后续 POST 要带 `IAM_CSRF` 对应头 `X-CSRF-Token`（`CsrfValidationFilter` 在带 SSO Cookie 的写请求上强制 Origin/Referer）。

然后跳转授权：

```javascript
const params = new URLSearchParams({
  client_id: "portal",
  redirect_uri: "https://portal.example.com/login/callback",
  response_type: "code",
  scope: "openid",
  state: randomState(),
  nonce: randomNonce(),
  code_challenge: s256(verifier),
  code_challenge_method: "S256"
});
window.location.href = "http://localhost:8080/oauth2/authorize?" + params.toString();
```

`code_challenge_method` 只允许 S256（plain → `INVALID_PKCE`）。无 SSO Cookie 时 authorize 失败（`SESSION_NOT_FOUND`）。

## 3. Callback（Portal 后端）

浏览器把 `code`、`state` 交给 BFF。BFF 校验 state，再：

```http
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(portal:super-secret)

grant_type=authorization_code
&code=...
&redirect_uri=https://portal.example.com/login/callback
&code_verifier=...
```

响应 `TokenResponse`：`access_token`、`token_type=Bearer`、`expires_in`、可能有 `refresh_token`、`id_token`、`scope`。

Java：`RestClient` form + Basic。Refresh 只放 BFF 服务器。

## 4. 当前用户

- **没有**可用的 UserInfo 端点（Discovery 有 URL，无 Controller）。
- 解 ID Token（`nonce`、`sub`、`aud`=client_id）或 Access Token claims（见 [14](14-Token.md)）。
- 业务侧用 `IamUserContextHolder`（username 字段 SDK **填 null**，Filter 不读用户名 claim）。

## 5. Logout

见 [18](18-Logout.md)。Portal 清自己 Session，再 `POST /oidc/logout?logout_type=global` 且带 CSRF。
