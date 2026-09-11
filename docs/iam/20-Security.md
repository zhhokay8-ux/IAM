# 20 Security

均来自源码，不是设计愿望。

| 机制 | 状态 | 证据 |
|---|---|---|
| PKCE | 【已实现】仅 S256 | Authorize / Token |
| state / nonce | 【已实现】Redis 5m | |
| redirect URI | 【已实现】精确匹配 | `IamRedirectUriValidator` |
| CORS | 【已实现】allowlist，禁 `*` | `CorsOriginValidator` |
| CSRF | 【已实现】Cookie 会话写请求 | `CsrfValidationFilter`；OAuth token 路径豁免 |
| Cookie HttpOnly/Secure/SameSite | 【已实现】SSO HttpOnly；CSRF 非 HttpOnly | `SsoCookieService` |
| frame-ancestors | 【已实现】普通页 none；embed 用 parent list；禁 ALLOW-FROM | `SecurityHeadersFilter` |
| postMessage | 【已实现】禁 `*` | `iam-embed.js` |
| Token 日志 | 【已实现】脱敏 + 拒 query access_token | `SensitiveDataMasker` |
| Open Redirect | 【已实现】redirect 必须登记 | |
| Refresh Rotation / reuse | 【已实现】 | |
| JTI 吊销 | 【部分实现】Revoke 写入；SDK 默认不查 | `IamSecurityConfiguration` |
| Rate Limit | 【部分实现】网关进程内；IAM 策略 Redis 库存在但网关未接 | |
| Brute force 登录 | 【设计存在但代码未实现】无密码也无锁定 | |
| Token Exchange aud/scope | 【已实现】 | |
| JWKS / Key rotation | 【部分实现】旋转服务有；私钥内存丢失 | |
| 登录密码 | 【设计存在但代码未实现】`SsoLoginRequest` 无 password | |

生产务必：HTTPS、`IAM_SSO_COOKIE_SECURE=true`、强 admin token、CORS 收紧、不要把 issuer 配成带 userinfo 的 URL（Discovery 会拒）。
