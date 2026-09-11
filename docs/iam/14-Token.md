# 14 Token 生命周期与 JWT 结构

证据：`AccessTokenServiceImpl`、`IdTokenServiceImpl`、`RefreshTokenFamilyServiceImpl`、Client `accessTokenTtl`/`refreshTokenTtl`、Redis TTL。

## 生命周期

```
Authorization Code (Redis 60s, 一次性)
    → Access Token (JWT, TTL=该 Client.accessTokenTtl 秒)
    → ID Token（授权码成功且 scope 含 openid 时；nonce 来自 authorize）
    → Refresh Token（哈希入库 + 明文只返回一次；TTL=Client.refreshTokenTtl）
         → 轮换：每次 refresh 发新 RT，旧的作废
         → 复用旧 RT：吊销整个 family
Revoke / Global logout：jti 进 Redis；RT family revoke
```

`iam.jwt.access-token-ttl` 在 yml 存在，**签发时长以 Client 表秒数为准**（Grant Handler 读 `client.getAccessTokenTtl()`）。

JTI：Access Token 由 `IdGenerator.next()` 生成（claims.jti 空时）。Introspect 读 jti。SDK 默认不查吊销列表。

## Access Token Claims（实际写入）

Header：JWS RS256，含 `kid`（`JwtSigner`）。

Payload（`AccessTokenServiceImpl`）：

| Claim | 有？ |
|---|---|
| iss | 是，`iam.issuer` |
| sub | 是 |
| aud | 是，列表 |
| iat / nbf / exp | 是，nbf=iat |
| jti | 是 |
| client_id | 是 |
| scope | 是，空格串 |
| roles | 非空才写 |
| tenant_id / org_id | 非空才写 |
| act | `{ "sub": actSub }`，Token Exchange 带 actor 时 |
| token_use | 非空才写 |

**没有** username、email、azp 等。不要假设 UserInfo。

## ID Token

`iss`、`sub`、`aud`（单 aud=client）、`iat`、`exp`、`nonce`。typ JWT。无 roles。

## 示例（结构示意，非真实签名）

```json
{ "alg": "RS256", "kid": "iam-key-...", "typ": "JWT" }
{ "iss": "http://localhost:8080", "sub": "0199...", "aud": ["system-order-api"],
  "client_id": "system-order", "scope": "openid order.read", "jti": "...", "exp": 0, "iat": 0, "nbf": 0 }
```
