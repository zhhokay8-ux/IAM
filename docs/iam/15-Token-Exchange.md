# 15 Token Exchange

**【已实现】** RFC grant `urn:ietf:params:oauth:grant-type:token-exchange`，别名 `token-exchange`。`actor_token` **已实现**（`ActorTokenValidator` + `act.sub` claim）。证据：`TokenExchangeController`、`TokenExchangeServiceImpl`、`TokenExchangeIntegrationTest`。

## 场景

System1 已有用户 Access Token A（aud=system-1-api）。后端调用 SystemN 时换 Token B（aud=system-n-api），**sub 保持用户**。

权限：调用方 Client 必须有对目标 resource+scope 的 `TOKEN_EXCHANGE` permission（`TokenExchangePolicyService`）。

## curl

```bash
curl -s -X POST http://localhost:8080/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u system-1:super-secret \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=$TOKEN_A" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  -d "requested_token_type=urn:ietf:params:oauth:token-type:access_token" \
  -d "audience=system-n-api" \
  -d "scope=order.read" \
  -d "actor_token=$OPTIONAL_ACTOR" \
  -d "actor_token_type=urn:ietf:params:oauth:token-type:access_token"
```

`subject_token` 必须能被 IAM `JwtSigner.verify`（同一套钥）。过期/错 iss/错 aud → 对应 JWT 错误码。新 Token **新 jti、新签名**。

## Java（System1 后端）

`RestClient` form 同上。不要把 Token A 当 Token B 转发给 SystemN。

## SystemN 校验

SDK：`iam.resource-server.audience=system-n-api`，scope `order.read`。System1 的 aud **不会**通过 AudienceValidator。
