# 07 Redis

前缀定义：`com.example.iam.core.redis.RedisKeyConstants`。TTL：`IamRedisProperties` / `application.yml` `iam.redis.*`。

| Redis Key | 用途 | TTL | 写入 | 读取 | 删除/消费 |
|---|---|---|---|---|---|
| `auth:code:{code}` | 授权码一次性 | 60s | Authorize 成功 | `/oauth2/token` authorization_code | 兑换后删除（防重放） |
| `oauth:state:{state}` | OAuth state | 5m | Authorize | 校验 | 过期 |
| `pkce:state:{state}` | PKCE S256 challenge | 5m | Authorize | token 时对照 verifier | 兑换 |
| `oidc:nonce:{nonce}` | OIDC nonce | 5m | Authorize | 发 ID Token | 过期 |
| `session:{sid}` | SSO Session JSON | 8h | login / migration redeem | authorize、sso/session、embed、logout | logout 删除或标记 revoked |
| `embed:code:{code}` | iframe 一次性码 | 30s | `/api/embed/code` | `/api/embed/exchange` | 兑换后删除，重放 `EMBED_CODE_REPLAY` |
| `migration:ticket:{ticket}` | 迁移一次性票 | 30–60s（默认 45s） | `/api/migration/ticket` | `/migration/login` | 兑换删除，重放 `MIGRATION_TICKET_REPLAY` |
| `refresh:status:{tokenHash}` | Refresh 状态辅助 | 30d | 签发/轮换 | refresh grant | reuse 时吊销家族 |
| `revoked:jti:{jti}` | Access Token 吊销 | 默认 15m 或剩余 exp | `/oauth2/revoke`、logout 路径相关 | `JtiValidator`（SDK 默认关闭） | TTL |
| `rate:limit:{key}` | 策略模块计数 | 1m | `RateLimitRepository` | 同左 | TTL。网关 Filter **不用 Redis** |

一次性：code / embed / ticket 均为 consume-once。Redis 不可用：登录、授权码、SSO **不可用**；已缓存 JWKS 的普通 API **仍可用**（`IamHighAvailabilityTest`）。高风险开启 jti 时 Redis/introspect 失败 Fail Closed。
