# IAM Admin 反向验证硬性规则

任何 Admin CRUD（含 disable / rotate / revoke / 改权限 / 改策略）若无法证明 **IAM Runtime 已经按新状态执行**，不得标记为已完成。

HTTP 200 只是五类证据中的第一项，单独成立 = **FAIL**。

---

## 1. 五类证据（缺一 FAIL）

| # | 证据 | 必须看到什么 | 不算数 |
|---|---|---|---|
| 1 | Admin API | 真实 ` /api/admin/**` 请求：认证、RBAC、成功/失败体 | 直接调领域 Service、只测 DTO |
| 2 | DB / Redis | 提交后查询物理状态：表行、hash、TTL、key 删除 | 只断言 API 响应字段 |
| 3 | Runtime | 现有运行时组件读取该状态（`IamPolicyEvaluator`、`IamClientValidator`、`IamSessionService`、`JwtSigner`、`EmbedPolicyService` 等） | Admin 模块再写一套 `if INACTIVE`；Mockito mock 掉 Evaluator |
| 4 | 协议 | 授权协议 HTTP 行为变化：`/oauth2/authorize`、`/oauth2/token`、introspect、revoke、SSO、Exchange、CC、Embed、Logout、JWKS | 只打 Admin 探测接口 |
| 5 | Audit | `iam_audit_log` 中 **约定事件名** + operator/resource/success；密钥已脱敏 | 用 `ADMIN_WRITE` 冒充业务事件；日志里有 secret |

同一测试方法（或同一集成场景的连续步骤）必须把 1→5 串起来，不能拆成互不相关的绿条。

---

## 2. 标准范例：Admin Disable Client

全部成立才算 PASS：

```
Admin API Disable Client
        ↓
iam_client.status = INACTIVE          （DB）
        ↓
IamPolicyEvaluator.validateClient
  → IamClientValidator                （Runtime 读 INACTIVE）
        ↓
GET /oauth2/authorize 被拒绝
  → IAM-4011 CLIENT_INACTIVE          （协议）
        ↓
AuditEvent.CLIENT_DISABLED            （Audit）
```

当前缺口（Phase 0/1 事实，不能假装已有）：

- **没有** Admin Disable Client API
- `IamClientService.update(..., INACTIVE)` + `AuthorizationControllerTest.clientDisabled` 已能证明 **协议拒绝**
- `AuditEvent` **没有** `CLIENT_DISABLED`（仅有 `CLIENT_UPDATED`）
- 因此即便将来 Admin 调 `update` 得到 200，在补齐 `CLIENT_DISABLED` 写入与断言之前，**不能标完成**

---

## 3. 其它 CRUD 的最低协议锚点

实现对应功能时，测试必须打到这些 Runtime/协议面（可增不可减）。状态以源码为准，禁止另造平行表。

| Admin 操作 | 状态证据 | Runtime | 协议证据 | Audit（若枚举没有则先加枚举再标完成） |
|---|---|---|---|---|
| Disable Client | `iam_client.status=INACTIVE` | `IamPolicyEvaluator.validateClient` | `/oauth2/authorize` 或 `/oauth2/token` → `CLIENT_INACTIVE` | `CLIENT_DISABLED` |
| Enable Client | `status=ACTIVE` | 同上放行 | authorize 能发 code | `CLIENT_UPDATED` 或专用事件 |
| Rotate secret | `client_secret_hash` 变更；旧 hash 失效 | `ClientAuthenticationProvider` | token 旧 secret 失败、新 secret 成功 | `SECRET_ROTATED`（枚举暂缺） |
| 改 redirect URI | `iam_client_redirect_uri` 精确行 | `IamRedirectUriValidator` | 旧 URI mismatch，新 URI 成功 | `CLIENT_UPDATED` |
| Disable Resource/Scope | 对应表 `INACTIVE` | `validateScope` / `requireActive` | token/authorize → `SCOPE_INACTIVE` 等 | 专用事件，禁止只记 `ADMIN_WRITE` |
| 改 Token Exchange 权限 | `iam_cli_res_perm` grant=`TOKEN_EXCHANGE` | `validateTokenExchangePermission` | `POST /oauth2/token` exchange 拒绝或成功 | `POLICY_CHANGED` |
| 改 CC 权限 | 同行 `CLIENT_CREDENTIALS` | `validateClientCredentialsPermission` | CC token 拒绝或成功 | `POLICY_CHANGED` |
| Disable User | `iam_user.status=INACTIVE` | `IamUserService.requireActiveForToken` | 发 token / Admin Bearer 失败 `USER_INACTIVE` | `USER_DISABLED`（枚举暂缺） |
| Revoke Session | Redis `session:{sid}` 无或 REVOKED | `IamSessionService` | 带该 Cookie 的 authorize/SSO 失败 | `SESSION_REVOKED`（枚举暂缺） |
| Revoke Token | refresh 行/jti 黑名单 | `TokenRevocationService` / introspect | introspect `active=false`；再用 refresh 失败 | `TOKEN_REVOKED` |
| Embed policy 变更 | `iam_embed_policy` | `EmbedPolicyService.requireActive` | embed exchange 拒绝或成功 | 专用或 `POLICY_CHANGED` |
| 密钥轮换 | `iam_signing_key` 元数据；私钥仍不落库 | `JwtSigner` / JWKS | 新 token kid；`/.well-known/jwks.json` 含新 key | 专用 rotate 事件（枚举暂缺） |

Session 在 Redis 不在 SQL：撤销类必须查 Redis，不能只查 Oracle。

---

## 4. 测试写法要求

- 集成测试走真实 Flyway + 现有 `AbstractIamIntegrationTest`（有 Docker 时）。
- 先 Admin API，再 **独立** 用 Repository/`StringRedisTemplate` 读状态，再 **直接调用** `IamPolicyEvaluator`（或等价 Runtime），再 **MockMvc 打协议端点**，最后查 `IamAuditLogRepository`。
- 权限：操作者必须具备对应 `admin.*.write`；AUDITOR 打同一写接口必须 403，且 DB **不变**。
- 禁止在 Admin Controller 里复制 `IamClientValidator` 的 ACTIVE 判断。

---

## 5. 完成定义

文档、PR、对话里写「XXX 已完成」之前，必须能指出：

1. Admin API 测试方法名  
2. 状态断言（表/key + 字段值）  
3. Runtime 调用点  
4. 协议 URL + 错误码/成功断言  
5. `AuditEvent` 名 + 审计行存在  

五条都能指向仓库里的测试，才允许 DONE。Phase 1 的 security probe **不是** CRUD，不适用本表的业务事件，但写探测仍须有 `ADMIN_WRITE` 审计。
