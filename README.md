# 统一认证中心及多业务系统 SSO/Token 互认架构设计方案

## 1. 方案目标

当前门户系统具备自身登录能力，同时已经集成业务系统 1、业务系统 2……业务系统 N。随着业务系统数量增加，如果继续采用“门户分别对接各业务系统”“业务系统之间两两互信”的模式，会逐渐出现以下问题：

- 登录协议和登录态不统一；
- 系统间 Token 两两互认，信任关系呈 N² 增长；
- iframe 跨域场景依赖第三方 Cookie，容易受浏览器策略影响；
- 新系统接入需要修改门户或认证逻辑；
- Token 签发、撤销、审计、密钥轮换难以集中治理；
- 存量系统登录态难以统一迁移。

因此建议建设独立的**统一认证中心 IAM/IdP/Authorization Server**，门户及所有业务系统全部作为认证中心的 Client / Resource Server 接入。

推荐协议基线采用：

- OpenID Connect 1.0：负责用户登录和身份认证；
- OAuth 2.0 Authorization Code Flow + PKCE：负责前端登录授权；
- OAuth 2.0 Token Exchange（RFC 8693）：负责业务系统间用户身份委托；
- JWT + JWKS：负责 Access Token 离线校验；
- OAuth 2.0 Security BCP（RFC 9700）：作为安全实现基线。

OIDC 本身就是构建在 OAuth 2.0 之上的身份层，而 RFC 9700 是目前 OAuth 2.0 的安全最佳实践，应优先遵循其中关于授权码、重定向 URI、Token 等安全要求。

---

# 2. 总体架构

```text
                           ┌────────────────────────────┐
                           │        用户浏览器           │
                           └─────────────┬──────────────┘
                                         │
                    ┌────────────────────┼─────────────────────┐
                    │                    │                     │
                    ▼                    ▼                     ▼
             ┌─────────────┐      ┌─────────────┐       ┌─────────────┐
             │ 统一门户     │      │ 业务系统 1   │ ..... │ 业务系统 N  │
             │ OIDC Client │      │ Client + RS │       │ Client + RS │
             └──────┬──────┘      └──────┬──────┘       └──────┬──────┘
                    │                    │                     │
                    └─────────────┬──────┴──────────┬──────────┘
                                  │                 │
                                  ▼                 ▼
                     ┌───────────────────────────────┐
                     │       API Gateway / WAF       │
                     └───────────────┬───────────────┘
                                     │
                                     ▼
              ┌─────────────────────────────────────────────┐
              │               统一认证中心                  │
              │                                             │
              │ Authorization Endpoint                      │
              │ Token Endpoint                              │
              │ OIDC / UserInfo                             │
              │ Token Exchange / STS                        │
              │ JWKS / Introspection                        │
              │ SSO Session / Logout                        │
              │ Client Registry / 接入配置                  │
              └──────────────┬───────────────┬──────────────┘
                             │               │
                      ┌──────▼──────┐  ┌────▼────────┐
                      │ Redis Cluster│  │ DB Cluster  │
                      │ Session/Code │  │ Client/User │
                      │ Refresh/JTI  │  │ Config/Audit│
                      └─────────────┘  └─────────────┘
                             │
                       ┌─────▼──────┐
                       │ KMS / HSM  │
                       │ Signing Key│
                       └────────────┘
```

认证中心是整个体系中唯一或受控的 Token Issuer，例如：

```text
iss = https://auth.example.com
```

所有业务系统只需要信任认证中心，而不需要彼此保存公钥或建立双向 Token 信任。

信任关系由：

```text
原方案：
System1 <-> System2
System1 <-> SystemN
System2 <-> SystemN
...
复杂度约 O(N²)

推荐方案：
                  Auth Center
                /     |      \
          System1  System2 ... SystemN

复杂度约 O(N)
```

这也是整个方案最重要的架构约束。

---

# 3. 门户统一登录与 SSO 设计

## 3.1 最终目标

门户自身不再独立维护认证逻辑，而是变成认证中心的 OIDC Client。

用户访问：

```text
https://portal.example.com
```

发现没有门户本地 Session 后，跳转：

```text
GET https://auth.example.com/oauth2/authorize
    ?client_id=portal
    &response_type=code
    &redirect_uri=https://portal.example.com/login/callback
    &scope=openid profile
    &state=...
    &nonce=...
    &code_challenge=...
    &code_challenge_method=S256
```

认证成功后：

```text
Auth Center
    ↓ authorization code
Portal Backend
    ↓ POST /oauth2/token
Auth Center
    ↓ ID Token + Access Token
Portal
```

Portal 根据 ID Token 建立自己的 HttpOnly 本地 Session。

**浏览器不长期保存 Access Token。**

推荐优先采用：

```text
Browser
   ↓ Cookie
Portal BFF
   ↓ Bearer Access Token
Backend API
```

即 BFF（Backend For Frontend）模式。

---

# 4. 用户从门户无感进入业务系统

用户已经登录门户后点击业务系统 1。

流程：

```text
用户
 │
 │ 点击业务系统 1
 ▼
Portal
 │
 │ 302 -> System1
 ▼
System1
 │
 │ 无本地 Session
 │ 302 -> Auth Center /authorize
 ▼
Auth Center
 │
 │ 检查 Auth Center SSO Session
 │ 已登录，无需输入用户名密码
 │
 │ 返回 authorization_code
 ▼
System1 Callback
 │
 │ 后端换 Token
 ▼
Auth Center
 │
 │ ID Token + Access Token
 ▼
System1
 │
 │ 建立本地 Session
 ▼
用户直接进入 System1
```

这里虽然发生了浏览器 302 跳转，但用户不会看到第二次登录页面，因此属于标准意义上的 SSO。

整个过程中不要使用：

```text
portal?token=xxxx
system1?token=xxxx
```

这种 URL 传 Token 的方式。

原因包括：

- Token 进入浏览器历史；
- Web Server access log 可能记录；
- Referer 泄漏；
- 页面截图/监控平台泄漏；
- 无法正确约束 Audience。

授权码应是一次性、短生命周期，并且 redirect URI 严格预注册、精确匹配，这也符合当前 OAuth 安全最佳实践。

---

# 5. Token 体系设计

建议认证中心维护四类凭证：

| 类型 | 用途 | 建议 TTL |
|---|---|---:|
| Authorization Code | OIDC 登录换 Token | 30～60 秒 |
| ID Token | Client 确认用户身份 | 5～10 分钟 |
| Access Token | API 调用 | 5～15 分钟 |
| Refresh Token | 获取新 Access Token | 数小时～数天，采用 Rotation |

Access Token 推荐 JWT，使用：

```text
RS256
```

或：

```text
ES256
```

签名。

私钥仅存在认证中心/KMS/HSM。

业务系统只获取公钥。

---

# 6. Access Token 示例

Header：

```json
{
  "alg": "RS256",
  "typ": "at+jwt",
  "kid": "iam-key-2026-09"
}
```

Payload：

```json
{
  "iss": "https://auth.example.com",
  "sub": "u_100086",
  "aud": [
    "system-n-api"
  ],
  "client_id": "system-1",
  "scope": "order.read order.query",
  "roles": [
    "order_viewer"
  ],
  "tenant_id": "tenant_01",
  "org_id": "org_1001",
  "iat": 1788847200,
  "nbf": 1788847200,
  "exp": 1788847800,
  "jti": "9ab42c74-a5b8-4d00-84a1-a89..."
}
```

其中最重要的字段：

```text
iss
```

表示：

> 谁签发了这个 Token。

```text
aud
```

表示：

> Token 是签发给谁使用的。

```text
sub
```

表示：

> 当前用户是谁。

```text
client_id
```

表示：

> 哪个 OAuth Client 获取了 Token。

```text
scope
```

表示：

> 本 Token 能做什么。

业务系统不能只验证：

```text
签名正确
```

而必须至少验证：

```text
1. alg
2. kid
3. signature
4. iss
5. aud
6. exp
7. nbf
8. scope / role
9. 必要情况下 jti/token 状态
```

否则会发生典型的 Token 跨系统滥用问题。

---

# 7. System1 与 SystemN Token 互认设计

## 7.1 不推荐方案

不要设计：

```text
System1 签 Token
      ↓
SystemN 信任 System1 公钥
```

以及：

```text
SystemN 签 Token
      ↓
System1 信任 SystemN 公钥
```

否则随着系统数量增加，就会变成：

```text
N × (N - 1)
```

级别的信任关系。

同时任何一个业务系统密钥泄漏，都可能影响整个体系。

---

# 8. 推荐信任链

统一设计成：

```text
             ┌───────────────┐
             │ Authentication│
             │    Center     │
             └───────┬───────┘
                     │
           JWT signing key
                     │
            ┌────────┴────────┐
            ▼                 ▼
        System1             SystemN
```

System1 和 SystemN 均只信任：

```text
issuer=https://auth.example.com
```

和认证中心 JWKS。

例如：

```http
GET /.well-known/openid-configuration
```

获取：

```json
{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/oauth2/authorize",
  "token_endpoint": "https://auth.example.com/oauth2/token",
  "jwks_uri": "https://auth.example.com/.well-known/jwks.json"
}
```

---

# 9. System1 调用 SystemN：Token Exchange

假设：

```text
用户 → System1 → SystemN
```

用户当前的 Access Token 是：

```text
aud = system-1-api
```

**System1 不应该直接把这个 Token 转发给 SystemN。**

因为这个 Token 本来并不是给 SystemN 使用的。

推荐使用 OAuth Token Exchange（RFC 8693）。RFC 8693 本身就是为安全令牌交换、身份委托和 impersonation/delegation 场景定义的标准机制。

流程：

```text
用户
 │ AccessToken A
 │ aud=system-1-api
 ▼
System1
 │
 │ POST /oauth2/token
 │ grant_type=token-exchange
 │ subject_token=A
 │ audience=system-n-api
 ▼
Auth Center / STS
 │
 │ 检查：
 │ System1 是否允许代表用户访问 SystemN
 │ 用户是否具有目标 scope
 │
 ▼
AccessToken B
 aud=system-n-api
 client_id=system-1
 act=system-1
 scope=xxx
 │
 ▼
System1
 │
 │ Authorization: Bearer B
 ▼
SystemN
```

交换后的 Token 可以增加：

```json
{
  "sub": "u_100086",
  "aud": "system-n-api",
  "client_id": "system-1",
  "scope": "contract.read",
  "act": {
    "sub": "system-1"
  }
}
```

这样 SystemN 可以同时知道：

```text
用户是谁：u_100086

谁代表用户调用：
system-1
```

从而形成清晰审计链：

```text
User
 ↓
System1
 ↓ Token Exchange
Auth Center
 ↓
SystemN
```

---

# 10. 纯后台系统间调用

如果没有用户参与：

```text
System1 → SystemN
```

采用：

```text
client_credentials
```

不要伪造用户 Token。

例如：

```http
POST /oauth2/token

grant_type=client_credentials
&client_id=system-1
&scope=system-n.data.read
&audience=system-n-api
```

Token：

```json
{
  "sub": "system-1",
  "client_id": "system-1",
  "aud": "system-n-api",
  "scope": "system-n.data.read"
}
```

因此体系明确区分：

```text
用户委托：
Token Exchange

系统身份：
Client Credentials
```

---

# 11. iframe / 微前端身份一致性设计

这是本方案中需要特别处理的一部分。

不能简单认为：

```text
Cookie 设置 SameSite=None
```

问题就解决了。

现代浏览器会限制第三方 Cookie；即使设置 `SameSite=None; Secure`，跨站 iframe 中的 Cookie 仍可能受用户设置、浏览器隐私机制和存储分区策略影响。Storage Access API 可以作为兼容机制，但不宜成为核心 SSO 的唯一基础。

因此分为两种模式。

---

# 12. 模式 A：同站点 iframe

例如：

```text
portal.example.com
system1.example.com
system2.example.com
```

属于不同 Origin，但通常仍属于同一 Site。

System1 自己建立：

```http
Set-Cookie:
SYSTEM1_SESSION=xxx;
HttpOnly;
Secure;
SameSite=Lax;
Path=/
```

不要尝试将所有业务 Session 做成：

```text
Domain=.example.com
```

共享 Cookie。

即：

```text
Portal 只读 Portal Cookie
System1 只读 System1 Cookie
SystemN 只读 SystemN Cookie
```

认证统一，但 Session 隔离。

---

# 13. 模式 B：真正跨站 iframe

例如：

```text
父页面：
https://portal.company-a.com

iframe：
https://business.company-b.com
```

推荐采用：

## Embed Code 模式

父页面首先向自己的后端请求：

```http
POST /api/embed-ticket
```

参数：

```json
{
  "target": "system-n",
  "page": "/order/detail/123"
}
```

Portal Backend 向认证中心申请一次性：

```text
Embed Code
```

例如：

```text
EC_r74x...
```

有效期：

```text
30 秒
```

一次性消费。

iframe：

```html
<iframe
  src="https://system-n.example.com/embed/bootstrap?code=EC_r74x..."
></iframe>
```

SystemN Backend 收到 code 后：

```text
SystemN
   ↓ server-to-server
Auth Center
   ↓ redeem embed code
SystemN
```

认证中心返回目标用户身份：

```json
{
  "sub": "u_100086",
  "aud": "system-n",
  "parent_client": "portal",
  "parent_origin": "https://portal.example.com",
  "exp": 1788847230
}
```

SystemN 从而确认：

```text
iframe 中的用户
=
Portal 当前登录用户
```

并且防止任意网站拿 SystemN iframe URL 伪造登录。

---

# 14. iframe 不依赖第三方 Cookie

如果浏览器允许第三方 Cookie，SystemN 可以建立：

```http
Set-Cookie:
SYS_N_SESSION=xxx;
Secure;
HttpOnly;
SameSite=None
```

但不能把它作为唯一机制。

推荐跨站 iframe 页面支持：

```text
Bearer Token / BFF Proxy / Embed Runtime Session
```

例如 SystemN iframe 获取 Embed Session 后，在页面运行期间把 Access Token 仅存放于：

```text
JavaScript 内存
```

而不是：

```text
localStorage
sessionStorage
URL
```

页面刷新后重新执行 Embed Bootstrap。

这样即使第三方 Cookie 被完全禁止，也能工作。

---

# 15. postMessage 身份握手

另一种适合微前端和 SPA iframe 的方式：

```text
Parent
  │
  │ iframe loaded
  ▼
Child
  │
  │ postMessage({type:"AUTH_READY"})
  ▼
Parent
  │
  │ POST /embed/token
  │ 获取 audience=system-n 的短期 Token
  │
  │ postMessage
  ▼
Child
```

父页面发送：

```javascript
iframe.contentWindow.postMessage(
  {
    type: "AUTH_TOKEN",
    token: "xxx",
    nonce: "abc123"
  },
  "https://system-n.example.com"
);
```

必须指定明确 targetOrigin：

```text
https://system-n.example.com
```

禁止：

```javascript
postMessage(data, "*")
```

Child 同样检查：

```javascript
if (event.origin !== "https://portal.example.com") {
    return;
}
```

并校验：

```text
nonce
audience
expiration
```

---

# 16. 微前端模式

如果采用 qiankun、Module Federation、Web Components 等微前端方案，推荐宿主提供统一的：

```text
Auth SDK
```

例如：

```javascript
auth.getUser()

auth.getAccessToken({
  audience: "system-n-api",
  scope: ["order.read"]
})

auth.fetch({
  audience: "system-n-api",
  url: "/api/order"
})
```

子应用不直接操作：

```text
认证 Cookie
Refresh Token
Client Secret
```

最好由宿主/BFF 提供受控 `fetch` 能力。

这样可以实现：

```text
门户身份
=
微前端身份
```

并减少 Token 泄漏面。

---

# 17. iframe 安全响应头

业务系统普通页面推荐：

```http
Content-Security-Policy:
frame-ancestors 'none';

X-Frame-Options: DENY
```

需要嵌入的页面则单独放：

```text
/embed/**
```

并配置：

```http
Content-Security-Policy:
frame-ancestors https://portal.example.com https://system1.example.com;
```

`frame-ancestors` 可以精确指定允许哪些父站点加载当前页面，是处理 iframe 白名单的推荐方式。

不要使用：

```text
X-Frame-Options: ALLOW-FROM
```

作为主要方案。

需要被跨域 iframe 嵌入的页面也不要继续设置：

```text
X-Frame-Options: SAMEORIGIN
```

否则会直接阻止跨域 iframe。

建议区分：

```text
普通业务页面：
frame-ancestors 'none'

允许门户嵌入页面：
frame-ancestors https://portal.example.com

允许多个业务系统嵌入：
frame-ancestors https://portal.example.com
                https://system1.example.com
                https://system2.example.com
```

所有祖先页面都必须满足 `frame-ancestors` 要求，否则嵌套 iframe 仍会被阻断。

---

# 18. CORS 配置

CORS 和 iframe 是两个不同问题。

iframe 能否加载主要看：

```text
CSP frame-ancestors
X-Frame-Options
```

JavaScript 能否跨域请求 API 才看：

```text
CORS
```

推荐：

```http
Access-Control-Allow-Origin:
https://portal.example.com

Access-Control-Allow-Methods:
GET,POST,PUT,DELETE

Access-Control-Allow-Headers:
Authorization,Content-Type,X-Request-ID

Vary:
Origin
```

严禁：

```http
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

组合使用。

Origin 应从认证中心或 API 网关配置中心的白名单动态匹配。

---

# 19. SameSite / Cookie 配置规范

门户自身 Cookie：

```http
Set-Cookie:
PORTAL_SESSION=xxx;
Path=/;
HttpOnly;
Secure;
SameSite=Lax
```

普通业务系统：

```http
Set-Cookie:
SYSTEM1_SESSION=xxx;
Path=/;
HttpOnly;
Secure;
SameSite=Lax
```

确实需要跨站 iframe Cookie：

```http
Set-Cookie:
SYSTEMN_SESSION=xxx;
Path=/;
HttpOnly;
Secure;
SameSite=None
```

但需要明确：

> `SameSite=None; Secure` 是允许跨站发送 Cookie 的必要条件之一，不代表浏览器一定允许第三方 Cookie。

浏览器可能继续阻断这类 Cookie。

因此：

```text
SameSite=None
```

属于兼容策略，

而：

```text
Embed Code + Token
```

才是推荐主路径。

---

# 20. CSRF 防护

所有 Cookie Session 接口必须防止 CSRF。

采用：

```text
SameSite
+
CSRF Token
+
Origin / Referer 校验
```

敏感接口再增加：

```text
二次确认/MFA
```

使用：

```text
Authorization: Bearer xxx
```

且 Token 不自动由浏览器携带的 API，CSRF 风险相对较低，但仍需要解决 XSS 风险。

---

# 21. 统一登出

需要区分：

```text
Local Logout
```

和：

```text
Global Logout
```

Local Logout：

```text
只销毁当前业务系统 Session
```

Global Logout：

```text
Portal
  ↓
Auth Center / logout
  ↓
销毁中央 SSO Session
  ↓
通知各 Client
```

可采用：

```text
OIDC Back-Channel Logout
```

优先于大量 iframe Front-Channel Logout。

业务系统收到通知：

```http
POST /oidc/backchannel-logout
```

根据：

```text
sid / sub
```

删除本地 Session。

---

# 22. JWT 撤销策略

JWT 最大优势是：

```text
业务系统本地验签
```

无需每次访问认证中心。

因此正常 API 链路：

```text
Request
 ↓
API Gateway / Business System
 ↓
本地 JWKS 验签
 ↓
业务请求
```

不要设计为：

```text
Request
 ↓
System1
 ↓
Auth Center
 ↓
Token Validate
 ↓
System1
```

否则认证中心会成为全系统同步单点。

对于 Token 撤销采取：

```text
短 Access Token
+
Refresh Token 可撤销
+
高风险场景 introspection
+
撤销事件推送
```

组合策略。

例如：

```text
Access Token：10 min

普通接口：
本地 JWT 校验

转账/审批/管理员操作：
JWT 校验 + Token Introspection / Session Status
```

---

# 23. JWKS 与密钥轮换

认证中心：

```http
GET /.well-known/jwks.json
```

返回：

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "key-2026-09",
      "use": "sig",
      "alg": "RS256",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

业务系统根据：

```text
kid
```

找到公钥。

密钥轮换：

```text
阶段 1：
JWKS 同时发布 Key A + Key B

阶段 2：
认证中心开始使用 Key B 签 Token

阶段 3：
等待所有 Key A Token 过期

阶段 4：
删除 Key A
```

因此不会出现：

```text
认证中心换密钥
→ 所有系统立即登录失效
```

的问题。

---

# 24. 核心接口清单

| 接口 | 用途 |
|---|---|
| `GET /.well-known/openid-configuration` | OIDC Discovery |
| `GET /.well-known/jwks.json` | 获取 Token 验签公钥 |
| `GET /oauth2/authorize` | OIDC/OAuth 授权 |
| `POST /oauth2/token` | authorization_code / refresh / client_credentials |
| `POST /oauth2/token` + token-exchange | System1 → SystemN Token 交换 |
| `POST /oauth2/revoke` | Token/Refresh Token 撤销 |
| `POST /oauth2/introspect` | 高风险接口实时检查 Token |
| `GET /oidc/userinfo` | 用户基础信息 |
| `GET/POST /oidc/logout` | 全局退出 |
| `POST /oidc/backchannel-logout` | 通知 Client 删除登录态 |
| `POST /api/embed/code` | 获取 iframe 一次性 Embed Code |
| `POST /api/embed/exchange` | Child Server 消费 Embed Code |
| `POST /api/migration/ticket` | 存量登录迁移 |
| `POST /admin/clients` | 新 Client 配置 |
| `PUT /admin/clients/{id}` | Client 配置更新 |
| `POST /admin/resources` | Resource Server 注册 |

---

# 25. Client 配置示例

例如 System1：

```yaml
client:
  id: system-1

  type: confidential

  redirectUris:
    - https://system1.example.com/login/oauth2/code/iam

  postLogoutRedirectUris:
    - https://system1.example.com/

  grantTypes:
    - authorization_code
    - refresh_token
    - urn:ietf:params:oauth:grant-type:token-exchange

  pkce:
    required: true

  scopes:
    - openid
    - profile
    - system1.read
    - system1.write

  audiences:
    own:
      - system-1-api

    tokenExchangeAllowed:
      - system-n-api

  iframe:
    enabled: true

    allowedParents:
      - https://portal.example.com
      - https://system-n.example.com

  logout:
    backChannelUri:
      https://system1.example.com/oidc/backchannel-logout
```

---

# 26. 新业务系统 N+1 接入

认证中心核心代码不允许因为增加 Client 而修改。

采用：

```text
Client Registry
+
Resource Registry
+
Policy Registry
```

配置化实现。

添加 System N+1 时：

```text
1. 注册 client_id
2. 生成 client credential / JWKS
3. 配置 redirect_uri
4. 注册 Resource Server
5. 注册 audience
6. 注册 scope
7. 注册允许调用哪些系统
8. 注册哪些系统可调用它
9. iframe parent Origin 白名单
10. logout callback
```

认证中心动态加载配置。

因此：

```text
System N+1
```

上线不需要：

```text
修改 Auth Center Java 代码
重新编译认证中心
```

最多只需要：

```text
新增数据库配置
+
配置审批
+
配置热加载
```

---

# 27. 推荐接入清单

每个系统接入必须提供：

| 配置项 | 示例 |
|---|---|
| Client ID | system-1 |
| Client 类型 | confidential/public |
| Owner | XXX 部门 |
| Redirect URI | https://.../callback |
| Logout URI | https://.../logout |
| Resource Audience | system-1-api |
| Scope | order.read |
| Token TTL | 10min |
| Client Authentication | private_key_jwt / secret |
| 是否允许 Token Exchange | true/false |
| 可调用 Resource | system-n-api |
| 可被哪些 Client 调用 | system-2 |
| iframe 是否开放 | true |
| iframe Parent Origin | https://portal... |
| CORS Origin | https://portal... |
| 用户映射规则 | employeeNo |
| Logout Callback | https://... |
| 环境 | DEV/UAT/PROD |
| 联系人 | XXX |

生产环境的 Client 配置建议经过：

```text
申请 → 审批 → 发布
```

而不是开放任意 Dynamic Registration。

---

# 28. 数据库表设计

## `iam_client`

```sql
id
client_id
client_name
client_type
status
token_endpoint_auth_method
access_token_ttl
refresh_token_ttl
pkce_required
owner
created_at
updated_at
```

---

## `iam_client_redirect_uri`

```sql
id
client_id
redirect_uri
uri_type
status
```

其中：

```text
uri_type:
LOGIN_CALLBACK
LOGOUT_CALLBACK
```

---

## `iam_resource_server`

```sql
id
resource_code
resource_name
audience
status
owner
created_at
```

例如：

```text
resource_code = SYSTEM_N
audience      = system-n-api
```

---

## `iam_scope`

```sql
id
resource_id
scope_code
scope_name
description
status
```

---

## `iam_client_resource_permission`

用于控制：

```text
谁允许访问谁
```

结构：

```sql
id
client_id
resource_id
scope_id
grant_type
status
created_at
```

例如：

```text
system-1
→ system-n-api
→ order.read
→ TOKEN_EXCHANGE
```

---

## `iam_user`

```sql
id
subject_id
username
display_name
status
tenant_id
org_id
created_at
updated_at
```

建议 `sub` 使用认证中心自己的不可变 ID。

不要使用：

```text
username
phone
email
```

作为 JWT `sub`。

因为这些字段可能发生变化。

---

## `iam_user_identity_mapping`

用于存量系统用户映射：

```sql
id
subject_id
system_code
external_user_id
external_username
mapping_status
created_at
```

例如：

```text
统一用户：
u_100086

System1：
E88271

SystemN：
zhangsan
```

统一映射为：

```text
u_100086
```

---

## `iam_refresh_token`

建议实际 Refresh Token 存 Hash。

```sql
id
token_hash
subject_id
client_id
session_id
issued_at
expires_at
revoked_at
rotation_parent_id
status
```

---

## `iam_signing_key`

仅保存 metadata。

```sql
id
kid
algorithm
kms_key_id
status
activated_at
retired_at
created_at
```

**不要把明文 RSA Private Key 放数据库。**

私钥保存：

```text
HSM / KMS / Secret Management
```

---

## `iam_embed_policy`

```sql
id
child_client_id
parent_client_id
parent_origin
allowed_path
status
created_at
```

从而精确控制：

```text
谁可以 iframe 谁
```

---

## `iam_audit_log`

```sql
id
trace_id
event_type
subject_id
client_id
resource_id
source_ip
user_agent
result
failure_reason
created_at
```

审计事件包括：

```text
LOGIN_SUCCESS
LOGIN_FAILURE
TOKEN_ISSUE
TOKEN_REFRESH
TOKEN_EXCHANGE
TOKEN_REVOKE
LOGOUT
CLIENT_CONFIG_CHANGE
EMBED_CODE_ISSUE
EMBED_CODE_EXCHANGE
```

---

# 29. Redis 数据设计

不建议把短期数据全部放数据库。

Redis 主要保存：

```text
SSO Session
Authorization Code
PKCE State
OAuth State
Nonce
Embed Code
Migration Ticket
Refresh Token 状态缓存
Token Revocation JTI
Login Attempt
Rate Limit
```

例如：

```text
auth:code:{code}
TTL = 60 sec
```

```text
embed:code:{code}
TTL = 30 sec
```

```text
oauth:state:{state}
TTL = 5 min
```

```text
session:{sid}
TTL = 8h
```

---

# 30. 高可用架构

推荐生产结构：

```text
                  GSLB / DNS
                      │
                WAF / LB Cluster
                      │
           ┌──────────┴──────────┐
           │                     │
     Auth Center AZ-A       Auth Center AZ-B
       Node 1/2/3             Node 4/5/6
           │                     │
           └─────────┬───────────┘
                     │
              Redis Cluster
               Multi-AZ
                     │
              DB HA Cluster
               Multi-AZ
                     │
                  KMS/HSM
```

认证中心应用层必须：

```text
无状态化
```

任何节点均可处理：

```text
authorize
token
jwks
userinfo
token-exchange
```

Session 放 Redis。

---

# 31. Token 校验高可用

普通业务请求：

```text
业务系统
  ↓
Local JWT Validator
  ↓
Local JWKS Cache
```

不要同步访问认证中心。

业务系统缓存：

```text
JWKS
Issuer
Audience
Policy
```

例如：

```text
JWKS cache TTL = 1h
refresh every = 10min
```

如果刷新失败：

```text
继续使用已缓存且未过期公钥
```

这意味着：

> 即使认证中心临时不可用，已经登录用户拿着有效 Access Token 仍然可以继续访问业务系统。

这是整个 HA 方案的重要能力。

---

# 32. 故障降级矩阵

| 故障 | 已签发 Token | 新登录 | Refresh | 普通 API |
|---|---|---|---|---|
| 单个 Auth 节点故障 | 正常 | 正常 | 正常 | 正常 |
| 整个 Auth Center 故障 | 有效期内正常 | 不可用 | 不可用 | 正常 |
| Redis 单节点故障 | 正常 | 正常 | 正常 | 正常 |
| Redis Cluster 整体故障 | 正常 | 降级/失败 | 失败 | 正常 |
| DB 主库故障 | 正常 | 视缓存策略 | 视实现 | 正常 |
| JWKS 服务故障 | 缓存 Key 正常 | 可受影响 | 可受影响 | 正常 |
| Gateway 节点故障 | 正常 | LB 切换 | LB 切换 | LB 切换 |

对于安全敏感接口：

```text
Introspection 不可用
```

建议：

```text
Fail Closed
```

即拒绝操作。

普通只读接口则可以：

```text
有效 JWT + 本地策略缓存
```

继续服务。

---

# 33. Redis 高可用

可选：

```text
Redis Cluster
```

或者：

```text
Redis Sentinel + 主从
```

关键数据需要：

```text
Multi-AZ
```

并根据 Redis 数据的重要程度配置：

```text
AOF
```

需要特别注意：

认证中心不能完全依赖：

```text
Redis 单实例
```

否则：

```text
Redis = 全系统登录单点
```

---

# 34. 数据库高可用

推荐：

```text
Primary + Standby
Multi-AZ
自动故障切换
```

核心 Client/Policy 配置建议同时具有：

```text
Local Cache
```

认证中心实例定期加载。

这样数据库短期不可用时：

```text
已有 Client 登录配置
Resource 配置
Scope 配置
```

仍可继续使用缓存。

但是：

```text
新增 Client
修改 Client
```

暂停。

---

# 35. 灾备建议

根据实际业务等级，可设计：

```text
同城双 AZ
+
异地灾备
```

建议目标：

```text
RPO ≤ 5 min
RTO ≤ 30 min
```

核心 Client 配置和用户映射：

```text
数据库复制
```

Signing Key：

```text
KMS/HSM 异地备份/托管复制
```

不能出现：

> 数据库恢复了，但是签发 JWT 的 Key 没恢复。

---

# 36. 存量系统迁移原则

不要采用：

```text
某天凌晨统一切换
```

建议：

```text
双轨 → 灰度 → 收口
```

分 4 个阶段。

---

# 37. 阶段一：认证中心建设

先不修改原业务行为。

建设：

```text
OIDC
OAuth Token
JWKS
Client Registry
Token Exchange
Audit
Redis
DB
KMS
SDK
```

门户和测试系统先接入。

---

# 38. 阶段二：门户接入

由于当前门户已有自己的登录能力，不建议第一天直接废除。

采用：

```text
Legacy Login
+
IAM Login
```

双模式。

目标架构最终变成：

```text
Portal
   ↓ OIDC
Auth Center
```

过渡阶段则加入：

```text
Legacy Login Bridge
```

---

# 39. 门户旧登录态平滑迁移

用户已经存在：

```text
PORTAL_LEGACY_SESSION
```

时，不要求重新输入密码。

流程：

```text
用户访问 Portal
       │
       │ Legacy Session 有效
       ▼
Portal Backend
       │
       │ 创建一次性 Migration Ticket
       ▼
Browser
       │
       │ Top-Level Redirect
       ▼
Auth Center /migration/login
       │
       │ Server 校验 Migration Ticket
       │ 查统一用户映射
       │ 建立 Auth Center SSO Session
       ▼
302 Portal
```

注意：

**这里必须使用一次性 Migration Ticket，而不是把旧 Session 或 JWT 暴露给认证中心 URL。**

Ticket：

```text
单次使用
TTL 30～60 秒
绑定：
client_id
user
browser/session
nonce
```

迁移成功以后：

```text
用户无感获得 IAM SSO Session
```

---

# 40. 业务系统旧登录态迁移

每个业务系统也可以使用相同策略。

例如用户访问 System1：

```text
SYSTEM1_LEGACY_SESSION
```

仍然有效。

System1：

```text
验证旧 Session
  ↓
申请 Migration Ticket
  ↓
Redirect IAM
  ↓
建立 IAM Session
  ↓
OIDC 回 System1
```

整个过程用户不重新输入密码。

建议 Migration Bridge 只保留：

```text
1～3 个月
```

迁移完成后永久关闭。

---

# 41. 不建议共享原密码

不要：

```text
System1 把用户密码 POST 给认证中心
```

也不要：

```text
认证中心读取每个系统 Session 表
```

更不要：

```text
把原系统 Session Cookie Domain 修改成所有系统共享
```

迁移应通过：

```text
受信系统
→ 短期签名凭证
→ IAM
```

完成。

---

# 42. 用户 ID 迁移

上线前必须解决统一用户主键问题。

例如：

```text
Portal      zhangsan
System1     88726
System2     ZHANGSAN01
SystemN     10023891
```

全部映射：

```text
IAM sub = u_100086
```

建议迁移前生成：

```text
user_identity_mapping
```

并进行：

```text
自动匹配
+
人工确认冲突账号
```

不能运行时单纯按：

```text
姓名
```

匹配。

---

# 43. 灰度策略

建议按：

```text
用户
部门
租户
系统
流量百分比
```

灰度。

例如：

```text
Phase 1：
IT 用户 5%

Phase 2：
内部员工 20%

Phase 3：
System1 50%

Phase 4：
100%
```

配置：

```yaml
iam:
  enabled: true

  rollout:
    percentage: 20

    includeUsers:
      - test001
      - test002

    includeDepartments:
      - IT
```

---

# 44. 双认证链路

迁移期间：

```text
if IAM enabled:
    使用 OIDC
else:
    使用 Legacy Login
```

同时业务应用应建立统一的：

```text
CurrentUser
```

抽象。

例如：

```java
CurrentUser {
    subjectId;
    username;
    tenantId;
    roles;
}
```

上层业务代码不知道：

```text
用户来自 Legacy Session
还是 OIDC
```

降低迁移风险。

---

# 45. 回滚方案

每个业务系统保留：

```text
iam.enabled
```

开关。

发生问题：

```text
关闭 IAM
↓
恢复 Legacy Authentication Filter
↓
原 Session 继续使用
```

数据库不立即删除：

```text
legacy_user
legacy_session
legacy_permission
```

建议 IAM 全量稳定：

```text
至少 1～2 个发布周期
```

之后再下线旧认证链路。

---

# 46. 网关设计

API Gateway 主要负责：

```text
TLS
WAF
CORS
Rate Limit
JWT 第一层校验
Request ID
审计
路由
```

但业务系统仍应自行检查：

```text
aud
scope
resource permission
```

不能认为：

```text
网关校验过 JWT
=
所有接口天然授权
```

推荐：

```text
Gateway：认证

Business Service：
业务授权
```

即 Authentication 和 Authorization 分层。

---

# 47. 权限模型

不要把所有权限全部塞入 JWT。

建议 JWT 只包含较稳定信息：

```text
sub
tenant
org
role
scope
```

复杂的数据权限：

```text
部门范围
项目范围
区域范围
行级权限
```

由业务系统自己的授权服务判断。

否则权限改变后：

```text
旧 JWT 在有效期内仍携带旧权限
```

而且 Token 会越来越大。

---

# 48. Token 泄漏防护

统一要求：

```text
HTTPS only

Access Token 不进 URL

Access Token 不写日志

Refresh Token 不提供给普通 JS

Cookie HttpOnly

PKCE=S256

redirect URI 精确匹配

禁止 open redirect

Client Secret 不放前端
```

RFC 9700 同样明确强化了重定向安全并要求避免不安全的开放重定向等实现。

高风险系统可进一步考虑：

```text
mTLS
```

或者 sender-constrained Token，例如 DPoP。

---

# 49. 日志与链路追踪

建议每次请求产生：

```text
trace_id
```

Token Exchange 产生：

```text
original_sub
calling_client
target_resource
scope
jti
```

最终审计能还原：

```text
2026-09-08 15:30

User: u_100086
Portal Login
  ↓
System1
  ↓
Token Exchange
  ↓
SystemN /contract/123
  ↓
contract.read
```

对于安全审计非常重要。

---

# 50. 推荐 SDK

为了降低 N+1 接入成本，建设统一：

```text
iam-spring-boot-starter
iam-dotnet-sdk
iam-node-sdk
iam-web-sdk
```

例如 Java：

```yaml
iam:
  issuer: https://auth.example.com

  resource-server:
    audience: system-n-api

  jwks:
    cache-ttl: 1h

  token:
    clock-skew: 30s
```

业务代码：

```java
@RequireScope("order.read")
@GetMapping("/orders/{id}")
public Order getOrder(...) {
}
```

SDK 内部完成：

```text
JWT 验签
Issuer 检查
Audience 检查
Expiration 检查
Scope 解析
UserContext 构造
```

新增系统因此基本不需要自行实现认证协议。

---

# 51. 推荐最终核心时序

## 场景一：Portal 登录

```text
Browser       Portal       Auth Center
   │             │              │
   │ GET /       │              │
   ├────────────>│              │
   │             │ /authorize   │
   │<────────────┤              │
   ├───────────────────────────>│
   │             │              │ Authenticate
   │<───────────────────────────┤ code
   ├────────────>│ callback     │
   │             ├─────────────>│ /token
   │             │<─────────────┤ ID/Access Token
   │             │ create local session
   │<────────────┤
```

---

## 场景二：Portal → System1 SSO

```text
Browser       System1       Auth Center
   │             │              │
   │ GET /       │              │
   ├────────────>│              │
   │             │ no session   │
   │<────────────┤ redirect     │
   ├───────────────────────────>│
   │             │              │ SSO cookie exists
   │<───────────────────────────┤ code
   ├────────────>│              │
   │             ├─────────────>│ exchange
   │             │<─────────────┤ token
   │             │ create session
   │<────────────┤
```

用户不会再次看到登录页面。

---

## 场景三：System1 → SystemN

```text
User        System1       Auth Center        SystemN
 │             │               │                │
 │ request     │               │                │
 ├────────────>│               │                │
 │             │ Token Exchange│                │
 │             ├──────────────>│                │
 │             │               │ validate       │
 │             │<──────────────┤ Token B        │
 │             │                                │
 │             ├───────────────────────────────>│
 │             │ Authorization: Bearer Token B  │
 │             │                                │ verify JWKS
 │             │<───────────────────────────────┤
 │<────────────┤
```

---

## 场景四：Portal iframe SystemN

```text
Browser       Portal       Auth Center       SystemN
   │             │              │               │
   │ open page   │              │               │
   ├────────────>│              │               │
   │             │ embed code   │               │
   │             ├─────────────>│               │
   │             │<─────────────┤ EC_xxx        │
   │<────────────┤ iframe URL                   │
   │                                            │
   ├───────────────────────────────────────────>│
   │                         code=EC_xxx        │
   │                                            │
   │                         SystemN ───────────> Auth
   │                         redeem EC_xxx
   │
   │<───────────────────────────────────────────┤
   │             authenticated iframe           │
```

---

# 52. 最终推荐架构结论

整套体系可以概括为：

```text
                 一个认证中心
                      │
          ┌───────────┼────────────┐
          │           │            │
        Portal      System1      SystemN
          │           │            │
          └───────────┼────────────┘
                      │
                  Unified IAM
```

**认证：**

```text
OIDC
Authorization Code + PKCE
```

**Token：**

```text
JWT
短生命周期
非对称签名
JWKS 本地校验
```

**业务系统之间：**

```text
不要直接互签 Token

统一信任 IAM Issuer

System1 → SystemN
使用 Token Exchange + Audience
```

**iframe：**

```text
同站点：
各系统独立 Session Cookie

跨站点：
Embed Code / postMessage / 内存 Token

SameSite=None Cookie：
仅作为兼容方案，不作为核心依赖
```

**微前端：**

```text
统一 Auth SDK
Host 提供 UserContext / Token Fetch
子应用不持有 Refresh Token
```

**新系统：**

```text
Client Registry
Resource Registry
Scope Registry
Policy Registry

全部配置化
```

**高可用：**

```text
Auth Center 无状态集群
Redis Multi-AZ
DB HA
KMS/HSM
JWKS 本地缓存
JWT 离线验证
```

**迁移：**

```text
Legacy Login
  ↓
Migration Ticket
  ↓
IAM Session
  ↓
OIDC

双轨运行
→ 用户灰度
→ 系统灰度
→ 全量
→ 关闭 Legacy
```

最终信任模型不是：

```text
门户相信 System1
System1 相信 SystemN
SystemN 相信 System2
```

而应该统一成：

```text
Portal
System1
System2
...
SystemN
SystemN+1
     │
     └────── 全部信任 ──────> IAM Issuer
```

这样才能同时解决 **SSO、Token 互认、iframe 身份一致、跨域、新系统接入以及高可用** 六个核心问题，并避免业务系统数量增长后认证关系失控。
