# 统一认证中心 IAM 使用与集成说明书

本目录根据**当前代码仓库逆向**写成。读者不需要先读架构设计稿；以源码为准。

状态标记：

- **【已实现】**：有可调用的类 / API / 表 / Redis Key。
- **【部分实现】**：有核心逻辑，但缺 HTTP、缺生产依赖或行为不完整。
- **【设计存在但代码未实现】**：Discovery 或设计里出现，但仓库里没有对应 Controller / 模块。

## 这个项目是什么

Maven 多模块（`com.example.iam:iam-parent:0.1.0-SNAPSHOT`），核心进程是 **`iam-authorization-server`**：OIDC Discovery、Authorization Code + PKCE、Token、Introspect、Revoke、SSO Cookie、Token Exchange、iframe Embed Code、Logout、Legacy 迁移 Ticket。业务系统用 **`iam-sdk-spring-boot`（artifact 名 iam-spring-boot-starter）** 本地验 JWT。

编译：Java 17（`pom.xml` `java.version`）。运行与 Docker 镜像：Temurin 21 JRE。Spring Boot **3.5.5**。JWT **RS256**（`SigningKeyServiceImpl.ALGORITHM`、`iam.jwt.algorithm`）。

## 系统架构（当前代码）

```
Browser
  → Portal 前端（本仓库无 Portal 应用）
      → IAM GET /oauth2/authorize  （需要 Cookie IAM_SSO_SESSION）
      → IAM POST /sso/login        （建立 SSO Session）
      → Portal BFF POST /oauth2/token
  → 业务系统前端
      → 业务后端 Bearer JWT
          → JwtTokenValidator（JWKS 缓存）本地验签
          → 需要用户身份跨系统时：业务后端 POST /oauth2/token (token-exchange)

Portal（已登录）
  → POST /api/embed/code
  → iframe 子应用
  → 子应用后端 POST /api/embed/exchange
```

| 角色 | 职责（代码实际） |
|---|---|
| IAM | 认证、发 Token、SSO Session、授权码、权限绑定校验、审计 |
| Portal | **本仓库不包含**；应作为 BFF 换 Token、持有自己的业务 Session |
| 业务系统 | 用 SDK 验 JWT、按 audience/scope/role 鉴权、业务数据权限自己做 |
| Gateway（`iam-gateway`） | 【部分实现】JWT 初验、CORS、进程内限流、审计日志；**无反向代理路由表** |
| Redis | Session / code / state / nonce / embed / migration ticket / refresh status / revoked jti |
| Oracle | Client、用户、权限、Refresh Token **哈希**、签名密钥 **元数据**、审计 |
| KMS/HSM | 【部分实现】表字段 `kms_key_id`；实现类是进程内 `LocalSigningKeySecretStore` |
| SDK | 拉 JWKS、验 JWT、注入 `IamUserContext`、`@RequireScope` / `@RequireRole` |
| 前端 SDK | 【部分实现】仅静态脚本 `/iam-embed.js`；无独立 npm 包 |

Authentication（登录、SSO Cookie）与 Token Issuing（`/oauth2/token`）在 IAM。Token Validation 与 Business Authorization（订单能不能看这条数据）在业务系统。IAM 的 Authorization 是 Client×Resource×Scope×Grant。

## 5 分钟快速启动

见 [04-快速启动.md](04-快速启动.md)。最短路径：设 `ORACLE_PASSWORD` / `REDIS_PASSWORD` / `DB_PASSWORD`，启动 Oracle+Redis，Flyway 随应用启动，然后 `GET /.well-known/openid-configuration`。

**本仓库没有** `/health`、`/actuator`、`/swagger-ui`（授权服务器 `application.yml` 未开启 Actuator）。

## 文档地图

| 你想做什么 | 读 |
|---|---|
| 目录与模块 | [02](02-项目目录结构.md) [03](03-模块说明.md) [01](01-项目概览.md) |
| 配置 / 库 / Redis | [05](05-环境配置.md) [06](06-数据库.md) [07](07-Redis.md) |
| 创建 Client | [08-Client注册.md](08-Client注册.md) |
| Portal / 业务系统 / Java / 前端 | [09](09-Portal集成.md) [10](10-业务系统集成.md) [11](11-Java后端集成.md) [12](12-前端集成.md) |
| SSO / Token / Exchange / CC | [13](13-SSO.md) [14](14-Token.md) [15](15-Token-Exchange.md) [16](16-Client-Credentials.md) |
| iframe / Logout / 权限 / 安全 | [17](17-iframe集成.md) [18](18-Logout.md) [19](19-权限模型.md) [20](20-Security.md) |
| API / 错误码 / 审计 / FAQ | [21](21-API参考.md) [22](22-错误码.md) [23](23-日志审计.md) [24](24-问题排查.md) |
| 部署 / HA / 迁移 / Demo | [25](25-生产部署.md) [26](26-HA与灾备.md) [27](27-Legacy迁移.md) [28](28-完整Demo.md) |
| 接入清单 / 已知问题 | [29](29-新系统接入Checklist.md) [99](99-已发现问题.md) |

## 必须先知道的限制

1. **Client / Resource / Scope / Embed Policy 没有 REST Admin API**（`iam-admin` 只有 `package-info`）。创建方式见 [08](08-Client注册.md)。
2. **`POST /sso/login` 不校验密码**，只按 `username` + `tenant_id` 找用户（`SsoAuthenticationService`）。
3. Discovery 声明了 `/oidc/userinfo`，**没有对应 Controller**。
4. 签名私钥在 **JVM 内存**（`LocalSigningKeySecretStore`），多节点不能直接水平扩展签发。
5. 无独立 Vue/React SDK。【当前项目不支持】把 Refresh Token 放到浏览器。
