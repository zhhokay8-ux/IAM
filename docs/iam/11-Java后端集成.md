# 11 Java 后端集成

证据：`iam-sdk-spring-boot`、`IamAutoConfiguration`、`IamJwtAuthenticationFilter`、`JwtTokenValidator`、`SdkStarterE2ETest`。

## Maven

```xml
<dependency>
  <groupId>com.example.iam</groupId>
  <artifactId>iam-sdk-spring-boot</artifactId>
  <version>0.1.0-SNAPSHOT</version>
</dependency>
```

Starter 名：`iam-spring-boot-starter`。自动配置文件：`META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`。

## application.yml

```yaml
iam:
  issuer: https://auth.example.com
  resource-server:
    enabled: true
    audience: system-order-api
    permit-all:
      - /public/**
  jwks:
    cache-ttl: 1h
    refresh: 10m
  token:
    clock-skew: 30s
```

不需要手写 SecurityConfig 才能验 JWT：Filter 已注册。Spring Security Resource Server 自动配置被 `IamSecurityAutoConfigurationExcluder` 排除，避免双 401。

## Controller

```java
@RestController
public class OrderController {
    @RequireScope("order.read")
    @GetMapping("/orders/{id}")
    public String get(@PathVariable String id) {
        IamUserContext ctx = IamUserContextHolder.require();
        return ctx.getSubject();
    }
}
```

`@RequireRole("admin")` 同样走 Aspect。缺 scope → `INSUFFICIENT_SCOPE`（403），缺 role → `INSUFFICIENT_ROLE`。

## JWT 在哪里验？

`IamJwtAuthenticationFilter` 读 `Authorization: Bearer`，调用 `JwtTokenValidator.validate`：

1. 解析 JWS，算法必须 RS256。
2. `kid` 必填，`IamJwksClient.resolvePublicKey(kid)`（内存 `JwksCache`，过期再拉；拉失败且允许 stale 则用旧集）。
3. 验签、`iss`、`aud` 包含配置的 audience、nbf/exp ± clockSkew、jti（SDK 默认跳过吊销存储）。

普通 API **不会**同步调用 IAM introspect。

## UserContext

`IamUserContext`：subject、username(**null**)、tenantId、orgId、roles、scopes、clientId。来自 Access Token claims，不是 UserInfo。

## Token Exchange / CC 客户端

`IamTokenClient.clientCredentials(clientId, secret, scope)` 只封装 CC。Token Exchange 需自写 form POST，见 [15](15-Token-Exchange.md)。
