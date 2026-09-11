# 08 Client 注册

**【部分实现】** 领域服务完整（`IamClientService` 等），**没有** `/api/clients` HTTP。动态注册 `dynamicRegister` 直接 `rejectDynamicRegistration`（`DYNAMIC_REGISTRATION_FORBIDDEN`）。

创建方式：

1. 写一次性 Spring `ApplicationRunner` 调 Service（与集成测试相同）。
2. 或直接插表（不推荐，secret 必须是 SHA-256 hex）。

用户可以用 HTTP：`POST /api/users`（需 `X-IAM-Admin-Token`）。

## 假设接入 system-order

建议约定（与测试命名一致）：

| 项 | 建议值 |
|---|---|
| resource_code | `SYSTEM_ORDER` |
| audience | `system-order-api` |
| client_id | `system-order` |
| client_secret | 仅 confidential，随机长串，只在创建时给你一次 |
| redirect LOGIN | `https://order.example.com/login/callback` |
| redirect LOGOUT | `https://order.example.com/oidc/backchannel-logout` |
| scope | `openid`、`order.read` |
| grant | `AUTHORIZATION_CODE`、按需 `TOKEN_EXCHANGE` / `CLIENT_CREDENTIALS` |
| pkceRequired | `true`（Service 默认 true） |
| accessTokenTtl | 秒，例如 600 |
| refreshTokenTtl | 秒，例如 2592000 |

`CreatePermissionRequest.grantType` 存库为枚举名：`AUTHORIZATION_CODE`、`CLIENT_CREDENTIALS`、`TOKEN_EXCHANGE`。

## Java 示例（测试同款 API）

```java
resourceService.create(new CreateResourceRequest(
        "SYSTEM_ORDER", "Order", "system-order-api", "ACTIVE", "platform"));
scopeService.create(new CreateScopeRequest(
        "SYSTEM_ORDER", "order.read", "Read orders", null, "ACTIVE"));
clientService.create(new CreateClientRequest(
        "system-order",
        "Order System",
        "CONFIDENTIAL",
        "ACTIVE",
        "client_secret_basic",
        600,
        2592000,
        true,
        "platform",
        List.of(
            new RedirectUriInput("https://order.example.com/login/callback", "LOGIN_CALLBACK"),
            new RedirectUriInput("https://order.example.com/oidc/backchannel-logout", "LOGOUT_CALLBACK")),
        "super-secret"));
permissionService.create(new CreatePermissionRequest(
        "system-order", "SYSTEM_ORDER", "order.read", "AUTHORIZATION_CODE", "ACTIVE"));
```

字段名是 Java record 访问器（Jackson 默认 **camelCase**：`clientId` 不是 `client_id`），因为本来就没有对外 JSON Admin。

`client_secret_basic`：Token 请求用 HTTP Basic 或 form `client_id`/`client_secret`（`TokenAuthenticationService` / `ClientAuthenticationProvider`）。

## 创建用户（【已实现】HTTP）

`iam.admin.access-token` 非空：

```bash
curl -s -X POST http://localhost:8080/api/users \
  -H "Content-Type: application/json" \
  -H "X-IAM-Admin-Token: change-me-admin" \
  -d "{\"username\":\"alice\",\"displayName\":\"Alice\",\"email\":\"a@example.com\",\"tenantId\":\"tenant-1\",\"orgId\":\"org-1\",\"status\":\"ACTIVE\"}"
```

身份映射：`POST /api/users/{subjectId}/identity-mappings`，body camelCase：`systemCode`、`externalUserId`、`externalUsername`、`mappingStatus`。

## Embed Policy

无 API。SQL 或 `IamEmbedPolicyRepository.save`，`parent_origin` 必须与请求 Origin 精确一致，`allowed_path` 可 ` /orders/*` 后缀（`EmbedPolicyServiceImpl`）。
