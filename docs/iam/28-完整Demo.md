# 28 完整 Demo（order-system 示例代码）

本仓库**没有**独立 order-system 工程。以下示例与当前 SDK/API 对齐，可复制到新 Maven 项目。Client 数据需用 [08](08-Client注册.md) 的 Service 写入 IAM。

## 目录

```
order-system/
├── frontend/index.html
└── backend/（Spring Boot + iam-sdk-spring-boot）
```

### backend application.yml

```yaml
iam:
  issuer: http://localhost:8080
  resource-server:
    audience: system-order-api
    permit-all: /public/**
```

### backend OrderController

```java
package com.example.order;

import com.example.iam.sdk.IamUserContextHolder;
import com.example.iam.sdk.RequireScope;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OrderController {
    @RequireScope("order.read")
    @GetMapping("/orders/{id}")
    public OrderDto get(@PathVariable String id) {
        var ctx = IamUserContextHolder.require();
        return new OrderDto(id, ctx.getSubject(), ctx.getTenantId());
    }

    public record OrderDto(String id, String subject, String tenantId) {}
}
```

无需自定义 SecurityConfig。登录/Callback 应在 **Portal 或 order BFF**，不要在这个 Resource Server 里放 client_secret。

### Token Exchange（order 调另一系统）

见 [15](15-Token-Exchange.md) 的 RestClient form。CC 批处理见 [16](16-Client-Credentials.md)。

### frontend（BFF 模式示意）

```html
<button onclick="location.href='/bff/login'">Login</button>
<script>
async function loadOrder() {
  const r = await fetch("/bff/orders/1", { credentials: "include" });
  if (r.status === 401) location.href = "/bff/login";
  if (r.status === 403) alert("no scope");
}
</script>
```

BFF `/bff/login` 实现 [09](09-Portal集成.md) 的 authorize 跳转；`/bff/orders/1` 用服务器端 Access Token 调 order-system。

Logout：`POST http://localhost:8080/oidc/logout?logout_type=global` + CSRF。
