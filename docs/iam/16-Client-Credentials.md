# 16 Client Credentials

**【已实现】** `ClientCredentialsGrantHandler`、`ClientCredentialsIntegrationTest`。  
场景：定时任务、消息消费、无用户。Token `sub` 是 **service principal（client_id）**，不是伪造的用户 UUID。证据：`servicePrincipalIsNotAUserSubject` 测试。

调用方 Client 必须是 confidential，且有目标 resource/scope 的 `CLIENT_CREDENTIALS` permission。Public client 拒绝。

```bash
curl -s -X POST http://localhost:8080/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u system-1:super-secret \
  -d "grant_type=client_credentials" \
  -d "scope=order.read" \
  -d "audience=system-n-api"
```

Java SDK：

```java
String json = new IamTokenClient("http://localhost:8080")
    .clientCredentials("system-1", "super-secret", "order.read");
```

`IamTokenClient` 返回 raw JSON 字符串。也可用 `RestClient` / `WebClient` form POST。然后 `Authorization: Bearer` 调 SystemN。
