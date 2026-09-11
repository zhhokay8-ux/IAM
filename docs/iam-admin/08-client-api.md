# Phase 3：Client API

前缀 `/api/admin/clients`。读：`admin.client.read`。写：`admin.client.write`。

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/admin/clients?q=&status=&page=&size=` | 分页搜索 client_id / client_name |
| GET | `/api/admin/clients/{clientId}` | 详情（无 secret） |
| POST | `/api/admin/clients` | 创建；默认 INACTIVE；返回一次性 `client_secret` |
| PUT | `/api/admin/clients/{clientId}` | 改名称/TTL/PKCE/owner/URI；**不改 status** |
| POST | `/api/admin/clients/{clientId}/disable` | INACTIVE + `CLIENT_DISABLED` |
| POST | `/api/admin/clients/{clientId}/enable` | ACTIVE + `CLIENT_ENABLED` |
| POST | `/api/admin/clients/{clientId}/rotate-secret` | 新 secret 只回一次 + `SECRET_ROTATED` |
| PUT | `/api/admin/clients/{clientId}/redirect-uris` | 整表替换 LOGIN_CALLBACK / LOGOUT_CALLBACK |
| GET | `/api/admin/clients/{clientId}/permissions` | 查看 `iam_cli_res_perm` |

成功体为现有 DTO（或 `RotatedSecretResponse`）。错误仍为 `ApiErrorResponse`。Cookie 写操作需 CSRF；集成测试使用 Bearer。
