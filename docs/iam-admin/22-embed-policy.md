# Phase 8：Embed Policy

Admin 委托现有 `EmbedPolicyService`（`requireActive` + CRUD）。表仍是 `iam_embed_policy`（parent/child 为 **client PK**）。Origin 必须经 `OriginValidator` → `IamOriginValidator`，禁止 `*`。Path 禁止裸 `*` / `/*`；仅允许精确路径或现有 Runtime 的前缀 `/foo/*`。

创建默认 **INACTIVE**。启停改 status，不物理删除。PUT 只改 origin/path。

| 方法 | 路径 | 权限 |
|---|---|---|
| GET | `/api/admin/embed-policies` | `admin.embed.read` |
| GET | `/api/admin/embed-policies/{id}` | `admin.embed.read` |
| POST | `/api/admin/embed-policies` | `admin.embed.write` |
| PUT | `/api/admin/embed-policies/{id}` | `admin.embed.write` |
| POST | `.../enable` `.../disable` | `admin.embed.write` |

## 反向验证（Disable 必须同时成立）

| 环节 | 证据 |
|---|---|
| Admin API | create → enable → disable 200 |
| DB | `iam_embed_policy.status=INACTIVE` |
| Runtime | `EmbedPolicyService.requireActive` → `EMBED_POLICY_DISABLED` |
| 协议 | `POST /api/embed/code` → `IAM-406x EMBED_POLICY_DISABLED` |
| Audit | `EMBED_POLICY_CHANGED` |

Wildcard origin 创建必须 `IAM-4004 INVALID_ORIGIN`。
