# Phase 8：Signing Key

Admin 只展示 `SigningKeyService` / `SigningKeyRotationService` 的 **KeyMetadata**：kid、algorithm、status、created_at、expires_at（`retiredAt`）、kms_key_id。禁止 private key、secret、KMS credential。无删除接口：仍可能用于验签的 key 保持 `VERIFYING` 直至 `retireExpired(tokenTtl)`。

Rotate 走现有 `SigningKeyRotationService.rotate()`：旧 ACTIVE → VERIFYING（overlap），新 ACTIVE 签发。JWKS（`JwksService`）同时发布 ACTIVE+VERIFYING 公钥。旧 JWT 用原 kid 继续 `JwtSigner.verify`。

**二次确认**：`POST /api/admin/signing-keys/rotate` body 必须 `{"confirm":true}`，否则 `IAM-4000`。权限 `admin.key.rotate`。Audit `SIGNING_KEY_ROTATED`。

| 方法 | 路径 | 权限 |
|---|---|---|
| GET | `/api/admin/signing-keys` | `admin.key.read` |
| GET | `/api/admin/signing-keys/active` | `admin.key.read` |
| GET | `/api/admin/signing-keys/{kid}` | `admin.key.read` |
| POST | `/api/admin/signing-keys/rotate` | `admin.key.rotate` |

## 多节点 / 重启

当前 `LocalSigningKeySecretStore` 把私钥放在 **进程内存**。Rotate 只保证本 JVM + 共享 `iam_signing_key` 元数据。多副本各自 rotate 会分裂 kid；重启丢失内存私钥。生产需共享 KMS，不能假装已经多节点安全。

## 反向验证

| 环节 | 证据 |
|---|---|
| Admin API | confirm rotate 200，body 无私钥 |
| DB | 新行 ACTIVE；旧行 VERIFYING |
| Runtime | `SigningKeyService.getActiveKey` 为新 kid；`JwtSigner.verify(旧JWT)` 成功 |
| 协议 | `GET /.well-known/jwks.json` 含新旧 kid |
| Audit | `SIGNING_KEY_ROTATED` |
