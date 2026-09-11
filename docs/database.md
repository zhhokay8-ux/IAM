# Database

Oracle 21 XE (JDBC `jdbc:oracle:thin:@//host:1521/XEPDB1`). Flyway `iam-authorization-server/src/main/resources/db/migration` uses `RAW(16)`, `VARCHAR2`, `NUMBER(1)`, `TIMESTAMP(6)`.

- `iam_client`, `iam_client_redirect_uri`
- `iam_resource_server`, `iam_scope`, `iam_client_resource_permission`
- `iam_user`, `iam_user_identity_mapping`
- `iam_refresh_token`, `iam_signing_key`
- `iam_embed_policy`
- `iam_audit_log` (+ `detail` in V15)

No new tables in Phase 17. Redis keys (not SQL): `session:`, `auth:code:`, `oauth:state:`, `pkce:state:`, `oidc:nonce:`, `embed:code:`, `migration:ticket:`, `refresh:status:`, `revoked:jti:`, `rate:limit:`.
