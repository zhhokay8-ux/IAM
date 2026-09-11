-- DEVELOPMENT ONLY. Not Flyway.
-- UUID 全部为 VARCHAR2(36) 明文。不插入 iam-admin / IAM-ADMIN。
--
-- Admin 登录：username=admin  tenant=iam（无密码）
-- Client secret 明文写入 client_secret_hash：
--   portal=dev-portal-secret
--   system-order=dev-order-secret
--   system-batch=dev-batch-secret
--   system-legacy=dev-inactive-secret

-- iam_client
MERGE INTO iam_client t
USING (
    SELECT 'd1000000-0000-0000-0000-000000000001' AS id, 'portal' AS client_id, 'Portal' AS client_name,
           'confidential' AS client_type, 'ACTIVE' AS status, 'client_secret_basic' AS auth_method,
           600 AS access_ttl, 2592000 AS refresh_ttl, 1 AS pkce, 'platform' AS owner,
           'dev-portal-secret' AS client_secret FROM dual
    UNION ALL
    SELECT 'd1000000-0000-0000-0000-000000000002', 'system-order', 'Order System',
           'confidential', 'ACTIVE', 'client_secret_basic', 600, 2592000, 1, 'platform', 'dev-order-secret' FROM dual
    UNION ALL
    SELECT 'd1000000-0000-0000-0000-000000000003', 'system-batch', 'Batch Job Client',
           'confidential', 'ACTIVE', 'client_secret_basic', 600, 86400, 0, 'platform', 'dev-batch-secret' FROM dual
    UNION ALL
    SELECT 'd1000000-0000-0000-0000-000000000004', 'system-legacy', 'Legacy Inactive Client',
           'confidential', 'INACTIVE', 'client_secret_basic', 600, 86400, 1, 'platform', 'dev-inactive-secret' FROM dual
) s
ON (t.client_id = s.client_id)
WHEN MATCHED THEN UPDATE SET
    t.client_name = s.client_name,
    t.client_type = s.client_type,
    t.status = s.status,
    t.token_endpoint_auth_method = s.auth_method,
    t.access_token_ttl = s.access_ttl,
    t.refresh_token_ttl = s.refresh_ttl,
    t.pkce_required = s.pkce,
    t.owner = s.owner,
    t.client_secret_hash = s.client_secret,
    t.updated_at = SYSTIMESTAMP
WHEN NOT MATCHED THEN INSERT (
    id, client_id, client_name, client_type, status, token_endpoint_auth_method,
    access_token_ttl, refresh_token_ttl, pkce_required, owner, created_at, updated_at, client_secret_hash
) VALUES (
    s.id, s.client_id, s.client_name, s.client_type, s.status, s.auth_method,
    s.access_ttl, s.refresh_ttl, s.pkce, s.owner, SYSTIMESTAMP, SYSTIMESTAMP, s.client_secret
);

-- iam_client_redirect_uri
MERGE INTO iam_client_redirect_uri t
USING (
    SELECT 'd1100000-0000-0000-0000-000000000001' AS id,
           (SELECT id FROM iam_client WHERE client_id = 'portal') AS client_pk,
           'https://portal.example.com/login/callback' AS redirect_uri, 'LOGIN_CALLBACK' AS uri_type, 'ACTIVE' AS status FROM dual
    UNION ALL
    SELECT 'd1100000-0000-0000-0000-000000000002',
           (SELECT id FROM iam_client WHERE client_id = 'portal'),
           'https://portal.example.com/oidc/backchannel-logout', 'LOGOUT_CALLBACK', 'ACTIVE' FROM dual
    UNION ALL
    SELECT 'd1100000-0000-0000-0000-000000000003',
           (SELECT id FROM iam_client WHERE client_id = 'system-order'),
           'https://order.example.com/login/callback', 'LOGIN_CALLBACK', 'ACTIVE' FROM dual
    UNION ALL
    SELECT 'd1100000-0000-0000-0000-000000000004',
           (SELECT id FROM iam_client WHERE client_id = 'system-order'),
           'https://order.example.com/oidc/backchannel-logout', 'LOGOUT_CALLBACK', 'ACTIVE' FROM dual
    UNION ALL
    SELECT 'd1100000-0000-0000-0000-000000000005',
           (SELECT id FROM iam_client WHERE client_id = 'system-legacy'),
           'https://legacy.example.com/login/callback', 'LOGIN_CALLBACK', 'ACTIVE' FROM dual
) s
ON (t.client_id = s.client_pk AND t.redirect_uri = s.redirect_uri AND t.uri_type = s.uri_type)
WHEN MATCHED THEN UPDATE SET t.status = s.status
WHEN NOT MATCHED THEN INSERT (id, client_id, redirect_uri, uri_type, status)
VALUES (s.id, s.client_pk, s.redirect_uri, s.uri_type, s.status);

-- iam_resource_server
MERGE INTO iam_resource_server t
USING (
    SELECT 'd2000000-0000-0000-0000-000000000001' AS id, 'PORTAL' AS resource_code, 'Portal API' AS resource_name,
           'portal-api' AS audience, 'ACTIVE' AS status, 'platform' AS owner FROM dual
    UNION ALL
    SELECT 'd2000000-0000-0000-0000-000000000002', 'SYSTEM_ORDER', 'Order API',
           'system-order-api', 'ACTIVE', 'platform' FROM dual
    UNION ALL
    SELECT 'd2000000-0000-0000-0000-000000000003', 'SYSTEM_BATCH', 'Batch API',
           'system-batch-api', 'ACTIVE', 'platform' FROM dual
) s
ON (t.resource_code = s.resource_code)
WHEN MATCHED THEN UPDATE SET
    t.resource_name = s.resource_name, t.audience = s.audience, t.status = s.status, t.owner = s.owner
WHEN NOT MATCHED THEN INSERT (id, resource_code, resource_name, audience, status, owner, created_at)
VALUES (s.id, s.resource_code, s.resource_name, s.audience, s.status, s.owner, SYSTIMESTAMP);

-- iam_scope
MERGE INTO iam_scope t
USING (
    SELECT 'd3000000-0000-0000-0000-000000000001' AS id,
           (SELECT id FROM iam_resource_server WHERE resource_code = 'PORTAL') AS resource_pk,
           'openid' AS scope_code, 'OpenID' AS scope_name, 'OIDC' AS description, 'ACTIVE' AS status FROM dual
    UNION ALL
    SELECT 'd3000000-0000-0000-0000-000000000002',
           (SELECT id FROM iam_resource_server WHERE resource_code = 'PORTAL'),
           'profile', 'Profile', 'OIDC profile', 'ACTIVE' FROM dual
    UNION ALL
    SELECT 'd3000000-0000-0000-0000-000000000003',
           (SELECT id FROM iam_resource_server WHERE resource_code = 'SYSTEM_ORDER'),
           'openid', 'OpenID', 'OIDC', 'ACTIVE' FROM dual
    UNION ALL
    SELECT 'd3000000-0000-0000-0000-000000000004',
           (SELECT id FROM iam_resource_server WHERE resource_code = 'SYSTEM_ORDER'),
           'order.read', 'Read orders', 'Read order APIs', 'ACTIVE' FROM dual
    UNION ALL
    SELECT 'd3000000-0000-0000-0000-000000000005',
           (SELECT id FROM iam_resource_server WHERE resource_code = 'SYSTEM_ORDER'),
           'order.write', 'Write orders', 'Write order APIs', 'ACTIVE' FROM dual
    UNION ALL
    SELECT 'd3000000-0000-0000-0000-000000000006',
           (SELECT id FROM iam_resource_server WHERE resource_code = 'SYSTEM_BATCH'),
           'job.run', 'Run jobs', 'Client credentials batch', 'ACTIVE' FROM dual
) s
ON (t.resource_id = s.resource_pk AND t.scope_code = s.scope_code)
WHEN MATCHED THEN UPDATE SET t.scope_name = s.scope_name, t.description = s.description, t.status = s.status
WHEN NOT MATCHED THEN INSERT (id, resource_id, scope_code, scope_name, description, status)
VALUES (s.id, s.resource_pk, s.scope_code, s.scope_name, s.description, s.status);

-- iam_cli_res_perm
MERGE INTO iam_cli_res_perm t
USING (
    SELECT 'd5000000-0000-0000-0000-000000000001' AS id,
           (SELECT id FROM iam_client WHERE client_id = 'portal') AS client_pk,
           (SELECT id FROM iam_resource_server WHERE resource_code = 'PORTAL') AS resource_pk,
           (SELECT s.id FROM iam_scope s JOIN iam_resource_server r ON r.id = s.resource_id
             WHERE r.resource_code = 'PORTAL' AND s.scope_code = 'openid') AS scope_pk,
           'AUTHORIZATION_CODE' AS grant_type, 'ACTIVE' AS status FROM dual
    UNION ALL
    SELECT 'd5000000-0000-0000-0000-000000000002',
           (SELECT id FROM iam_client WHERE client_id = 'portal'),
           (SELECT id FROM iam_resource_server WHERE resource_code = 'PORTAL'),
           (SELECT s.id FROM iam_scope s JOIN iam_resource_server r ON r.id = s.resource_id
             WHERE r.resource_code = 'PORTAL' AND s.scope_code = 'profile'),
           'AUTHORIZATION_CODE', 'ACTIVE' FROM dual
    UNION ALL
    SELECT 'd5000000-0000-0000-0000-000000000003',
           (SELECT id FROM iam_client WHERE client_id = 'portal'),
           (SELECT id FROM iam_resource_server WHERE resource_code = 'SYSTEM_ORDER'),
           (SELECT s.id FROM iam_scope s JOIN iam_resource_server r ON r.id = s.resource_id
             WHERE r.resource_code = 'SYSTEM_ORDER' AND s.scope_code = 'order.read'),
           'AUTHORIZATION_CODE', 'ACTIVE' FROM dual
    UNION ALL
    SELECT 'd5000000-0000-0000-0000-000000000004',
           (SELECT id FROM iam_client WHERE client_id = 'portal'),
           (SELECT id FROM iam_resource_server WHERE resource_code = 'SYSTEM_ORDER'),
           (SELECT s.id FROM iam_scope s JOIN iam_resource_server r ON r.id = s.resource_id
             WHERE r.resource_code = 'SYSTEM_ORDER' AND s.scope_code = 'order.read'),
           'TOKEN_EXCHANGE', 'ACTIVE' FROM dual
    UNION ALL
    SELECT 'd5000000-0000-0000-0000-000000000005',
           (SELECT id FROM iam_client WHERE client_id = 'system-order'),
           (SELECT id FROM iam_resource_server WHERE resource_code = 'SYSTEM_ORDER'),
           (SELECT s.id FROM iam_scope s JOIN iam_resource_server r ON r.id = s.resource_id
             WHERE r.resource_code = 'SYSTEM_ORDER' AND s.scope_code = 'openid'),
           'AUTHORIZATION_CODE', 'ACTIVE' FROM dual
    UNION ALL
    SELECT 'd5000000-0000-0000-0000-000000000006',
           (SELECT id FROM iam_client WHERE client_id = 'system-order'),
           (SELECT id FROM iam_resource_server WHERE resource_code = 'SYSTEM_ORDER'),
           (SELECT s.id FROM iam_scope s JOIN iam_resource_server r ON r.id = s.resource_id
             WHERE r.resource_code = 'SYSTEM_ORDER' AND s.scope_code = 'order.read'),
           'AUTHORIZATION_CODE', 'ACTIVE' FROM dual
    UNION ALL
    SELECT 'd5000000-0000-0000-0000-000000000007',
           (SELECT id FROM iam_client WHERE client_id = 'system-batch'),
           (SELECT id FROM iam_resource_server WHERE resource_code = 'SYSTEM_BATCH'),
           (SELECT s.id FROM iam_scope s JOIN iam_resource_server r ON r.id = s.resource_id
             WHERE r.resource_code = 'SYSTEM_BATCH' AND s.scope_code = 'job.run'),
           'CLIENT_CREDENTIALS', 'ACTIVE' FROM dual
) s
ON (t.client_id = s.client_pk AND t.resource_id = s.resource_pk AND t.scope_id = s.scope_pk AND t.grant_type = s.grant_type)
WHEN MATCHED THEN UPDATE SET t.status = s.status
WHEN NOT MATCHED THEN INSERT (id, client_id, resource_id, scope_id, grant_type, status, created_at)
VALUES (s.id, s.client_pk, s.resource_pk, s.scope_pk, s.grant_type, s.status, SYSTIMESTAMP);

-- iam_user（id 与 subject_id 使用同一明文 UUID）
MERGE INTO iam_user t
USING (
    SELECT 'e1000000-0000-0000-0000-000000000001' AS id, 'admin' AS username, 'IAM Admin' AS display_name,
           'ACTIVE' AS status, 'iam' AS tenant_id, 'hq' AS org_id, 'admin@example.com' AS email FROM dual
    UNION ALL
    SELECT 'e1000000-0000-0000-0000-000000000002', 'secadmin', 'Security Admin',
           'ACTIVE', 'iam', 'hq', 'secadmin@example.com' FROM dual
    UNION ALL
    SELECT 'e1000000-0000-0000-0000-000000000003', 'operator', 'Operator',
           'ACTIVE', 'iam', 'ops', 'operator@example.com' FROM dual
    UNION ALL
    SELECT 'e1000000-0000-0000-0000-000000000004', 'auditor', 'Auditor',
           'ACTIVE', 'iam', 'audit', 'auditor@example.com' FROM dual
    UNION ALL
    SELECT 'e1000000-0000-0000-0000-000000000005', 'alice', 'Alice',
           'ACTIVE', 'iam', 'org-1', 'alice@example.com' FROM dual
    UNION ALL
    SELECT 'e1000000-0000-0000-0000-000000000006', 'disabled', 'Disabled User',
           'INACTIVE', 'iam', 'org-1', 'disabled@example.com' FROM dual
) s
ON (t.tenant_id = s.tenant_id AND t.username = s.username)
WHEN MATCHED THEN UPDATE SET
    t.display_name = s.display_name, t.status = s.status, t.org_id = s.org_id, t.email = s.email, t.updated_at = SYSTIMESTAMP
WHEN NOT MATCHED THEN INSERT (
    id, subject_id, username, display_name, status, tenant_id, org_id, created_at, updated_at, email
) VALUES (
    s.id, s.id, s.username, s.display_name, s.status, s.tenant_id, s.org_id, SYSTIMESTAMP, SYSTIMESTAMP, s.email
);

-- iam_user_identity_mapping（FK subject_id -> iam_user.subject_id）
MERGE INTO iam_user_identity_mapping t
USING (
    SELECT 'e2000000-0000-0000-0000-000000000001' AS id,
           (SELECT subject_id FROM iam_user WHERE tenant_id = 'iam' AND username = 'alice') AS subject_pk,
           'HIS' AS system_code, 'his-alice' AS external_user_id, 'alice.his' AS external_username, 'ACTIVE' AS mapping_status FROM dual
    UNION ALL
    SELECT 'e2000000-0000-0000-0000-000000000002',
           (SELECT subject_id FROM iam_user WHERE tenant_id = 'iam' AND username = 'admin'),
           'HIS', 'his-admin', 'admin.his', 'ACTIVE' FROM dual
) s
ON (t.system_code = s.system_code AND t.external_user_id = s.external_user_id)
WHEN MATCHED THEN UPDATE SET
    t.subject_id = s.subject_pk, t.external_username = s.external_username, t.mapping_status = s.mapping_status
WHEN NOT MATCHED THEN INSERT (id, subject_id, system_code, external_user_id, external_username, mapping_status, created_at)
VALUES (s.id, s.subject_pk, s.system_code, s.external_user_id, s.external_username, s.mapping_status, SYSTIMESTAMP);

-- iam_admin_user_role（角色来自 V16，按 role_code 关联）
MERGE INTO iam_admin_user_role t
USING (
    SELECT 'e2100000-0000-0000-0000-000000000001' AS id,
           (SELECT subject_id FROM iam_user WHERE tenant_id = 'iam' AND username = 'admin') AS subject_pk,
           (SELECT id FROM iam_admin_role WHERE role_code = 'IAM_ADMIN') AS role_pk FROM dual
    UNION ALL
    SELECT 'e2100000-0000-0000-0000-000000000002',
           (SELECT subject_id FROM iam_user WHERE tenant_id = 'iam' AND username = 'secadmin'),
           (SELECT id FROM iam_admin_role WHERE role_code = 'IAM_SECURITY_ADMIN') FROM dual
    UNION ALL
    SELECT 'e2100000-0000-0000-0000-000000000003',
           (SELECT subject_id FROM iam_user WHERE tenant_id = 'iam' AND username = 'operator'),
           (SELECT id FROM iam_admin_role WHERE role_code = 'IAM_OPERATOR') FROM dual
    UNION ALL
    SELECT 'e2100000-0000-0000-0000-000000000004',
           (SELECT subject_id FROM iam_user WHERE tenant_id = 'iam' AND username = 'auditor'),
           (SELECT id FROM iam_admin_role WHERE role_code = 'IAM_AUDITOR') FROM dual
) s
ON (t.subject_id = s.subject_pk AND t.role_id = s.role_pk)
WHEN NOT MATCHED THEN INSERT (id, subject_id, role_id, created_at)
VALUES (s.id, s.subject_pk, s.role_pk, SYSTIMESTAMP);

-- iam_refresh_token（FK subject_id -> iam_user.id）
MERGE INTO iam_refresh_token t
USING (
    SELECT 'e3000000-0000-0000-0000-000000000001' AS id,
           'dev-refresh-alice' AS token_hash,
           (SELECT id FROM iam_user WHERE tenant_id = 'iam' AND username = 'alice') AS user_pk,
           (SELECT id FROM iam_client WHERE client_id = 'portal') AS client_pk,
           'e3100000-0000-0000-0000-000000000001' AS session_id,
           'ACTIVE' AS status, 'openid order.read' AS scope, 'portal-api system-order-api' AS audience FROM dual
    UNION ALL
    SELECT 'e3000000-0000-0000-0000-000000000002',
           'dev-refresh-admin-revoked',
           (SELECT id FROM iam_user WHERE tenant_id = 'iam' AND username = 'admin'),
           (SELECT id FROM iam_client WHERE client_id = 'portal'),
           'e3100000-0000-0000-0000-000000000002',
           'REVOKED', 'openid', 'portal-api' FROM dual
) s
ON (t.token_hash = s.token_hash)
WHEN MATCHED THEN UPDATE SET t.status = s.status, t.scope = s.scope, t.audience = s.audience
WHEN NOT MATCHED THEN INSERT (
    id, token_hash, subject_id, client_id, session_id, issued_at, expires_at, revoked_at,
    rotation_parent_id, status, scope, audience
) VALUES (
    s.id, s.token_hash, s.user_pk, s.client_pk, s.session_id, SYSTIMESTAMP,
    SYSTIMESTAMP + NUMTODSINTERVAL(30, 'DAY'),
    CASE WHEN s.status = 'REVOKED' THEN SYSTIMESTAMP ELSE NULL END,
    NULL, s.status, s.scope, s.audience
);

-- iam_embed_policy
MERGE INTO iam_embed_policy t
USING (
    SELECT 'e4000000-0000-0000-0000-000000000001' AS id,
           (SELECT id FROM iam_client WHERE client_id = 'system-order') AS child_pk,
           (SELECT id FROM iam_client WHERE client_id = 'portal') AS parent_pk,
           'https://portal.example.com' AS parent_origin, '/orders/*' AS allowed_path, 'ACTIVE' AS status FROM dual
) s
ON (t.child_client_id = s.child_pk AND t.parent_client_id = s.parent_pk
    AND t.parent_origin = s.parent_origin AND t.allowed_path = s.allowed_path)
WHEN MATCHED THEN UPDATE SET t.status = s.status
WHEN NOT MATCHED THEN INSERT (id, child_client_id, parent_client_id, parent_origin, allowed_path, status, created_at)
VALUES (s.id, s.child_pk, s.parent_pk, s.parent_origin, s.allowed_path, s.status, SYSTIMESTAMP);

-- iam_audit_log
MERGE INTO iam_audit_log t
USING (
    SELECT 'f1000000-0000-0000-0000-000000000001' AS id, 'seed-trace-login-ok' AS trace_id, 'LOGIN_SUCCESS' AS event_type,
           (SELECT subject_id FROM iam_user WHERE tenant_id = 'iam' AND username = 'admin') AS subject_pk,
           (SELECT id FROM iam_client WHERE client_id = 'portal') AS client_pk,
           'SUCCESS' AS result, CAST(NULL AS VARCHAR2(1024)) AS failure_reason,
           'admin' AS operator_name, 'iam' AS tenant_id, 'USER' AS res_type, 'dev seed' AS detail FROM dual
    UNION ALL
    SELECT 'f1000000-0000-0000-0000-000000000002', 'seed-trace-login-fail', 'LOGIN_FAILURE',
           CAST(NULL AS VARCHAR2(36)),
           (SELECT id FROM iam_client WHERE client_id = 'portal'),
           'FAILURE', 'unknown user', CAST(NULL AS VARCHAR2(128)), 'iam', 'USER', 'dev seed' FROM dual
    UNION ALL
    SELECT 'f1000000-0000-0000-0000-000000000003', 'seed-trace-client-off', 'CLIENT_DISABLED',
           (SELECT subject_id FROM iam_user WHERE tenant_id = 'iam' AND username = 'admin'),
           (SELECT id FROM iam_client WHERE client_id = 'system-legacy'),
           'SUCCESS', CAST(NULL AS VARCHAR2(1024)), 'admin', 'iam', 'CLIENT', 'system-legacy' FROM dual
    UNION ALL
    SELECT 'f1000000-0000-0000-0000-000000000004', 'seed-trace-admin-auth', 'ADMIN_AUTH_SUCCESS',
           (SELECT subject_id FROM iam_user WHERE tenant_id = 'iam' AND username = 'admin'),
           (SELECT id FROM iam_client WHERE client_id = 'portal'),
           'SUCCESS', CAST(NULL AS VARCHAR2(1024)), 'admin', 'iam', 'ADMIN', 'dev seed' FROM dual
) s
ON (t.trace_id = s.trace_id)
WHEN MATCHED THEN UPDATE SET t.event_type = s.event_type, t.result = s.result, t.detail = s.detail
WHEN NOT MATCHED THEN INSERT (
    id, trace_id, event_type, subject_id, client_id, resource_id, source_ip, user_agent,
    result, failure_reason, created_at, detail, operator_name, tenant_id, res_type
) VALUES (
    s.id, s.trace_id, s.event_type, s.subject_pk, s.client_pk, NULL, '127.0.0.1', 'seed',
    s.result, s.failure_reason, SYSTIMESTAMP, s.detail, s.operator_name, s.tenant_id, s.res_type
);

COMMIT;
