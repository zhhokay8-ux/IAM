CREATE TABLE iam_admin_role (
    id VARCHAR2(36) PRIMARY KEY,
    role_code VARCHAR2(64) NOT NULL,
    role_name VARCHAR2(128) NOT NULL,
    status VARCHAR2(32) NOT NULL,
    created_at TIMESTAMP(6) NOT NULL,
    CONSTRAINT uk_iam_admin_role_code UNIQUE (role_code)
);
CREATE INDEX idx_adm_role_status ON iam_admin_role (status);

CREATE TABLE iam_admin_perm (
    id VARCHAR2(36) PRIMARY KEY,
    perm_code VARCHAR2(64) NOT NULL,
    perm_name VARCHAR2(128) NOT NULL,
    created_at TIMESTAMP(6) NOT NULL,
    CONSTRAINT uk_iam_admin_perm_code UNIQUE (perm_code)
);

CREATE TABLE iam_admin_role_perm (
    id VARCHAR2(36) PRIMARY KEY,
    role_id VARCHAR2(36) NOT NULL,
    perm_id VARCHAR2(36) NOT NULL,
    CONSTRAINT uk_iam_adm_role_perm UNIQUE (role_id, perm_id),
    CONSTRAINT fk_adm_rp_role FOREIGN KEY (role_id)
        REFERENCES iam_admin_role (id) ON DELETE CASCADE,
    CONSTRAINT fk_adm_rp_perm FOREIGN KEY (perm_id)
        REFERENCES iam_admin_perm (id) ON DELETE CASCADE
);
CREATE INDEX idx_adm_rp_role ON iam_admin_role_perm (role_id);
CREATE INDEX idx_adm_rp_perm ON iam_admin_role_perm (perm_id);

CREATE TABLE iam_admin_user_role (
    id VARCHAR2(36) PRIMARY KEY,
    subject_id VARCHAR2(36) NOT NULL,
    role_id VARCHAR2(36) NOT NULL,
    created_at TIMESTAMP(6) NOT NULL,
    CONSTRAINT uk_iam_adm_user_role UNIQUE (subject_id, role_id),
    CONSTRAINT fk_adm_ur_subject FOREIGN KEY (subject_id)
        REFERENCES iam_user (subject_id) ON DELETE CASCADE,
    CONSTRAINT fk_adm_ur_role FOREIGN KEY (role_id)
        REFERENCES iam_admin_role (id) ON DELETE CASCADE
);
CREATE INDEX idx_adm_ur_subject ON iam_admin_user_role (subject_id);
CREATE INDEX idx_adm_ur_role ON iam_admin_user_role (role_id);

ALTER TABLE iam_audit_log ADD operator_name VARCHAR2(128);
ALTER TABLE iam_audit_log ADD tenant_id VARCHAR2(128);
ALTER TABLE iam_audit_log ADD res_type VARCHAR2(64);

COMMENT ON TABLE iam_admin_role IS 'IAM Admin 角色';
COMMENT ON TABLE iam_admin_perm IS 'IAM Admin 权限点';
COMMENT ON TABLE iam_admin_role_perm IS '角色与权限绑定';
COMMENT ON TABLE iam_admin_user_role IS '用户 subject 与 Admin 角色绑定';
COMMENT ON COLUMN iam_audit_log.operator_name IS '管理操作者用户名，禁止存 Secret';
COMMENT ON COLUMN iam_audit_log.tenant_id IS '管理操作者租户';
COMMENT ON COLUMN iam_audit_log.res_type IS '管理操作资源类型';

INSERT INTO iam_admin_role (id, role_code, role_name, status, created_at) VALUES ('a1000000-0000-0000-0000-000000000001', 'IAM_ADMIN', 'IAM Admin', 'ACTIVE', SYSTIMESTAMP);
INSERT INTO iam_admin_role (id, role_code, role_name, status, created_at) VALUES ('a1000000-0000-0000-0000-000000000002', 'IAM_SECURITY_ADMIN', 'IAM Security Admin', 'ACTIVE', SYSTIMESTAMP);
INSERT INTO iam_admin_role (id, role_code, role_name, status, created_at) VALUES ('a1000000-0000-0000-0000-000000000003', 'IAM_OPERATOR', 'IAM Operator', 'ACTIVE', SYSTIMESTAMP);
INSERT INTO iam_admin_role (id, role_code, role_name, status, created_at) VALUES ('a1000000-0000-0000-0000-000000000004', 'IAM_AUDITOR', 'IAM Auditor', 'ACTIVE', SYSTIMESTAMP);

INSERT INTO iam_admin_perm (id, perm_code, perm_name, created_at) VALUES ('a2000000-0000-0000-0000-000000000001', 'admin.client.read', 'Client read', SYSTIMESTAMP);
INSERT INTO iam_admin_perm (id, perm_code, perm_name, created_at) VALUES ('a2000000-0000-0000-0000-000000000002', 'admin.client.write', 'Client write', SYSTIMESTAMP);
INSERT INTO iam_admin_perm (id, perm_code, perm_name, created_at) VALUES ('a2000000-0000-0000-0000-000000000003', 'admin.resource.read', 'Resource read', SYSTIMESTAMP);
INSERT INTO iam_admin_perm (id, perm_code, perm_name, created_at) VALUES ('a2000000-0000-0000-0000-000000000004', 'admin.resource.write', 'Resource write', SYSTIMESTAMP);
INSERT INTO iam_admin_perm (id, perm_code, perm_name, created_at) VALUES ('a2000000-0000-0000-0000-000000000005', 'admin.scope.read', 'Scope read', SYSTIMESTAMP);
INSERT INTO iam_admin_perm (id, perm_code, perm_name, created_at) VALUES ('a2000000-0000-0000-0000-000000000006', 'admin.scope.write', 'Scope write', SYSTIMESTAMP);
INSERT INTO iam_admin_perm (id, perm_code, perm_name, created_at) VALUES ('a2000000-0000-0000-0000-000000000007', 'admin.policy.read', 'Policy read', SYSTIMESTAMP);
INSERT INTO iam_admin_perm (id, perm_code, perm_name, created_at) VALUES ('a2000000-0000-0000-0000-000000000008', 'admin.policy.write', 'Policy write', SYSTIMESTAMP);
INSERT INTO iam_admin_perm (id, perm_code, perm_name, created_at) VALUES ('a2000000-0000-0000-0000-000000000009', 'admin.user.read', 'User read', SYSTIMESTAMP);
INSERT INTO iam_admin_perm (id, perm_code, perm_name, created_at) VALUES ('a2000000-0000-0000-0000-00000000000a', 'admin.user.write', 'User write', SYSTIMESTAMP);
INSERT INTO iam_admin_perm (id, perm_code, perm_name, created_at) VALUES ('a2000000-0000-0000-0000-00000000000b', 'admin.token.read', 'Token read', SYSTIMESTAMP);
INSERT INTO iam_admin_perm (id, perm_code, perm_name, created_at) VALUES ('a2000000-0000-0000-0000-00000000000c', 'admin.token.revoke', 'Token revoke', SYSTIMESTAMP);
INSERT INTO iam_admin_perm (id, perm_code, perm_name, created_at) VALUES ('a2000000-0000-0000-0000-00000000000d', 'admin.session.read', 'Session read', SYSTIMESTAMP);
INSERT INTO iam_admin_perm (id, perm_code, perm_name, created_at) VALUES ('a2000000-0000-0000-0000-00000000000e', 'admin.session.revoke', 'Session revoke', SYSTIMESTAMP);
INSERT INTO iam_admin_perm (id, perm_code, perm_name, created_at) VALUES ('a2000000-0000-0000-0000-00000000000f', 'admin.embed.read', 'Embed read', SYSTIMESTAMP);
INSERT INTO iam_admin_perm (id, perm_code, perm_name, created_at) VALUES ('a2000000-0000-0000-0000-000000000010', 'admin.embed.write', 'Embed write', SYSTIMESTAMP);
INSERT INTO iam_admin_perm (id, perm_code, perm_name, created_at) VALUES ('a2000000-0000-0000-0000-000000000011', 'admin.audit.read', 'Audit read', SYSTIMESTAMP);
INSERT INTO iam_admin_perm (id, perm_code, perm_name, created_at) VALUES ('a2000000-0000-0000-0000-000000000012', 'admin.key.read', 'Signing key read', SYSTIMESTAMP);
INSERT INTO iam_admin_perm (id, perm_code, perm_name, created_at) VALUES ('a2000000-0000-0000-0000-000000000013', 'admin.key.rotate', 'Signing key rotate', SYSTIMESTAMP);
INSERT INTO iam_admin_perm (id, perm_code, perm_name, created_at) VALUES ('a2000000-0000-0000-0000-000000000014', 'admin.config.read', 'Config read', SYSTIMESTAMP);

INSERT INTO iam_admin_role_perm (id, role_id, perm_id)
SELECT LOWER(SUBSTR(h, 1, 8) || '-' || SUBSTR(h, 9, 4) || '-' || SUBSTR(h, 13, 4) || '-' || SUBSTR(h, 17, 4) || '-' || SUBSTR(h, 21, 12)),
       role_id, perm_id
  FROM (
        SELECT RAWTOHEX(SYS_GUID()) AS h, r.id AS role_id, p.id AS perm_id
          FROM iam_admin_role r CROSS JOIN iam_admin_perm p
         WHERE r.role_code = 'IAM_ADMIN'
       );

INSERT INTO iam_admin_role_perm (id, role_id, perm_id)
SELECT LOWER(SUBSTR(h, 1, 8) || '-' || SUBSTR(h, 9, 4) || '-' || SUBSTR(h, 13, 4) || '-' || SUBSTR(h, 17, 4) || '-' || SUBSTR(h, 21, 12)),
       role_id, perm_id
  FROM (
        SELECT RAWTOHEX(SYS_GUID()) AS h, r.id AS role_id, p.id AS perm_id
          FROM iam_admin_role r CROSS JOIN iam_admin_perm p
         WHERE r.role_code = 'IAM_SECURITY_ADMIN' AND p.perm_code NOT IN ('admin.user.write')
       );

INSERT INTO iam_admin_role_perm (id, role_id, perm_id)
SELECT LOWER(SUBSTR(h, 1, 8) || '-' || SUBSTR(h, 9, 4) || '-' || SUBSTR(h, 13, 4) || '-' || SUBSTR(h, 17, 4) || '-' || SUBSTR(h, 21, 12)),
       role_id, perm_id
  FROM (
        SELECT RAWTOHEX(SYS_GUID()) AS h, r.id AS role_id, p.id AS perm_id
          FROM iam_admin_role r CROSS JOIN iam_admin_perm p
         WHERE r.role_code = 'IAM_OPERATOR' AND p.perm_code IN (
            'admin.client.read', 'admin.resource.read', 'admin.scope.read', 'admin.policy.read',
            'admin.user.read', 'admin.user.write', 'admin.token.read', 'admin.token.revoke',
            'admin.session.read', 'admin.session.revoke', 'admin.embed.read', 'admin.audit.read',
            'admin.config.read')
       );

INSERT INTO iam_admin_role_perm (id, role_id, perm_id)
SELECT LOWER(SUBSTR(h, 1, 8) || '-' || SUBSTR(h, 9, 4) || '-' || SUBSTR(h, 13, 4) || '-' || SUBSTR(h, 17, 4) || '-' || SUBSTR(h, 21, 12)),
       role_id, perm_id
  FROM (
        SELECT RAWTOHEX(SYS_GUID()) AS h, r.id AS role_id, p.id AS perm_id
          FROM iam_admin_role r CROSS JOIN iam_admin_perm p
         WHERE r.role_code = 'IAM_AUDITOR' AND p.perm_code IN (
            'admin.client.read', 'admin.resource.read', 'admin.scope.read', 'admin.policy.read',
            'admin.user.read', 'admin.token.read', 'admin.session.read', 'admin.embed.read',
            'admin.audit.read', 'admin.key.read', 'admin.config.read')
       );
