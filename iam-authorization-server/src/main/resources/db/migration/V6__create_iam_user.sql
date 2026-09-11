CREATE TABLE iam_user (
    id VARCHAR2(36) PRIMARY KEY,
    subject_id VARCHAR2(36) NOT NULL,
    username VARCHAR2(128) NOT NULL,
    display_name VARCHAR2(256),
    status VARCHAR2(32) NOT NULL,
    tenant_id VARCHAR2(128) NOT NULL,
    org_id VARCHAR2(128),
    created_at TIMESTAMP(6) NOT NULL,
    updated_at TIMESTAMP(6) NOT NULL,
    CONSTRAINT uk_iam_user_subject UNIQUE (subject_id),
    CONSTRAINT uk_iam_user_tenant_username UNIQUE (tenant_id, username)
);
CREATE INDEX idx_iam_user_username ON iam_user (username);
CREATE INDEX idx_iam_user_status ON iam_user (status);
CREATE INDEX idx_iam_user_tenant ON iam_user (tenant_id);
CREATE INDEX idx_iam_user_org ON iam_user (org_id);
