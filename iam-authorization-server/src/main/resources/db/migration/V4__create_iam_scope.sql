CREATE TABLE iam_scope (
    id VARCHAR2(36) PRIMARY KEY,
    resource_id VARCHAR2(36) NOT NULL,
    scope_code VARCHAR2(128) NOT NULL,
    scope_name VARCHAR2(256) NOT NULL,
    description VARCHAR2(1024),
    status VARCHAR2(32) NOT NULL,
    CONSTRAINT uk_iam_scope_res_code UNIQUE (resource_id, scope_code),
    CONSTRAINT fk_iam_scope_resource FOREIGN KEY (resource_id)
        REFERENCES iam_resource_server (id) ON DELETE CASCADE
);
CREATE INDEX idx_iam_scope_resource ON iam_scope (resource_id);
CREATE INDEX idx_iam_scope_status ON iam_scope (status);
