CREATE TABLE iam_cli_res_perm (
    id VARCHAR2(36) PRIMARY KEY,
    client_id VARCHAR2(36) NOT NULL,
    resource_id VARCHAR2(36) NOT NULL,
    scope_id VARCHAR2(36) NOT NULL,
    grant_type VARCHAR2(64) NOT NULL,
    status VARCHAR2(32) NOT NULL,
    created_at TIMESTAMP(6) NOT NULL,
    CONSTRAINT uk_cli_res_perm UNIQUE (client_id, resource_id, scope_id, grant_type),
    CONSTRAINT fk_perm_client FOREIGN KEY (client_id)
        REFERENCES iam_client (id) ON DELETE CASCADE,
    CONSTRAINT fk_perm_resource FOREIGN KEY (resource_id)
        REFERENCES iam_resource_server (id) ON DELETE CASCADE,
    CONSTRAINT fk_perm_scope FOREIGN KEY (scope_id)
        REFERENCES iam_scope (id) ON DELETE CASCADE
);
CREATE INDEX idx_perm_client ON iam_cli_res_perm (client_id);
CREATE INDEX idx_perm_resource ON iam_cli_res_perm (resource_id);
CREATE INDEX idx_perm_scope ON iam_cli_res_perm (scope_id);
