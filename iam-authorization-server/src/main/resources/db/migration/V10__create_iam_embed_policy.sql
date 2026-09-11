CREATE TABLE iam_embed_policy (
    id VARCHAR2(36) PRIMARY KEY,
    child_client_id VARCHAR2(36) NOT NULL,
    parent_client_id VARCHAR2(36) NOT NULL,
    parent_origin VARCHAR2(512) NOT NULL,
    allowed_path VARCHAR2(512) NOT NULL,
    status VARCHAR2(32) NOT NULL,
    created_at TIMESTAMP(6) NOT NULL,
    CONSTRAINT uk_iam_embed_policy UNIQUE (child_client_id, parent_client_id, parent_origin, allowed_path),
    CONSTRAINT fk_iam_embed_child FOREIGN KEY (child_client_id)
        REFERENCES iam_client (id) ON DELETE CASCADE,
    CONSTRAINT fk_iam_embed_parent FOREIGN KEY (parent_client_id)
        REFERENCES iam_client (id) ON DELETE CASCADE
);
CREATE INDEX idx_iam_embed_child ON iam_embed_policy (child_client_id);
CREATE INDEX idx_iam_embed_parent ON iam_embed_policy (parent_client_id);
CREATE INDEX idx_iam_embed_status ON iam_embed_policy (status);
