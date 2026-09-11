CREATE TABLE iam_refresh_token (
    id VARCHAR2(36) PRIMARY KEY,
    token_hash VARCHAR2(128) NOT NULL,
    subject_id VARCHAR2(36) NOT NULL,
    client_id VARCHAR2(36) NOT NULL,
    session_id VARCHAR2(36) NOT NULL,
    issued_at TIMESTAMP(6) NOT NULL,
    expires_at TIMESTAMP(6) NOT NULL,
    revoked_at TIMESTAMP(6),
    rotation_parent_id VARCHAR2(36),
    status VARCHAR2(32) NOT NULL,
    CONSTRAINT uk_iam_refresh_token_hash UNIQUE (token_hash),
    CONSTRAINT fk_iam_refresh_subject FOREIGN KEY (subject_id)
        REFERENCES iam_user (id) ON DELETE CASCADE,
    CONSTRAINT fk_iam_refresh_client FOREIGN KEY (client_id)
        REFERENCES iam_client (id) ON DELETE CASCADE
);
CREATE INDEX idx_iam_refresh_subject ON iam_refresh_token (subject_id);
CREATE INDEX idx_iam_refresh_client ON iam_refresh_token (client_id);
CREATE INDEX idx_iam_refresh_session ON iam_refresh_token (session_id);
CREATE INDEX idx_iam_refresh_status ON iam_refresh_token (status);
CREATE INDEX idx_iam_refresh_expires ON iam_refresh_token (expires_at);
