CREATE TABLE iam_user_identity_mapping (
    id VARCHAR2(36) PRIMARY KEY,
    subject_id VARCHAR2(36) NOT NULL,
    system_code VARCHAR2(128) NOT NULL,
    external_user_id VARCHAR2(256) NOT NULL,
    external_username VARCHAR2(256),
    mapping_status VARCHAR2(32) NOT NULL,
    created_at TIMESTAMP(6) NOT NULL,
    CONSTRAINT uk_iam_user_identity_mapping UNIQUE (subject_id, system_code, external_user_id),
    CONSTRAINT fk_iam_identity_subject FOREIGN KEY (subject_id)
        REFERENCES iam_user (id) ON DELETE CASCADE
);
CREATE INDEX idx_iam_identity_subject ON iam_user_identity_mapping (subject_id);
CREATE INDEX idx_iam_identity_system ON iam_user_identity_mapping (system_code);
CREATE INDEX idx_iam_identity_external_id ON iam_user_identity_mapping (external_user_id);
CREATE INDEX idx_iam_identity_status ON iam_user_identity_mapping (mapping_status);
