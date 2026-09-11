CREATE TABLE iam_signing_key (
    id VARCHAR2(36) PRIMARY KEY,
    kid VARCHAR2(128) NOT NULL,
    algorithm VARCHAR2(32) NOT NULL,
    kms_key_id VARCHAR2(512) NOT NULL,
    status VARCHAR2(32) NOT NULL,
    activated_at TIMESTAMP(6),
    retired_at TIMESTAMP(6),
    created_at TIMESTAMP(6) NOT NULL,
    CONSTRAINT uk_iam_signing_key_kid UNIQUE (kid)
);
CREATE INDEX idx_iam_signing_key_status ON iam_signing_key (status);
CREATE INDEX idx_iam_signing_key_algorithm ON iam_signing_key (algorithm);
