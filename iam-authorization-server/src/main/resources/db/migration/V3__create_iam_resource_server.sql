CREATE TABLE iam_resource_server (
    id VARCHAR2(36) PRIMARY KEY,
    resource_code VARCHAR2(128) NOT NULL,
    resource_name VARCHAR2(256) NOT NULL,
    audience VARCHAR2(256) NOT NULL,
    status VARCHAR2(32) NOT NULL,
    owner VARCHAR2(256),
    created_at TIMESTAMP(6) NOT NULL,
    CONSTRAINT uk_iam_rs_code UNIQUE (resource_code),
    CONSTRAINT uk_iam_rs_audience UNIQUE (audience)
);
CREATE INDEX idx_iam_rs_status ON iam_resource_server (status);
CREATE INDEX idx_iam_rs_owner ON iam_resource_server (owner);
