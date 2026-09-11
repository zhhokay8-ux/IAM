CREATE TABLE iam_client (
    id VARCHAR2(36) PRIMARY KEY,
    client_id VARCHAR2(128) NOT NULL,
    client_name VARCHAR2(256) NOT NULL,
    client_type VARCHAR2(32) NOT NULL,
    status VARCHAR2(32) NOT NULL,
    token_endpoint_auth_method VARCHAR2(64) NOT NULL,
    access_token_ttl NUMBER(10) NOT NULL,
    refresh_token_ttl NUMBER(10) NOT NULL,
    pkce_required NUMBER(1) NOT NULL,
    owner VARCHAR2(256),
    created_at TIMESTAMP(6) NOT NULL,
    updated_at TIMESTAMP(6) NOT NULL,
    CONSTRAINT uk_iam_client_client_id UNIQUE (client_id),
    CONSTRAINT ck_iam_client_access_ttl CHECK (access_token_ttl > 0),
    CONSTRAINT ck_iam_client_refresh_ttl CHECK (refresh_token_ttl > 0),
    CONSTRAINT ck_iam_client_pkce CHECK (pkce_required IN (0, 1))
);
CREATE INDEX idx_iam_client_status ON iam_client (status);
CREATE INDEX idx_iam_client_owner ON iam_client (owner);
