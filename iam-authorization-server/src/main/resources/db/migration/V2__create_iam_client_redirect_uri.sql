CREATE TABLE iam_client_redirect_uri (
    id VARCHAR2(36) PRIMARY KEY,
    client_id VARCHAR2(36) NOT NULL,
    redirect_uri VARCHAR2(500) NOT NULL,
    uri_type VARCHAR2(32) NOT NULL,
    status VARCHAR2(32) NOT NULL,
    CONSTRAINT uk_iam_cli_redir_uri UNIQUE (client_id, redirect_uri, uri_type),
    CONSTRAINT fk_iam_cli_redir_client FOREIGN KEY (client_id)
        REFERENCES iam_client (id) ON DELETE CASCADE
);
CREATE INDEX idx_iam_cli_redir_client ON iam_client_redirect_uri (client_id);
CREATE INDEX idx_iam_cli_redir_status ON iam_client_redirect_uri (status);
