CREATE TABLE iam_audit_log (
    id VARCHAR2(36) PRIMARY KEY,
    trace_id VARCHAR2(64) NOT NULL,
    event_type VARCHAR2(128) NOT NULL,
    subject_id VARCHAR2(36),
    client_id VARCHAR2(36),
    resource_id VARCHAR2(36),
    source_ip VARCHAR2(64),
    user_agent VARCHAR2(512),
    result VARCHAR2(32) NOT NULL,
    failure_reason VARCHAR2(1024),
    created_at TIMESTAMP(6) NOT NULL
);
CREATE INDEX idx_iam_audit_trace ON iam_audit_log (trace_id);
CREATE INDEX idx_iam_audit_event ON iam_audit_log (event_type);
CREATE INDEX idx_iam_audit_subject ON iam_audit_log (subject_id);
CREATE INDEX idx_iam_audit_client ON iam_audit_log (client_id);
CREATE INDEX idx_iam_audit_resource ON iam_audit_log (resource_id);
CREATE INDEX idx_iam_audit_result ON iam_audit_log (result);
CREATE INDEX idx_iam_audit_created_at ON iam_audit_log (created_at);
