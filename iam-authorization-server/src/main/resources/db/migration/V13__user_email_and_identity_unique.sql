ALTER TABLE iam_user_identity_mapping DROP CONSTRAINT fk_iam_identity_subject;
ALTER TABLE iam_user_identity_mapping DROP CONSTRAINT uk_iam_user_identity_mapping;

ALTER TABLE iam_user ADD email VARCHAR2(256);

ALTER TABLE iam_user_identity_mapping
    ADD CONSTRAINT uk_idmap_sys_ext UNIQUE (system_code, external_user_id);

ALTER TABLE iam_user_identity_mapping
    ADD CONSTRAINT fk_iam_identity_subject FOREIGN KEY (subject_id)
        REFERENCES iam_user (subject_id) ON DELETE CASCADE;

CREATE INDEX idx_iam_user_email ON iam_user (email);

COMMENT ON COLUMN iam_user.email IS '用户邮箱，可变更，禁止作为 JWT sub';
