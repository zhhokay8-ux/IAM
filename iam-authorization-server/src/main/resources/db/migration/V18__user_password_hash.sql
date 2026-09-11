ALTER TABLE iam_user ADD password_hash VARCHAR2(100);
COMMENT ON COLUMN iam_user.password_hash IS 'BCrypt password hash; plaintext is forbidden';
