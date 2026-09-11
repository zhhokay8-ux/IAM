ALTER TABLE iam_client ADD client_secret_hash VARCHAR2(128);

ALTER TABLE iam_refresh_token ADD scope VARCHAR2(1024);

ALTER TABLE iam_refresh_token ADD audience VARCHAR2(1024);
