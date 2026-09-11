-- Convert existing RAW(16) UUID columns to VARCHAR2(36) hyphenated plaintext.
-- No-op when V1-V16 already created VARCHAR2 (fresh databases).
-- After editing V1-V16 checksums, run Flyway repair once on databases that already applied V16.

DECLARE
    v_type USER_TAB_COLUMNS.DATA_TYPE%TYPE;

    PROCEDURE drop_fk(p_table VARCHAR2, p_name VARCHAR2) IS
    BEGIN
        EXECUTE IMMEDIATE 'ALTER TABLE ' || p_table || ' DROP CONSTRAINT ' || p_name;
    EXCEPTION
        WHEN OTHERS THEN
            IF SQLCODE != -2443 THEN
                RAISE;
            END IF;
    END;

    PROCEDURE drop_pk(p_table VARCHAR2) IS
    BEGIN
        EXECUTE IMMEDIATE 'ALTER TABLE ' || p_table || ' DROP PRIMARY KEY CASCADE';
    EXCEPTION
        WHEN OTHERS THEN
            IF SQLCODE != -2441 AND SQLCODE != -2442 THEN
                RAISE;
            END IF;
    END;

    FUNCTION uuid_sql(p_col VARCHAR2) RETURN VARCHAR2 IS
    BEGIN
        RETURN 'CASE WHEN ' || p_col || ' IS NULL THEN NULL ELSE LOWER(SUBSTR(RAWTOHEX(' || p_col
            || '),1,8)||''-''||SUBSTR(RAWTOHEX(' || p_col || '),9,4)||''-''||SUBSTR(RAWTOHEX('
            || p_col || '),13,4)||''-''||SUBSTR(RAWTOHEX(' || p_col || '),17,4)||''-''||SUBSTR(RAWTOHEX('
            || p_col || '),21,12)) END';
    END;

    PROCEDURE conv(p_table VARCHAR2, p_col VARCHAR2, p_not_null NUMBER) IS
        v_dt USER_TAB_COLUMNS.DATA_TYPE%TYPE;
        v_tmp VARCHAR2(30);
        v_cnt NUMBER;
    BEGIN
        SELECT COUNT(*) INTO v_cnt
          FROM user_tab_columns
         WHERE table_name = UPPER(p_table) AND column_name = UPPER(p_col);
        IF v_cnt = 0 THEN
            RETURN;
        END IF;
        SELECT data_type INTO v_dt
          FROM user_tab_columns
         WHERE table_name = UPPER(p_table) AND column_name = UPPER(p_col);
        IF v_dt <> 'RAW' THEN
            RETURN;
        END IF;
        v_tmp := SUBSTR(p_col, 1, 26) || '_TXT';
        EXECUTE IMMEDIATE 'ALTER TABLE ' || p_table || ' ADD ' || v_tmp || ' VARCHAR2(36)';
        EXECUTE IMMEDIATE 'UPDATE ' || p_table || ' SET ' || v_tmp || ' = ' || uuid_sql(p_col);
        EXECUTE IMMEDIATE 'ALTER TABLE ' || p_table || ' DROP COLUMN ' || p_col;
        EXECUTE IMMEDIATE 'ALTER TABLE ' || p_table || ' RENAME COLUMN ' || v_tmp || ' TO ' || p_col;
        IF p_not_null = 1 THEN
            EXECUTE IMMEDIATE 'ALTER TABLE ' || p_table || ' MODIFY ' || p_col || ' VARCHAR2(36) NOT NULL';
        END IF;
    END;

    PROCEDURE add_pk(p_table VARCHAR2, p_col VARCHAR2) IS
    BEGIN
        EXECUTE IMMEDIATE 'ALTER TABLE ' || p_table || ' ADD PRIMARY KEY (' || p_col || ')';
    EXCEPTION
        WHEN OTHERS THEN
            IF SQLCODE != -2260 THEN
                RAISE;
            END IF;
    END;

    PROCEDURE add_uk(p_sql VARCHAR2) IS
    BEGIN
        EXECUTE IMMEDIATE p_sql;
    EXCEPTION
        WHEN OTHERS THEN
            IF SQLCODE != -2261 AND SQLCODE != -2260 THEN
                RAISE;
            END IF;
    END;

    PROCEDURE add_fk(p_name VARCHAR2, p_sql VARCHAR2) IS
    BEGIN
        EXECUTE IMMEDIATE p_sql;
    EXCEPTION
        WHEN OTHERS THEN
            IF SQLCODE != -2275 THEN
                RAISE;
            END IF;
    END;
BEGIN
    SELECT data_type INTO v_type
      FROM user_tab_columns
     WHERE table_name = 'IAM_CLIENT' AND column_name = 'ID';
    IF v_type <> 'RAW' THEN
        RETURN;
    END IF;

    drop_fk('iam_client_redirect_uri', 'fk_iam_cli_redir_client');
    drop_fk('iam_scope', 'fk_iam_scope_resource');
    drop_fk('iam_cli_res_perm', 'fk_perm_client');
    drop_fk('iam_cli_res_perm', 'fk_perm_resource');
    drop_fk('iam_cli_res_perm', 'fk_perm_scope');
    drop_fk('iam_user_identity_mapping', 'fk_iam_identity_subject');
    drop_fk('iam_refresh_token', 'fk_iam_refresh_subject');
    drop_fk('iam_refresh_token', 'fk_iam_refresh_client');
    drop_fk('iam_embed_policy', 'fk_iam_embed_child');
    drop_fk('iam_embed_policy', 'fk_iam_embed_parent');
    drop_fk('iam_admin_role_perm', 'fk_adm_rp_role');
    drop_fk('iam_admin_role_perm', 'fk_adm_rp_perm');
    drop_fk('iam_admin_user_role', 'fk_adm_ur_subject');
    drop_fk('iam_admin_user_role', 'fk_adm_ur_role');

    drop_pk('iam_client');
    drop_pk('iam_client_redirect_uri');
    drop_pk('iam_resource_server');
    drop_pk('iam_scope');
    drop_pk('iam_cli_res_perm');
    drop_pk('iam_user');
    drop_pk('iam_user_identity_mapping');
    drop_pk('iam_refresh_token');
    drop_pk('iam_signing_key');
    drop_pk('iam_embed_policy');
    drop_pk('iam_audit_log');
    drop_pk('iam_admin_role');
    drop_pk('iam_admin_perm');
    drop_pk('iam_admin_role_perm');
    drop_pk('iam_admin_user_role');

    conv('iam_client', 'id', 1);
    conv('iam_client_redirect_uri', 'id', 1);
    conv('iam_client_redirect_uri', 'client_id', 1);
    conv('iam_resource_server', 'id', 1);
    conv('iam_scope', 'id', 1);
    conv('iam_scope', 'resource_id', 1);
    conv('iam_cli_res_perm', 'id', 1);
    conv('iam_cli_res_perm', 'client_id', 1);
    conv('iam_cli_res_perm', 'resource_id', 1);
    conv('iam_cli_res_perm', 'scope_id', 1);
    conv('iam_user', 'id', 1);
    conv('iam_user', 'subject_id', 1);
    conv('iam_user_identity_mapping', 'id', 1);
    conv('iam_user_identity_mapping', 'subject_id', 1);
    conv('iam_refresh_token', 'id', 1);
    conv('iam_refresh_token', 'subject_id', 1);
    conv('iam_refresh_token', 'client_id', 1);
    conv('iam_refresh_token', 'session_id', 1);
    conv('iam_refresh_token', 'rotation_parent_id', 0);
    conv('iam_signing_key', 'id', 1);
    conv('iam_embed_policy', 'id', 1);
    conv('iam_embed_policy', 'child_client_id', 1);
    conv('iam_embed_policy', 'parent_client_id', 1);
    conv('iam_audit_log', 'id', 1);
    conv('iam_audit_log', 'subject_id', 0);
    conv('iam_audit_log', 'client_id', 0);
    conv('iam_audit_log', 'resource_id', 0);
    conv('iam_admin_role', 'id', 1);
    conv('iam_admin_perm', 'id', 1);
    conv('iam_admin_role_perm', 'id', 1);
    conv('iam_admin_role_perm', 'role_id', 1);
    conv('iam_admin_role_perm', 'perm_id', 1);
    conv('iam_admin_user_role', 'id', 1);
    conv('iam_admin_user_role', 'subject_id', 1);
    conv('iam_admin_user_role', 'role_id', 1);

    add_pk('iam_client', 'id');
    add_pk('iam_client_redirect_uri', 'id');
    add_pk('iam_resource_server', 'id');
    add_pk('iam_scope', 'id');
    add_pk('iam_cli_res_perm', 'id');
    add_pk('iam_user', 'id');
    add_pk('iam_user_identity_mapping', 'id');
    add_pk('iam_refresh_token', 'id');
    add_pk('iam_signing_key', 'id');
    add_pk('iam_embed_policy', 'id');
    add_pk('iam_audit_log', 'id');
    add_pk('iam_admin_role', 'id');
    add_pk('iam_admin_perm', 'id');
    add_pk('iam_admin_role_perm', 'id');
    add_pk('iam_admin_user_role', 'id');

    add_uk('ALTER TABLE iam_user ADD CONSTRAINT uk_iam_user_subject UNIQUE (subject_id)');
    add_uk('ALTER TABLE iam_client_redirect_uri ADD CONSTRAINT uk_iam_cli_redir_uri UNIQUE (client_id, redirect_uri, uri_type)');
    add_uk('ALTER TABLE iam_cli_res_perm ADD CONSTRAINT uk_cli_res_perm UNIQUE (client_id, resource_id, scope_id, grant_type)');
    add_uk('ALTER TABLE iam_embed_policy ADD CONSTRAINT uk_iam_embed_policy UNIQUE (child_client_id, parent_client_id, parent_origin, allowed_path)');
    add_uk('ALTER TABLE iam_admin_role_perm ADD CONSTRAINT uk_iam_adm_role_perm UNIQUE (role_id, perm_id)');
    add_uk('ALTER TABLE iam_admin_user_role ADD CONSTRAINT uk_iam_adm_user_role UNIQUE (subject_id, role_id)');

    add_fk('fk_iam_cli_redir_client',
        'ALTER TABLE iam_client_redirect_uri ADD CONSTRAINT fk_iam_cli_redir_client FOREIGN KEY (client_id) REFERENCES iam_client (id) ON DELETE CASCADE');
    add_fk('fk_iam_scope_resource',
        'ALTER TABLE iam_scope ADD CONSTRAINT fk_iam_scope_resource FOREIGN KEY (resource_id) REFERENCES iam_resource_server (id) ON DELETE CASCADE');
    add_fk('fk_perm_client',
        'ALTER TABLE iam_cli_res_perm ADD CONSTRAINT fk_perm_client FOREIGN KEY (client_id) REFERENCES iam_client (id) ON DELETE CASCADE');
    add_fk('fk_perm_resource',
        'ALTER TABLE iam_cli_res_perm ADD CONSTRAINT fk_perm_resource FOREIGN KEY (resource_id) REFERENCES iam_resource_server (id) ON DELETE CASCADE');
    add_fk('fk_perm_scope',
        'ALTER TABLE iam_cli_res_perm ADD CONSTRAINT fk_perm_scope FOREIGN KEY (scope_id) REFERENCES iam_scope (id) ON DELETE CASCADE');
    add_fk('fk_iam_identity_subject',
        'ALTER TABLE iam_user_identity_mapping ADD CONSTRAINT fk_iam_identity_subject FOREIGN KEY (subject_id) REFERENCES iam_user (subject_id) ON DELETE CASCADE');
    add_fk('fk_iam_refresh_subject',
        'ALTER TABLE iam_refresh_token ADD CONSTRAINT fk_iam_refresh_subject FOREIGN KEY (subject_id) REFERENCES iam_user (id) ON DELETE CASCADE');
    add_fk('fk_iam_refresh_client',
        'ALTER TABLE iam_refresh_token ADD CONSTRAINT fk_iam_refresh_client FOREIGN KEY (client_id) REFERENCES iam_client (id) ON DELETE CASCADE');
    add_fk('fk_iam_embed_child',
        'ALTER TABLE iam_embed_policy ADD CONSTRAINT fk_iam_embed_child FOREIGN KEY (child_client_id) REFERENCES iam_client (id) ON DELETE CASCADE');
    add_fk('fk_iam_embed_parent',
        'ALTER TABLE iam_embed_policy ADD CONSTRAINT fk_iam_embed_parent FOREIGN KEY (parent_client_id) REFERENCES iam_client (id) ON DELETE CASCADE');
    add_fk('fk_adm_rp_role',
        'ALTER TABLE iam_admin_role_perm ADD CONSTRAINT fk_adm_rp_role FOREIGN KEY (role_id) REFERENCES iam_admin_role (id) ON DELETE CASCADE');
    add_fk('fk_adm_rp_perm',
        'ALTER TABLE iam_admin_role_perm ADD CONSTRAINT fk_adm_rp_perm FOREIGN KEY (perm_id) REFERENCES iam_admin_perm (id) ON DELETE CASCADE');
    add_fk('fk_adm_ur_subject',
        'ALTER TABLE iam_admin_user_role ADD CONSTRAINT fk_adm_ur_subject FOREIGN KEY (subject_id) REFERENCES iam_user (subject_id) ON DELETE CASCADE');
    add_fk('fk_adm_ur_role',
        'ALTER TABLE iam_admin_user_role ADD CONSTRAINT fk_adm_ur_role FOREIGN KEY (role_id) REFERENCES iam_admin_role (id) ON DELETE CASCADE');
END;
