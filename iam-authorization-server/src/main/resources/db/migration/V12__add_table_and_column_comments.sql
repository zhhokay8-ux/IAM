-- Add database comments for IAM tables and columns.

COMMENT ON TABLE iam_client IS 'OAuth/OIDC 客户端注册表';
COMMENT ON COLUMN iam_client.id IS '客户端主键';
COMMENT ON COLUMN iam_client.client_id IS '客户端唯一标识';
COMMENT ON COLUMN iam_client.client_name IS '客户端显示名称';
COMMENT ON COLUMN iam_client.client_type IS '客户端类型，例如 CONFIDENTIAL 或 PUBLIC';
COMMENT ON COLUMN iam_client.status IS '客户端状态';
COMMENT ON COLUMN iam_client.token_endpoint_auth_method IS 'Token Endpoint 认证方式';
COMMENT ON COLUMN iam_client.access_token_ttl IS 'Access Token 有效期，单位秒';
COMMENT ON COLUMN iam_client.refresh_token_ttl IS 'Refresh Token 有效期，单位秒';
COMMENT ON COLUMN iam_client.pkce_required IS '是否强制要求 PKCE';
COMMENT ON COLUMN iam_client.owner IS '客户端归属负责人或团队';
COMMENT ON COLUMN iam_client.created_at IS '创建时间';
COMMENT ON COLUMN iam_client.updated_at IS '更新时间';

COMMENT ON TABLE iam_client_redirect_uri IS 'OAuth/OIDC 客户端回调地址表';
COMMENT ON COLUMN iam_client_redirect_uri.id IS '回调地址主键';
COMMENT ON COLUMN iam_client_redirect_uri.client_id IS '所属客户端 ID';
COMMENT ON COLUMN iam_client_redirect_uri.redirect_uri IS '注册的回调 URI';
COMMENT ON COLUMN iam_client_redirect_uri.uri_type IS '回调 URI 类型';
COMMENT ON COLUMN iam_client_redirect_uri.status IS '回调地址状态';

COMMENT ON TABLE iam_resource_server IS '资源服务器注册表';
COMMENT ON COLUMN iam_resource_server.id IS '资源服务器主键';
COMMENT ON COLUMN iam_resource_server.resource_code IS '资源服务器编码';
COMMENT ON COLUMN iam_resource_server.resource_name IS '资源服务器名称';
COMMENT ON COLUMN iam_resource_server.audience IS 'Token 受众标识';
COMMENT ON COLUMN iam_resource_server.status IS '资源服务器状态';
COMMENT ON COLUMN iam_resource_server.owner IS '资源服务器归属负责人或团队';
COMMENT ON COLUMN iam_resource_server.created_at IS '创建时间';

COMMENT ON TABLE iam_scope IS '资源作用域表';
COMMENT ON COLUMN iam_scope.id IS '作用域主键';
COMMENT ON COLUMN iam_scope.resource_id IS '所属资源服务器 ID';
COMMENT ON COLUMN iam_scope.scope_code IS '作用域编码';
COMMENT ON COLUMN iam_scope.scope_name IS '作用域名称';
COMMENT ON COLUMN iam_scope.description IS '作用域说明';
COMMENT ON COLUMN iam_scope.status IS '作用域状态';

COMMENT ON TABLE iam_cli_res_perm IS '客户端资源授权关系表';
COMMENT ON COLUMN iam_cli_res_perm.id IS '授权关系主键';
COMMENT ON COLUMN iam_cli_res_perm.client_id IS '客户端 ID';
COMMENT ON COLUMN iam_cli_res_perm.resource_id IS '资源服务器 ID';
COMMENT ON COLUMN iam_cli_res_perm.scope_id IS '作用域 ID';
COMMENT ON COLUMN iam_cli_res_perm.grant_type IS '授权类型';
COMMENT ON COLUMN iam_cli_res_perm.status IS '授权状态';
COMMENT ON COLUMN iam_cli_res_perm.created_at IS '创建时间';

COMMENT ON TABLE iam_user IS '统一用户表';
COMMENT ON COLUMN iam_user.id IS '用户主键';
COMMENT ON COLUMN iam_user.subject_id IS '统一用户主体标识';
COMMENT ON COLUMN iam_user.username IS '登录用户名';
COMMENT ON COLUMN iam_user.display_name IS '用户显示名称';
COMMENT ON COLUMN iam_user.status IS '用户状态';
COMMENT ON COLUMN iam_user.tenant_id IS '租户 ID';
COMMENT ON COLUMN iam_user.org_id IS '组织机构 ID';
COMMENT ON COLUMN iam_user.created_at IS '创建时间';
COMMENT ON COLUMN iam_user.updated_at IS '更新时间';

COMMENT ON TABLE iam_user_identity_mapping IS '外部系统用户身份映射表';
COMMENT ON COLUMN iam_user_identity_mapping.id IS '身份映射主键';
COMMENT ON COLUMN iam_user_identity_mapping.subject_id IS '统一用户主体 ID';
COMMENT ON COLUMN iam_user_identity_mapping.system_code IS '外部系统编码';
COMMENT ON COLUMN iam_user_identity_mapping.external_user_id IS '外部系统用户 ID';
COMMENT ON COLUMN iam_user_identity_mapping.external_username IS '外部系统用户名';
COMMENT ON COLUMN iam_user_identity_mapping.mapping_status IS '映射状态';
COMMENT ON COLUMN iam_user_identity_mapping.created_at IS '创建时间';

COMMENT ON TABLE iam_refresh_token IS 'Refresh Token 持久化表';
COMMENT ON COLUMN iam_refresh_token.id IS 'Refresh Token 主键';
COMMENT ON COLUMN iam_refresh_token.token_hash IS 'Refresh Token 的 SHA-256 哈希值，禁止保存明文';
COMMENT ON COLUMN iam_refresh_token.subject_id IS '统一用户 ID';
COMMENT ON COLUMN iam_refresh_token.client_id IS '客户端 ID';
COMMENT ON COLUMN iam_refresh_token.session_id IS '会话 ID';
COMMENT ON COLUMN iam_refresh_token.issued_at IS '签发时间';
COMMENT ON COLUMN iam_refresh_token.expires_at IS '过期时间';
COMMENT ON COLUMN iam_refresh_token.revoked_at IS '撤销时间';
COMMENT ON COLUMN iam_refresh_token.rotation_parent_id IS '轮换前的父 Refresh Token ID';
COMMENT ON COLUMN iam_refresh_token.status IS 'Refresh Token 状态';

COMMENT ON TABLE iam_signing_key IS '签名密钥元数据表';
COMMENT ON COLUMN iam_signing_key.id IS '签名密钥主键';
COMMENT ON COLUMN iam_signing_key.kid IS '密钥 ID';
COMMENT ON COLUMN iam_signing_key.algorithm IS '签名算法';
COMMENT ON COLUMN iam_signing_key.kms_key_id IS 'KMS/HSM 密钥标识，禁止保存 RSA 私钥';
COMMENT ON COLUMN iam_signing_key.status IS '密钥状态';
COMMENT ON COLUMN iam_signing_key.activated_at IS '启用时间';
COMMENT ON COLUMN iam_signing_key.retired_at IS '停用时间';
COMMENT ON COLUMN iam_signing_key.created_at IS '创建时间';

COMMENT ON TABLE iam_embed_policy IS 'iframe 嵌入策略表';
COMMENT ON COLUMN iam_embed_policy.id IS '嵌入策略主键';
COMMENT ON COLUMN iam_embed_policy.child_client_id IS '子应用客户端 ID';
COMMENT ON COLUMN iam_embed_policy.parent_client_id IS '父应用客户端 ID';
COMMENT ON COLUMN iam_embed_policy.parent_origin IS '允许的父应用 Origin';
COMMENT ON COLUMN iam_embed_policy.allowed_path IS '允许嵌入的路径';
COMMENT ON COLUMN iam_embed_policy.status IS '策略状态';
COMMENT ON COLUMN iam_embed_policy.created_at IS '创建时间';

COMMENT ON TABLE iam_audit_log IS '认证与授权审计日志表';
COMMENT ON COLUMN iam_audit_log.id IS '审计日志主键';
COMMENT ON COLUMN iam_audit_log.trace_id IS '链路追踪 ID';
COMMENT ON COLUMN iam_audit_log.event_type IS '审计事件类型';
COMMENT ON COLUMN iam_audit_log.subject_id IS '统一用户 ID';
COMMENT ON COLUMN iam_audit_log.client_id IS '客户端 ID';
COMMENT ON COLUMN iam_audit_log.resource_id IS '资源服务器 ID';
COMMENT ON COLUMN iam_audit_log.source_ip IS '来源 IP';
COMMENT ON COLUMN iam_audit_log.user_agent IS '客户端 User-Agent';
COMMENT ON COLUMN iam_audit_log.result IS '处理结果';
COMMENT ON COLUMN iam_audit_log.failure_reason IS '失败原因';
COMMENT ON COLUMN iam_audit_log.created_at IS '创建时间';
