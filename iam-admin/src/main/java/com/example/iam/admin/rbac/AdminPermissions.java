package com.example.iam.admin.rbac;

public final class AdminPermissions {
    public static final String CLIENT_READ = "admin.client.read";
    public static final String CLIENT_WRITE = "admin.client.write";
    public static final String RESOURCE_READ = "admin.resource.read";
    public static final String RESOURCE_WRITE = "admin.resource.write";
    public static final String SCOPE_READ = "admin.scope.read";
    public static final String SCOPE_WRITE = "admin.scope.write";
    public static final String POLICY_READ = "admin.policy.read";
    public static final String POLICY_WRITE = "admin.policy.write";
    public static final String USER_READ = "admin.user.read";
    public static final String USER_WRITE = "admin.user.write";
    public static final String TOKEN_READ = "admin.token.read";
    public static final String TOKEN_REVOKE = "admin.token.revoke";
    public static final String SESSION_READ = "admin.session.read";
    public static final String SESSION_REVOKE = "admin.session.revoke";
    public static final String EMBED_READ = "admin.embed.read";
    public static final String EMBED_WRITE = "admin.embed.write";
    public static final String AUDIT_READ = "admin.audit.read";
    public static final String KEY_READ = "admin.key.read";
    public static final String KEY_ROTATE = "admin.key.rotate";
    public static final String CONFIG_READ = "admin.config.read";

    private AdminPermissions() {}
}
