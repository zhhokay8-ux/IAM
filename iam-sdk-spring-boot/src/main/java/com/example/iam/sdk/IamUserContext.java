package com.example.iam.sdk;

import java.util.List;

public final class IamUserContext {

    private final String subject;
    private final String username;
    private final String tenantId;
    private final String orgId;
    private final List<String> roles;
    private final List<String> scopes;
    private final String clientId;

    public IamUserContext(
            String subject,
            String username,
            String tenantId,
            String orgId,
            List<String> roles,
            List<String> scopes,
            String clientId) {
        this.subject = subject;
        this.username = username;
        this.tenantId = tenantId;
        this.orgId = orgId;
        this.roles = roles == null ? List.of() : List.copyOf(roles);
        this.scopes = scopes == null ? List.of() : List.copyOf(scopes);
        this.clientId = clientId;
    }

    public String getSubject() {
        return subject;
    }

    public String getUsername() {
        return username;
    }

    public String getTenantId() {
        return tenantId;
    }

    public String getOrgId() {
        return orgId;
    }

    public List<String> getRoles() {
        return roles;
    }

    public List<String> getScopes() {
        return scopes;
    }

    public String getClientId() {
        return clientId;
    }
}
