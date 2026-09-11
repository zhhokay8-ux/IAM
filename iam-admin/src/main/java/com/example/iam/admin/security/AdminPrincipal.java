package com.example.iam.admin.security;

import java.util.Set;
import java.util.UUID;

public record AdminPrincipal(
        UUID subjectId,
        String username,
        String tenantId,
        Set<String> roles,
        Set<String> permissions,
        AuthMethod authMethod) {

    public enum AuthMethod {
        COOKIE,
        BEARER,
        LEGACY
    }

    public boolean hasRole(String roleCode) {
        return roles != null && roles.contains(roleCode);
    }

    public boolean hasPermission(String permission) {
        return permissions != null && permissions.contains(permission);
    }

    public boolean hasAnyAdminRole() {
        return roles != null && !roles.isEmpty();
    }
}
