package com.example.iam.user.dto;

public record CreateUserRequest(
        String username,
        String displayName,
        String email,
        String tenantId,
        String orgId,
        String status,
        String password
) {
    public CreateUserRequest(
            String username,
            String displayName,
            String email,
            String tenantId,
            String orgId,
            String status) {
        this(username, displayName, email, tenantId, orgId, status, null);
    }
}
