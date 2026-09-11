package com.example.iam.user.dto;

public record CreateUserRequest(
        String username,
        String displayName,
        String email,
        String tenantId,
        String orgId,
        String status
) {
}
