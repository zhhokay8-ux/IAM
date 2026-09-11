package com.example.iam.user.context;

public record UserContext(
        String subjectId,
        String username,
        String displayName,
        String email,
        String tenantId,
        String orgId,
        String status
) {
}
