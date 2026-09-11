package com.example.iam.user.dto;

import java.time.Instant;
import java.util.UUID;

public record UserResponse(
        UUID id,
        String subjectId,
        String username,
        String displayName,
        String email,
        String status,
        String tenantId,
        String orgId,
        Instant createdAt,
        Instant updatedAt
) {
}
