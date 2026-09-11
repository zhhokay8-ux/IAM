package com.example.iam.clientregistry.dto;

import java.time.Instant;
import java.util.UUID;

public record PermissionResponse(
        UUID id,
        String clientId,
        String resourceCode,
        String audience,
        String scopeCode,
        String grantType,
        String status,
        Instant createdAt
) {
}
