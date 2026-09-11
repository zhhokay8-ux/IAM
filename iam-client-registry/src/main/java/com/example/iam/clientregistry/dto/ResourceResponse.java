package com.example.iam.clientregistry.dto;

import java.time.Instant;
import java.util.UUID;

public record ResourceResponse(
        UUID id,
        String resourceCode,
        String resourceName,
        String audience,
        String status,
        String owner,
        Instant createdAt
) {
}
