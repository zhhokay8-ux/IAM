package com.example.iam.user.dto;

import java.time.Instant;
import java.util.UUID;

public record IdentityMappingResponse(
        UUID id,
        String subjectId,
        String systemCode,
        String externalUserId,
        String externalUsername,
        String mappingStatus,
        Instant createdAt
) {
}
