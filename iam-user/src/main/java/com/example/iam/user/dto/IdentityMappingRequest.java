package com.example.iam.user.dto;

public record IdentityMappingRequest(
        String systemCode,
        String externalUserId,
        String externalUsername,
        String mappingStatus
) {
}
