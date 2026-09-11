package com.example.iam.clientregistry.dto;

import java.util.UUID;

public record ScopeResponse(
        UUID id,
        UUID resourceId,
        String resourceCode,
        String scopeCode,
        String scopeName,
        String description,
        String status
) {
}
