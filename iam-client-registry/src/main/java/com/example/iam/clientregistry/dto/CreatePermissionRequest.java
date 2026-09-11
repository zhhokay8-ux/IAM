package com.example.iam.clientregistry.dto;

public record CreatePermissionRequest(
        String clientId,
        String resourceCode,
        String scopeCode,
        String grantType,
        String status
) {
}
