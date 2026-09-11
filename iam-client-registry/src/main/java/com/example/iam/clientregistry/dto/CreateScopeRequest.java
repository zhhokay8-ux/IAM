package com.example.iam.clientregistry.dto;

public record CreateScopeRequest(
        String resourceCode,
        String scopeCode,
        String scopeName,
        String description,
        String status
) {
}
