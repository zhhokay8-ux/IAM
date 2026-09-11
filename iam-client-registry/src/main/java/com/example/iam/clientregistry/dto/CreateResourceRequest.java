package com.example.iam.clientregistry.dto;

public record CreateResourceRequest(
        String resourceCode,
        String resourceName,
        String audience,
        String status,
        String owner
) {
}
