package com.example.iam.clientregistry.dto;

public record UpdateResourceRequest(
        String resourceName,
        String audience,
        String status,
        String owner
) {
}
