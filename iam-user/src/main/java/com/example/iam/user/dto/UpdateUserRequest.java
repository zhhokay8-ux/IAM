package com.example.iam.user.dto;

public record UpdateUserRequest(
        String username,
        String displayName,
        String email,
        String orgId,
        String status
) {
}
