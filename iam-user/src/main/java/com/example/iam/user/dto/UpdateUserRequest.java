package com.example.iam.user.dto;

public record UpdateUserRequest(
        String username,
        String displayName,
        String email,
        String orgId,
        String status,
        String password
) {
    public UpdateUserRequest(String username, String displayName, String email, String orgId, String status) {
        this(username, displayName, email, orgId, status, null);
    }
}
