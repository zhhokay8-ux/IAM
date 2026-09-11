package com.example.iam.admin.web.user;

import com.fasterxml.jackson.annotation.JsonProperty;

public record AdminCreateUserRequest(
        String username,
        @JsonProperty("display_name") String displayName,
        String email,
        @JsonProperty("tenant_id") String tenantId,
        @JsonProperty("org_id") String orgId,
        String password) {}
