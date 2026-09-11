package com.example.iam.admin.web.user;

import com.fasterxml.jackson.annotation.JsonProperty;

public record AdminUpdateUserRequest(
        String username,
        @JsonProperty("display_name") String displayName,
        String email,
        @JsonProperty("org_id") String orgId) {}
