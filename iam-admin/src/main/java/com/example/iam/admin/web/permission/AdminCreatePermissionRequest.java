package com.example.iam.admin.web.permission;

import com.fasterxml.jackson.annotation.JsonProperty;

public record AdminCreatePermissionRequest(
        @JsonProperty("client_id") String clientId,
        @JsonProperty("resource_code") String resourceCode,
        @JsonProperty("scope_code") String scopeCode,
        @JsonProperty("grant_type") String grantType) {}
