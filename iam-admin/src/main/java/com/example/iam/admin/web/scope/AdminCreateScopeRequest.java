package com.example.iam.admin.web.scope;

import com.fasterxml.jackson.annotation.JsonProperty;

public record AdminCreateScopeRequest(
        @JsonProperty("resource_code") String resourceCode,
        @JsonProperty("scope_code") String scopeCode,
        @JsonProperty("scope_name") String scopeName,
        String description) {}
