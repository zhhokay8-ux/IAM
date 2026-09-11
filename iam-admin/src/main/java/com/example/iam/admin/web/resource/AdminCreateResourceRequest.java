package com.example.iam.admin.web.resource;

import com.fasterxml.jackson.annotation.JsonProperty;

public record AdminCreateResourceRequest(
        @JsonProperty("resource_code") String resourceCode,
        @JsonProperty("resource_name") String resourceName,
        String audience,
        String owner) {}
