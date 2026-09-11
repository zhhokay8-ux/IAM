package com.example.iam.admin.web.resource;

import com.fasterxml.jackson.annotation.JsonProperty;

public record AdminUpdateResourceRequest(
        @JsonProperty("resource_name") String resourceName, String audience, String owner) {}
