package com.example.iam.admin.web.embed;

import com.fasterxml.jackson.annotation.JsonProperty;

public record AdminEmbedPolicyRequest(
        @JsonProperty("parent_client_id") String parentClientId,
        @JsonProperty("child_client_id") String childClientId,
        @JsonProperty("parent_origin") String parentOrigin,
        @JsonProperty("allowed_path") String allowedPath) {}
