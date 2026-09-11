package com.example.iam.embed;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;

public record EmbedContext(
        @JsonProperty("code") String code,
        @JsonProperty("parent_client_id") String parentClientId,
        @JsonProperty("child_client_id") String childClientId,
        @JsonProperty("subject_id") String subjectId,
        @JsonProperty("session_id") String sessionId,
        @JsonProperty("nonce") String nonce,
        @JsonProperty("origin") String origin,
        @JsonProperty("allowed_path") String allowedPath,
        @JsonProperty("created_at") Instant createdAt,
        @JsonProperty("expires_at") Instant expiresAt
) {
}
