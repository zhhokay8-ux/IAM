package com.example.iam.embed;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;

public record CreateEmbedCodeResponse(
        @JsonProperty("code") String code,
        @JsonProperty("expires_at") Instant expiresAt,
        @JsonProperty("child_client_id") String childClientId,
        @JsonProperty("path") String path,
        @JsonProperty("nonce") String nonce
) {
}
