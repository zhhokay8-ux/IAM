package com.example.iam.migration;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;

public record MigrationTicket(
        @JsonProperty("ticket") String ticket,
        @JsonProperty("client_id") String clientId,
        @JsonProperty("subject_id") String subjectId,
        @JsonProperty("browser_session") String browserSession,
        @JsonProperty("nonce") String nonce,
        @JsonProperty("return_to") String returnTo,
        @JsonProperty("created_at") Instant createdAt,
        @JsonProperty("expires_at") Instant expiresAt
) {
}
