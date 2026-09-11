package com.example.iam.authorizationserver.sso;

import com.example.iam.session.IamSession;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;

public record SsoSessionResponse(
        @JsonProperty("sid") String sid,
        @JsonProperty("subject_id") String subjectId,
        @JsonProperty("client_id") String clientId,
        @JsonProperty("authentication_level") String authenticationLevel,
        @JsonProperty("created_at") Instant createdAt,
        @JsonProperty("last_access_at") Instant lastAccessAt,
        @JsonProperty("expires_at") Instant expiresAt,
        @JsonProperty("status") String status
) {
    public static SsoSessionResponse from(IamSession session) {
        return new SsoSessionResponse(
                session.sid(),
                session.subjectId(),
                session.clientId(),
                session.authenticationLevel(),
                session.createdAt(),
                session.lastAccessAt(),
                session.expiresAt(),
                session.status());
    }
}
