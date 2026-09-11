package com.example.iam.session;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;

public record IamSession(
        @JsonProperty("sid") String sid,
        @JsonProperty("subject_id") String subjectId,
        @JsonProperty("created_at") Instant createdAt,
        @JsonProperty("last_access_at") Instant lastAccessAt,
        @JsonProperty("expires_at") Instant expiresAt,
        @JsonProperty("authentication_level") String authenticationLevel,
        @JsonProperty("client_id") String clientId,
        @JsonProperty("status") String status
) {
    public static final String STATUS_ACTIVE = "ACTIVE";
    public static final String STATUS_REVOKED = "REVOKED";

    public IamSession withLastAccessAt(Instant lastAccessAt) {
        return new IamSession(
                sid, subjectId, createdAt, lastAccessAt, expiresAt, authenticationLevel, clientId, status);
    }

    public IamSession withStatus(String status) {
        return new IamSession(
                sid, subjectId, createdAt, lastAccessAt, expiresAt, authenticationLevel, clientId, status);
    }

    public IamSession withExpiresAt(Instant expiresAt) {
        return new IamSession(
                sid, subjectId, createdAt, lastAccessAt, expiresAt, authenticationLevel, clientId, status);
    }
}
