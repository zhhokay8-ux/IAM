package com.example.iam.admin.web.session;

import com.example.iam.session.IamSession;
import java.time.Instant;

public record AdminSessionResponse(
        String sid,
        String subjectId,
        Instant createdAt,
        Instant lastAccessAt,
        Instant expiresAt,
        String authenticationLevel,
        String clientId,
        String status) {

    public static AdminSessionResponse from(IamSession session) {
        return new AdminSessionResponse(
                session.sid(),
                session.subjectId(),
                session.createdAt(),
                session.lastAccessAt(),
                session.expiresAt(),
                session.authenticationLevel(),
                session.clientId(),
                session.status());
    }
}
