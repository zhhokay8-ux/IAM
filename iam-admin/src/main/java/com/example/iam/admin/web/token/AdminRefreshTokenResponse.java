package com.example.iam.admin.web.token;

import com.example.iam.token.entity.IamRefreshTokenEntity;
import java.time.Instant;
import java.util.UUID;

public record AdminRefreshTokenResponse(
        UUID id,
        UUID userPk,
        String subjectId,
        UUID clientId,
        UUID familyId,
        Instant issuedAt,
        Instant expiresAt,
        Instant revokedAt,
        String status,
        String scope,
        String audience) {

    public static AdminRefreshTokenResponse from(IamRefreshTokenEntity entity, String jwtSubject) {
        return new AdminRefreshTokenResponse(
                entity.getId(),
                entity.getSubjectId(),
                jwtSubject,
                entity.getClientId(),
                entity.getSessionId(),
                entity.getIssuedAt(),
                entity.getExpiresAt(),
                entity.getRevokedAt(),
                entity.getStatus(),
                entity.getScope(),
                entity.getAudience());
    }
}
