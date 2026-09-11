package com.example.iam.token.oauth;

import java.time.Instant;
import java.util.List;

public record AccessTokenClaims(
        String subject,
        List<String> audiences,
        String clientId,
        String scope,
        List<String> roles,
        String tenantId,
        String orgId,
        Instant issuedAt,
        Instant expiresAt,
        String jti,
        String actSub,
        String tokenUse
) {
}
