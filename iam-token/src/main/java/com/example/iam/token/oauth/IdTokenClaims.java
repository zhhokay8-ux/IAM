package com.example.iam.token.oauth;

import java.time.Instant;

public record IdTokenClaims(
        String subject,
        String audience,
        Instant issuedAt,
        Instant expiresAt,
        String nonce
) {
}
