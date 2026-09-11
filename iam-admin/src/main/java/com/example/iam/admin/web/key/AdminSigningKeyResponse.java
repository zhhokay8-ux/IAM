package com.example.iam.admin.web.key;

import com.example.iam.token.signing.KeyMetadata;
import java.time.Instant;

public record AdminSigningKeyResponse(
        String kid,
        String algorithm,
        String status,
        Instant createdAt,
        Instant expiresAt,
        String kmsKeyId) {

    public static AdminSigningKeyResponse from(KeyMetadata metadata) {
        return new AdminSigningKeyResponse(
                metadata.kid(),
                metadata.algorithm(),
                metadata.status(),
                metadata.createdAt(),
                metadata.retiredAt(),
                metadata.kmsKeyId());
    }
}
