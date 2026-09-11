package com.example.iam.token.signing;

import java.time.Instant;

public record KeyMetadata(
        String kid,
        String algorithm,
        String kmsKeyId,
        String status,
        Instant activatedAt,
        Instant retiredAt,
        Instant createdAt
) {
    @Override
    public String toString() {
        return "KeyMetadata[kid=" + kid + ", algorithm=" + algorithm + ", status=" + status + "]";
    }
}
