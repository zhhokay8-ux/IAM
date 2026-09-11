package com.example.iam.embed;

import java.time.Instant;
import java.util.UUID;

public record EmbedPolicyView(
        UUID id,
        String parentClientId,
        String childClientId,
        String parentOrigin,
        String allowedPath,
        String status,
        Instant createdAt) {}
