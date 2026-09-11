package com.example.iam.clientregistry.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record ClientResponse(
        UUID id,
        String clientId,
        String clientName,
        String clientType,
        String status,
        String tokenEndpointAuthMethod,
        Integer accessTokenTtl,
        Integer refreshTokenTtl,
        Boolean pkceRequired,
        String owner,
        List<RedirectUriInput> redirectUris,
        Instant createdAt,
        Instant updatedAt
) {
}
