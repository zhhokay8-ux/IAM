package com.example.iam.clientregistry.dto;

import java.util.List;

public record UpdateClientRequest(
        String clientName,
        String status,
        String tokenEndpointAuthMethod,
        Integer accessTokenTtl,
        Integer refreshTokenTtl,
        Boolean pkceRequired,
        String owner,
        List<RedirectUriInput> redirectUris
) {
}
