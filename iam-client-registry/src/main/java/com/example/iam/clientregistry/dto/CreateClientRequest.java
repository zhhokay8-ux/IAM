package com.example.iam.clientregistry.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public record CreateClientRequest(
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
        @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
        String clientSecret
) {
    @Override
    public String toString() {
        return "CreateClientRequest[clientId=" + clientId
                + ", clientName=" + clientName
                + ", clientType=" + clientType
                + ", status=" + status
                + ", pkceRequired=" + pkceRequired
                + ", clientSecret=***]";
    }
}
