package com.example.iam.admin.web.client;

import com.example.iam.clientregistry.dto.RedirectUriInput;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public record AdminCreateClientRequest(
        @JsonProperty("client_id") String clientId,
        @JsonProperty("client_name") String clientName,
        @JsonProperty("client_type") String clientType,
        String status,
        @JsonProperty("token_endpoint_auth_method") String tokenEndpointAuthMethod,
        @JsonProperty("access_token_ttl") Integer accessTokenTtl,
        @JsonProperty("refresh_token_ttl") Integer refreshTokenTtl,
        @JsonProperty("pkce_required") Boolean pkceRequired,
        String owner,
        @JsonProperty("redirect_uris") List<RedirectUriInput> redirectUris) {}
