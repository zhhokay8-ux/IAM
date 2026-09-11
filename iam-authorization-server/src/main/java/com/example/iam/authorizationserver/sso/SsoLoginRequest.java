package com.example.iam.authorizationserver.sso;

import com.fasterxml.jackson.annotation.JsonProperty;

public record SsoLoginRequest(
        @JsonProperty("username") String username,
        @JsonProperty("tenant_id") String tenantId,
        @JsonProperty("client_id") String clientId
) {
}
