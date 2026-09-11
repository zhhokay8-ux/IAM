package com.example.iam.authorizationserver.admin.token;

import com.example.iam.authorizationserver.oauth.introspect.TokenIntrospectionResponse;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record AdminTokenIntrospectResponse(
        boolean active,
        String sub,
        List<String> aud,
        @JsonProperty("client_id") String clientId,
        String scope,
        @JsonProperty("token_type") String tokenType,
        Long exp,
        Long iat,
        String jti,
        String warning) {

    public static final String HIGH_RISK_WARNING =
            "High-risk token operation. Do not persist, log, or copy the presented token.";

    public static AdminTokenIntrospectResponse from(TokenIntrospectionResponse response) {
        return new AdminTokenIntrospectResponse(
                response.active(),
                response.sub(),
                response.aud(),
                response.clientId(),
                response.scope(),
                response.tokenType(),
                response.exp(),
                response.iat(),
                response.jti(),
                HIGH_RISK_WARNING);
    }
}
