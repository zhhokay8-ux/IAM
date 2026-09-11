package com.example.iam.authorizationserver.oauth.introspect;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record TokenIntrospectionResponse(
        boolean active,
        String sub,
        List<String> aud,
        @JsonProperty("client_id") String clientId,
        String scope,
        @JsonProperty("token_type") String tokenType,
        Long exp,
        Long iat,
        String jti
) {
    public static TokenIntrospectionResponse inactive() {
        return new TokenIntrospectionResponse(false, null, null, null, null, null, null, null, null);
    }
}
