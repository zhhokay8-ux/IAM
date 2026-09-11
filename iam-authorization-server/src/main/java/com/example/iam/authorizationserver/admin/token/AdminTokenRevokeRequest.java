package com.example.iam.authorizationserver.admin.token;

import com.fasterxml.jackson.annotation.JsonProperty;

public record AdminTokenRevokeRequest(
        @JsonProperty("token") String token, @JsonProperty("token_type_hint") String tokenTypeHint) {

    @Override
    public String toString() {
        return "AdminTokenRevokeRequest[token=***, tokenTypeHint=" + tokenTypeHint + "]";
    }
}
