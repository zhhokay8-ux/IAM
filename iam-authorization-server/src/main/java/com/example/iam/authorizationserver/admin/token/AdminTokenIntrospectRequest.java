package com.example.iam.authorizationserver.admin.token;

import com.fasterxml.jackson.annotation.JsonProperty;

public record AdminTokenIntrospectRequest(@JsonProperty("token") String token) {

    @Override
    public String toString() {
        return "AdminTokenIntrospectRequest[token=***]";
    }
}
