package com.example.iam.clientregistry.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record RotatedSecretResponse(
        ClientResponse client, @JsonProperty("client_secret") String clientSecret) {
    @Override
    public String toString() {
        return "RotatedSecretResponse[clientId="
                + (client == null ? null : client.clientId())
                + ", clientSecret=***]";
    }
}
