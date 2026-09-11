package com.example.iam.embed;

import com.fasterxml.jackson.annotation.JsonProperty;

public record ExchangeEmbedCodeRequest(
        @JsonProperty("code") String code,
        @JsonProperty("origin") String origin,
        @JsonProperty("nonce") String nonce,
        @JsonProperty("session_id") String sessionId
) {
}
