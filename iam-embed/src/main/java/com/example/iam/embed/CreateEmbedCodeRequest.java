package com.example.iam.embed;

import com.fasterxml.jackson.annotation.JsonProperty;

public record CreateEmbedCodeRequest(
        @JsonProperty("child_client_id") String childClientId,
        @JsonProperty("path") String path,
        @JsonProperty("origin") String origin,
        @JsonProperty("nonce") String nonce
) {
}
