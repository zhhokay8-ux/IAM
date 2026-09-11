package com.example.iam.clientregistry.dto;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonProperty;

public record RedirectUriInput(
        @JsonProperty("redirectUri") @JsonAlias("redirect_uri") String redirectUri,
        @JsonProperty("uriType") @JsonAlias("uri_type") String uriType) {}

