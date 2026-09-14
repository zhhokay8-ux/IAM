package com.example.iam.authorizationserver.sso;

import com.fasterxml.jackson.annotation.JsonProperty;

public record SsoCsrfResponse(@JsonProperty("csrf_token") String csrfToken) {}
