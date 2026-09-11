package com.example.iam.authorizationserver.oauth.token.exchange;

public record TokenExchangeRequest(
        String grantType,
        String subjectToken,
        String subjectTokenType,
        String requestedTokenType,
        String audience,
        String scope,
        String actorToken,
        String actorTokenType
) {
}
