package com.example.iam.authorizationserver.oauth;

public record AuthorizationRequest(
        String clientId,
        String redirectUri,
        String responseType,
        String scope,
        String state,
        String nonce,
        String codeChallenge,
        String codeChallengeMethod
) {
}
