package com.example.iam.token.oauth;

public record AuthorizationCodePayload(
        String clientId,
        String redirectUri,
        String codeChallenge,
        String codeChallengeMethod,
        String subject,
        String scope,
        String nonce,
        String state
) {
}
