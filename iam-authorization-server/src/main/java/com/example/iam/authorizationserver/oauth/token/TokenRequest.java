package com.example.iam.authorizationserver.oauth.token;

public record TokenRequest(
        String grantType,
        String code,
        String redirectUri,
        String codeVerifier,
        String refreshToken,
        String scope,
        String audience,
        String clientId,
        String clientSecret
) {
}
