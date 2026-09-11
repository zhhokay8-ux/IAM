package com.example.iam.authorizationserver.admin.auth;

public record AdminOAuthPending(
        String state, String nonce, String codeVerifier, String redirectUri, String clientId) {}
