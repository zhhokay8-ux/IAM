package com.example.iam.resourceserver.jwt;

import java.util.List;

public record ValidatedAccessToken(
        String subject,
        String issuer,
        List<String> audiences,
        String clientId,
        List<String> scopes,
        List<String> roles,
        String tenantId,
        String orgId,
        String jti
) {
}
