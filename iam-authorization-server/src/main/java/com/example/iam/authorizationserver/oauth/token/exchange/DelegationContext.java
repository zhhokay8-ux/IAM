package com.example.iam.authorizationserver.oauth.token.exchange;

import java.util.List;

public record DelegationContext(
        String subject,
        List<String> audiences,
        List<String> scopes,
        String clientId,
        String tenantId,
        String orgId,
        List<String> roles,
        String jti
) {
}
