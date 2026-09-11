package com.example.iam.migration;

import java.util.List;

public record LegacyPrincipal(
        String systemCode,
        String externalUserId,
        String username,
        String tenantId,
        List<String> roles,
        String sessionId
) {
    public LegacyPrincipal {
        roles = roles == null ? List.of() : List.copyOf(roles);
    }
}
