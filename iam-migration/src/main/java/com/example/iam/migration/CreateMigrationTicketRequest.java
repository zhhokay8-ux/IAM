package com.example.iam.migration;

public record CreateMigrationTicketRequest(
        String clientId,
        String clientSecret,
        String systemCode,
        String externalUserId,
        String subjectId,
        String browserSession,
        String nonce,
        String returnTo
) {
}
