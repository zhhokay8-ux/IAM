package com.example.iam.migration;

public record RedeemMigrationTicketRequest(
        String ticket,
        String clientId,
        String subjectId,
        String browserSession,
        String nonce
) {
}
