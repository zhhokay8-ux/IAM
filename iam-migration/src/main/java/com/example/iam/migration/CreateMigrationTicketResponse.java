package com.example.iam.migration;

import java.time.Instant;

public record CreateMigrationTicketResponse(String ticket, Instant expiresAt, String loginPath) {
}
