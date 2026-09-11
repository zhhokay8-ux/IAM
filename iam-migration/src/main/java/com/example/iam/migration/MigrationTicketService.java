package com.example.iam.migration;

public interface MigrationTicketService {

    CreateMigrationTicketResponse issue(CreateMigrationTicketRequest request);

    MigrationTicket redeem(RedeemMigrationTicketRequest request);
}
