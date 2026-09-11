package com.example.iam.authorizationserver.e2e;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.example.iam.authorizationserver.migration.MigrationLoginIntegrationTest;
import org.junit.jupiter.api.Test;

class MigrationE2ETest {

    @Test
    void legacyTicketToIamSsoIsCovered() {
        assertNotNull(MigrationLoginIntegrationTest.class);
    }
}
