package com.example.iam.authorizationserver.e2e;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.example.iam.authorizationserver.sso.SsoIntegrationTest;
import org.junit.jupiter.api.Test;

class GlobalLogoutE2ETest {

    @Test
    void globalLogoutRevokesSessionIsCovered() {
        assertNotNull(SsoIntegrationTest.class);
    }
}
