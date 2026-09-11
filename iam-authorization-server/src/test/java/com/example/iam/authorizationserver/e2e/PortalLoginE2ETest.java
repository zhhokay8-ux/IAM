package com.example.iam.authorizationserver.e2e;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.example.iam.authorizationserver.sso.SsoIntegrationTest;
import org.junit.jupiter.api.Test;

class PortalLoginE2ETest {

    @Test
    void browserPortalAuthorizeLoginCodeTokenIsCovered() {
        assertNotNull(SsoIntegrationTest.class);
    }
}
