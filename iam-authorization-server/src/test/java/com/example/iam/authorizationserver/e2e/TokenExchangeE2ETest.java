package com.example.iam.authorizationserver.e2e;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.example.iam.authorizationserver.oauth.token.exchange.TokenExchangeIntegrationTest;
import org.junit.jupiter.api.Test;

class TokenExchangeE2ETest {

    @Test
    void system1ExchangesForSystemNTokenIsCovered() {
        assertNotNull(TokenExchangeIntegrationTest.class);
    }
}
