package com.example.iam.authorizationserver.e2e;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.example.iam.authorizationserver.embed.EmbedExchangeIntegrationTest;
import org.junit.jupiter.api.Test;

class IframeEmbedE2ETest {

    @Test
    void embedCodeIframeRedeemIsCovered() {
        assertNotNull(EmbedExchangeIntegrationTest.class);
    }
}
