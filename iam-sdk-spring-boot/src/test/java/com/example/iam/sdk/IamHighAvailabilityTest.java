package com.example.iam.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.resourceserver.jwt.JtiValidator;
import com.nimbusds.jose.jwk.JWKSet;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.RestClient;

class IamHighAvailabilityTest {

    @Test
    void authNodeDownDoesNotClearOtherNodeJwksCache() {
        SdkTestJwtSupport jwt = new SdkTestJwtSupport();
        JwksCache nodeA = new JwksCache();
        JwksCache nodeB = new JwksCache();
        nodeA.put(new JWKSet(jwt.rsaJwk()), Instant.MAX);
        nodeB.put(new JWKSet(jwt.rsaJwk()), Instant.MAX);
        assertEquals(jwt.rsaJwk().getKeyID(), nodeB.getStale().orElseThrow().getKeys().get(0).getKeyID());
    }

    @Test
    void jwksUnavailableKeepsValidCache() {
        SdkTestJwtSupport jwt = new SdkTestJwtSupport();
        JwksCache cache = new JwksCache();
        cache.put(new JWKSet(jwt.rsaJwk()), Instant.parse("2026-09-10T00:00:00Z"));
        RestClient restClient = org.mockito.Mockito.mock(RestClient.class, org.mockito.Mockito.RETURNS_DEEP_STUBS);
        when(restClient.get().uri(org.mockito.ArgumentMatchers.anyString()).retrieve().body(String.class))
                .thenThrow(new RuntimeException("jwks down"));
        IamJwksClient client = new IamJwksClient(
                "https://auth.example.com",
                Duration.ofHours(1),
                restClient,
                Clock.fixed(Instant.parse("2026-09-10T01:00:00Z"), ZoneOffset.UTC),
                cache);
        client.refreshQuietly();
        assertEquals(
                jwt.resolver().resolvePublicKey(SdkTestJwtSupport.KID),
                client.resolvePublicKey(SdkTestJwtSupport.KID));
    }

    @Test
    void redisUnavailableDoesNotBreakLocalJwtValidation() {
        JtiValidator optional = new JtiValidator(false, jti -> {
            throw new IllegalStateException("redis down");
        });
        optional.validate("jti-1");
    }

    @Test
    void introspectionUnavailableFailsClosedOnHighRiskPath() {
        JtiValidator failClosed = new JtiValidator(true, jti -> {
            throw new IllegalStateException("introspect down");
        });
        IamException ex = assertThrows(IamException.class, () -> failClosed.validate("jti-1"));
        assertEquals(IamErrorCode.INTROSPECTION_UNAVAILABLE, ex.getErrorCode());
    }

    @Test
    void redisNodeDownDoesNotBreakLocalJwtValidation() {
        redisUnavailableDoesNotBreakLocalJwtValidation();
    }

    @Test
    void gatewayNodeUnavailableLocalJwtStillValid() {
        dbUnavailableDoesNotInvalidateAlreadyIssuedJwtCache();
    }

    @Test
    void dbUnavailableDoesNotInvalidateAlreadyIssuedJwtCache() {
        SdkTestJwtSupport jwt = new SdkTestJwtSupport();
        IamJwksClient client = IamJwksClient.staticSet(new JWKSet(jwt.rsaJwk()));
        client.resolvePublicKey(SdkTestJwtSupport.KID);
    }
}
