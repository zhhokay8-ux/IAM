package com.example.iam.token.signing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.example.iam.token.jwks.JwksService;
import com.example.iam.token.jwks.JwksServiceImpl;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SigningKeyRotationServiceTest {

    private SigningKeyService signingKeyService;
    private SigningKeyRotationService rotationService;
    private JwksService jwksService;
    private JwtSigner signer;

    @BeforeEach
    void setUp() {
        InMemorySigningKeyRepository repository = new InMemorySigningKeyRepository();
        LocalSigningKeySecretStore secretStore = new LocalSigningKeySecretStore();
        signingKeyService = new SigningKeyServiceImpl(repository, secretStore, 2048);
        rotationService = new SigningKeyRotationServiceImpl(signingKeyService, repository, secretStore);
        jwksService = new JwksServiceImpl(repository, secretStore);
        signer = new JwtSignerImpl(signingKeyService, secretStore, new JwtKeyResolverImpl(repository, secretStore));
    }

    @Test
    void rotatePublishesBothKeysThenSignsWithNewKey() throws Exception {
        String keyA = signingKeyService.createActiveKey().kid();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("u-1")
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plusSeconds(60)))
                .build();
        String tokenA = signer.sign(claims).serialize();

        String keyB = rotationService.rotate().kid();
        assertNotEquals(keyA, keyB);
        assertEquals(keyB, signingKeyService.getActiveKey().kid());

        JWKSet published = jwksService.jwks();
        assertEquals(2, published.getKeys().size());
        assertTrue(published.getKeyByKeyId(keyA) != null);
        assertTrue(published.getKeyByKeyId(keyB) != null);

        assertEquals(keyB, signer.sign(claims).getHeader().getKeyID());
        assertEquals("u-1", signer.verify(tokenA).getJWTClaimsSet().getSubject());

        rotationService.retireExpired(Duration.ZERO);
        JWKSet afterRetire = jwksService.jwks();
        assertEquals(1, afterRetire.getKeys().size());
        assertEquals(keyB, afterRetire.getKeys().get(0).getKeyID());
    }
}
