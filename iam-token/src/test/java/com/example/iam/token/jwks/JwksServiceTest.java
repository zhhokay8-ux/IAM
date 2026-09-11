package com.example.iam.token.jwks;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.example.iam.token.signing.InMemorySigningKeyRepository;
import com.example.iam.token.signing.LocalSigningKeySecretStore;
import com.example.iam.token.signing.SigningKeyRotationServiceImpl;
import com.example.iam.token.signing.SigningKeyService;
import com.example.iam.token.signing.SigningKeyServiceImpl;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class JwksServiceTest {

    private SigningKeyService signingKeyService;
    private JwksService jwksService;
    private SigningKeyRotationServiceImpl rotationService;

    @BeforeEach
    void setUp() {
        InMemorySigningKeyRepository repository = new InMemorySigningKeyRepository();
        LocalSigningKeySecretStore secretStore = new LocalSigningKeySecretStore();
        signingKeyService = new SigningKeyServiceImpl(repository, secretStore, 2048);
        jwksService = new JwksServiceImpl(repository, secretStore);
        rotationService = new SigningKeyRotationServiceImpl(signingKeyService, repository, secretStore);
    }

    @Test
    void jwksContainsPublicKeyOnly() {
        String kid = signingKeyService.createActiveKey().kid();
        JWKSet set = jwksService.jwks();
        assertEquals(1, set.getKeys().size());
        JWK jwk = set.getKeyByKeyId(kid);
        assertTrue(jwk instanceof RSAKey);
        RSAKey rsa = (RSAKey) jwk;
        assertEquals("RSA", rsa.getKeyType().getValue());
        assertEquals("sig", rsa.getKeyUse().identifier());
        assertEquals("RS256", rsa.getAlgorithm().getName());
        assertTrue(rsa.toPublicJWK().toJSONString().contains("\"n\""));
        assertFalse(rsa.isPrivate());
        Map<String, Object> json = set.toJSONObject(false);
        String body = json.toString();
        assertFalse(body.contains("\"d\""));
        assertFalse(body.contains("BEGIN"));
        assertFalse(body.toLowerCase().contains("private"));
    }

    @Test
    void rotationPublishesPreviousAndCurrentPublicKeys() {
        String first = signingKeyService.createActiveKey().kid();
        String second = rotationService.rotate().kid();
        JWKSet set = jwksService.jwks();
        assertEquals(2, set.getKeys().size());
        assertTrue(set.getKeyByKeyId(first) != null);
        assertTrue(set.getKeyByKeyId(second) != null);
        set.getKeys().forEach(key -> assertFalse(key.isPrivate()));
    }
}
