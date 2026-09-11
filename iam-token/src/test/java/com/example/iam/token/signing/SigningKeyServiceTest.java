package com.example.iam.token.signing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SigningKeyServiceTest {

    private SigningKeyService service;

    @BeforeEach
    void setUp() {
        service = new SigningKeyServiceImpl(new InMemorySigningKeyRepository(), new LocalSigningKeySecretStore(), 2048);
    }

    @Test
    void createActiveKeyStoresOnlyMetadata() {
        KeyMetadata metadata = service.createActiveKey();
        assertNotNull(metadata.kid());
        assertTrue(metadata.kid().startsWith("iam-key-"));
        assertEquals(SigningKeyServiceImpl.ALGORITHM, metadata.algorithm());
        assertEquals(SigningKeyStatus.ACTIVE, metadata.status());
        assertTrue(metadata.kmsKeyId().startsWith("local:"));
        String rendered = metadata.toString();
        assertFalse(rendered.contains("BEGIN"));
        assertFalse(rendered.toLowerCase().contains("private"));
    }
}
