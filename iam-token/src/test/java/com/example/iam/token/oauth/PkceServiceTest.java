package com.example.iam.token.oauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.token.redis.PkceStateRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class PkceServiceTest {

    private static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    @Mock
    private PkceStateRepository repository;

    private PkceService service;

    @BeforeEach
    void setUp() {
        service = new PkceServiceImpl(repository);
    }

    @Test
    void rejectsPlainPkce() {
        IamException ex = assertThrows(IamException.class, () -> service.requireS256("plain"));
        assertEquals(IamErrorCode.INVALID_PKCE, ex.getErrorCode());
    }

    @Test
    void rejectsInvalidChallengeCharacters() {
        IamException ex = assertThrows(IamException.class, () -> service.requireValidChallenge("!!!!not-a-challenge!!!!not-a-challenge!!!!"));
        assertEquals(IamErrorCode.INVALID_PKCE, ex.getErrorCode());
    }

    @Test
    void computesS256Challenge() {
        assertEquals(CHALLENGE, service.challengeS256(VERIFIER));
        assertTrue(service.matches(VERIFIER, CHALLENGE));
    }
}
