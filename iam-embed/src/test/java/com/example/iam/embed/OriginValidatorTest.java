package com.example.iam.embed;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.example.iam.clientregistry.validation.IamOriginValidator;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class OriginValidatorTest {

    private OriginValidator validator;

    @BeforeEach
    void setUp() {
        validator = new OriginValidator(new IamOriginValidator());
    }

    @Test
    void rejectsWildcard() {
        IamException ex = assertThrows(IamException.class, () -> validator.requireExplicitOrigin("*"));
        assertEquals(IamErrorCode.INVALID_ORIGIN, ex.getErrorCode());
    }

    @Test
    void rejectsWildcardInHost() {
        IamException ex = assertThrows(
                IamException.class, () -> validator.requireExplicitOrigin("https://*.example.com"));
        assertEquals(IamErrorCode.INVALID_ORIGIN, ex.getErrorCode());
    }

    @Test
    void matchingOriginSucceeds() {
        assertDoesNotThrow(() -> validator.requireMatch("https://portal.example.com", "https://portal.example.com"));
    }

    @Test
    void mismatchedOriginFails() {
        IamException ex = assertThrows(
                IamException.class,
                () -> validator.requireMatch("https://evil.example.com", "https://portal.example.com"));
        assertEquals(IamErrorCode.INVALID_ORIGIN, ex.getErrorCode());
    }
}
