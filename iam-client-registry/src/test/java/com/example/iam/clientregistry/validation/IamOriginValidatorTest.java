package com.example.iam.clientregistry.validation;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import java.util.List;
import org.junit.jupiter.api.Test;

class IamOriginValidatorTest {

    private final IamOriginValidator validator = new IamOriginValidator();

    @Test
    void rejectsWildcard() {
        IamException ex = assertThrows(IamException.class, () -> validator.validateSyntax("*"));
        assertEquals(IamErrorCode.INVALID_ORIGIN, ex.getErrorCode());
    }

    @Test
    void rejectsOriginNotInAllowlist() {
        IamException ex = assertThrows(
                IamException.class,
                () -> validator.validateOrigin("https://evil.example.com", List.of("https://portal.example.com")));
        assertEquals(IamErrorCode.INVALID_ORIGIN, ex.getErrorCode());
    }

    @Test
    void exactOriginMatchSucceeds() {
        assertDoesNotThrow(() -> validator.validateOrigin(
                "https://portal.example.com", List.of("https://portal.example.com")));
    }
}
