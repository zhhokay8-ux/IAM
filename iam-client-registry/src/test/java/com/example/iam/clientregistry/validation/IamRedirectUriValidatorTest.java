package com.example.iam.clientregistry.validation;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import java.util.List;
import org.junit.jupiter.api.Test;

class IamRedirectUriValidatorTest {

    private final IamRedirectUriValidator validator = new IamRedirectUriValidator();
    private static final String REGISTERED = "https://portal.example.com/login/callback";

    @Test
    void rejectsWildcardRedirectUri() {
        IamException ex = assertThrows(
                IamException.class,
                () -> validator.validateSyntax("https://*.example.com/callback"));
        assertEquals(IamErrorCode.INVALID_REDIRECT_URI, ex.getErrorCode());
    }

    @Test
    void rejectsMismatch() {
        IamException ex = assertThrows(
                IamException.class,
                () -> validator.validateRedirectUri("https://evil.example.com/callback", List.of(REGISTERED)));
        assertEquals(IamErrorCode.REDIRECT_URI_MISMATCH, ex.getErrorCode());
    }

    @Test
    void extraCharacterDoesNotMatch() {
        IamException ex = assertThrows(
                IamException.class,
                () -> validator.validateRedirectUri(REGISTERED + "x", List.of(REGISTERED)));
        assertEquals(IamErrorCode.REDIRECT_URI_MISMATCH, ex.getErrorCode());
    }

    @Test
    void exactMatchSucceeds() {
        assertDoesNotThrow(() -> validator.validateRedirectUri(REGISTERED, List.of(REGISTERED)));
    }

    @Test
    void rejectsOpenRedirectSchemes() {
        IamException ex = assertThrows(
                IamException.class,
                () -> validator.validateSyntax("javascript:alert(1)"));
        assertEquals(IamErrorCode.INVALID_REDIRECT_URI, ex.getErrorCode());
    }

    @Test
    void rejectsUserinfoOpenRedirect() {
        IamException ex = assertThrows(
                IamException.class,
                () -> validator.validateSyntax("https://portal.example.com@evil.example.com/callback"));
        assertEquals(IamErrorCode.INVALID_REDIRECT_URI, ex.getErrorCode());
    }

    @Test
    void rejectsControlCharacters() {
        IamException ex = assertThrows(
                IamException.class,
                () -> validator.validateSyntax("https://portal.example.com/callback\r\n"));
        assertEquals(IamErrorCode.INVALID_REDIRECT_URI, ex.getErrorCode());
    }
}
