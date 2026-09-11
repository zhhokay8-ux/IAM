package com.example.iam.common.error;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

class IamErrorCodeTest {

    @Test
    void codesAreUniqueAndHttpStatusesAreValid() {
        Set<String> codes = new HashSet<>();
        for (IamErrorCode errorCode : IamErrorCode.values()) {
            assertTrue(codes.add(errorCode.getCode()), "duplicate code: " + errorCode.getCode());
            assertTrue(errorCode.getHttpStatus() >= 400 && errorCode.getHttpStatus() < 600);
            assertTrue(errorCode.getMessage() != null && !errorCode.getMessage().isBlank());
        }
        assertEquals("IAM-4000", IamErrorCode.INVALID_ARGUMENT.getCode());
        assertEquals(400, IamErrorCode.INVALID_ARGUMENT.getHttpStatus());
        assertEquals(500, IamErrorCode.INTERNAL_ERROR.getHttpStatus());
        assertNotEquals(IamErrorCode.INVALID_ARGUMENT.getCode(), IamErrorCode.INTERNAL_ERROR.getCode());
    }
}
