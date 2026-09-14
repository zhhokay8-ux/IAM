package com.example.iam.user.password;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class IamPasswordHasherTest {

    private final IamPasswordHasher hasher = new IamPasswordHasher();

    @Test
    void hashedPasswordMatchesAndWrongPasswordDoesNot() {
        String hash = hasher.hash("ChangeMe123!");
        assertTrue(hasher.matches("ChangeMe123!", hash));
        assertFalse(hasher.matches("wrong-pass", hash));
        assertFalse(hasher.matches("ChangeMe123!", null));
        assertFalse(hasher.matches("ChangeMe123!", ""));
    }

    @Test
    void seedBcryptHashIsAccepted() {
        assertTrue(hasher.matches(
                "ChangeMe123!", "$2b$10$UpRyCdJvQ06gk7wF12e3E.xifGdtQuDQKHQ5QIMmwYHRTNBihRdzu"));
    }
}
