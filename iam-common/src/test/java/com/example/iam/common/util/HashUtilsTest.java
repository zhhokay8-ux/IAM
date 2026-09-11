package com.example.iam.common.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class HashUtilsTest {

    @Test
    void sha256HexIsStableAndLowercase() {
        String hash = HashUtils.sha256Hex("refresh-token");
        assertEquals(64, hash.length());
        assertEquals(hash, HashUtils.sha256Hex("refresh-token"));
        assertEquals(hash.toLowerCase(), hash);
        assertNotEquals(hash, HashUtils.sha256Hex("other"));
    }

    @Test
    void sha256HexRejectsNull() {
        assertThrows(NullPointerException.class, () -> HashUtils.sha256Hex((String) null));
    }
}
