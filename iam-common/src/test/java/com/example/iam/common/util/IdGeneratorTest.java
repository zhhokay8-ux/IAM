package com.example.iam.common.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class IdGeneratorTest {

    @Test
    void nextReturnsUniqueUuidV7() {
        String first = IdGenerator.next();
        String second = IdGenerator.next();
        assertNotEquals(first, second);
        UUID parsed = UUID.fromString(first);
        assertEquals(7, parsed.version());
        assertEquals(2, parsed.variant());
    }
}
