package com.example.iam.common.util;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.UUID;

public final class IdGenerator {

    private static final SecureRandom RANDOM = new SecureRandom();

    private IdGenerator() {
    }

    /**
     * Time-ordered UUID v7-style identifier for subjects, clients, and audit rows.
     */
    public static String next() {
        return uuidV7().toString();
    }

    public static UUID uuidV7() {
        long epochMs = Instant.now().toEpochMilli();
        byte[] random = new byte[10];
        RANDOM.nextBytes(random);

        long msb = (epochMs << 16) | ((random[0] & 0x0F) << 8) | (random[1] & 0xFF);
        msb = (msb & 0xFFFFFFFFFFFF0FFFL) | 0x0000000000007000L;

        long lsb = 0;
        for (int i = 2; i < 10; i++) {
            lsb = (lsb << 8) | (random[i] & 0xFF);
        }
        lsb = (lsb & 0x3FFFFFFFFFFFFFFFL) | 0x8000000000000000L;
        return new UUID(msb, lsb);
    }
}
