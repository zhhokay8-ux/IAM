package com.example.iam.user.subject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.UUID;
import org.junit.jupiter.api.Test;

class UserSubjectGeneratorTest {

    private final UserSubjectGenerator generator = new UserSubjectGenerator();

    @Test
    void generatesImmutableUuidV7IndependentOfUsername() {
        UUID first = generator.next();
        UUID second = generator.next();
        assertNotNull(first);
        assertNotEquals(first, second);
        assertEquals(7, first.version());
        assertNotEquals("zhangsan", first.toString());
        assertNotEquals("user@example.com", first.toString());
    }
}
