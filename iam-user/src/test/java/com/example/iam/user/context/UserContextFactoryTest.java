package com.example.iam.user.context;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.user.domain.UserStatus;
import com.example.iam.user.entity.IamUserEntity;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class UserContextFactoryTest {

    private final UserContextFactory factory = new UserContextFactory();
    private final UUID subjectId = UUID.fromString("01999a2e-7c3a-7000-8000-000000000001");

    @Test
    void tokenContextUsesGeneratedSubjectNotUsernameOrEmail() {
        UserContext context = factory.forToken(user(UserStatus.ACTIVE));
        assertEquals(subjectId.toString(), context.subjectId());
        assertNotEquals(context.username(), context.subjectId());
        assertNotEquals(context.email(), context.subjectId());
    }

    @Test
    void inactiveUserCannotObtainToken() {
        IamException ex = assertThrows(IamException.class, () -> factory.forToken(user(UserStatus.INACTIVE)));
        assertEquals(IamErrorCode.USER_INACTIVE, ex.getErrorCode());
    }

    private IamUserEntity user(String status) {
        return IamUserEntity.builder()
                .subjectId(subjectId)
                .username("zhangsan")
                .email("zhangsan@example.com")
                .status(status)
                .tenantId("tenant_01")
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .build();
    }
}
