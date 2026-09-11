package com.example.iam.user.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.user.context.UserContextFactory;
import com.example.iam.user.domain.UserStatus;
import com.example.iam.user.dto.CreateUserRequest;
import com.example.iam.user.dto.UpdateUserRequest;
import com.example.iam.user.entity.IamUserEntity;
import com.example.iam.user.repository.IamUserRepository;
import com.example.iam.user.service.impl.IamUserServiceImpl;
import com.example.iam.user.subject.UserSubjectGenerator;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class IamUserServiceTest {

    @Mock
    private IamUserRepository userRepository;

    @Mock
    private UserSubjectGenerator subjectGenerator;

    private IamUserService service;
    private UUID subjectId;

    @BeforeEach
    void setUp() {
        service = new IamUserServiceImpl(userRepository, subjectGenerator, new UserContextFactory());
        subjectId = UUID.fromString("01999a2e-7c3a-7000-8000-000000000001");
    }

    @Test
    void createGeneratesSubjectIndependentOfUsername() {
        when(subjectGenerator.next()).thenReturn(subjectId);
        when(userRepository.existsByUsernameAndTenantId("zhangsan", "tenant_01")).thenReturn(false);
        when(userRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        var created = service.create(new CreateUserRequest(
                "zhangsan", "Zhang", "zhangsan@example.com", "tenant_01", "org_1", "ACTIVE"));

        assertEquals(subjectId.toString(), created.subjectId());
        assertNotEquals("zhangsan", created.subjectId());
        assertNotEquals("zhangsan@example.com", created.subjectId());
    }

    @Test
    void duplicateUsernameInTenantIsRejected() {
        when(userRepository.existsByUsernameAndTenantId("zhangsan", "tenant_01")).thenReturn(true);
        IamException ex = assertThrows(
                IamException.class,
                () -> service.create(new CreateUserRequest(
                        "zhangsan", "Zhang", "zhangsan@example.com", "tenant_01", "org_1", "ACTIVE")));
        assertEquals(IamErrorCode.DUPLICATE_USERNAME, ex.getErrorCode());
    }

    @Test
    void usernameAndEmailCanChangeWithoutChangingSubject() {
        IamUserEntity entity = user(UserStatus.ACTIVE);
        when(userRepository.findBySubjectId(subjectId)).thenReturn(Optional.of(entity));
        when(userRepository.findByUsernameAndTenantId("lisi", "tenant_01")).thenReturn(Optional.empty());
        when(userRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        var updated = service.update(subjectId, new UpdateUserRequest(
                "lisi", "Li", "lisi@example.com", "org_2", null));

        assertEquals(subjectId.toString(), updated.subjectId());
        assertEquals("lisi", updated.username());
        assertEquals("lisi@example.com", updated.email());
    }

    @Test
    void inactiveUserCannotObtainToken() {
        when(userRepository.findBySubjectId(subjectId)).thenReturn(Optional.of(user(UserStatus.INACTIVE)));
        IamException ex = assertThrows(IamException.class, () -> service.requireActiveForToken(subjectId));
        assertEquals(IamErrorCode.USER_INACTIVE, ex.getErrorCode());
    }

    @Test
    void disableSetsInactive() {
        IamUserEntity entity = user(UserStatus.ACTIVE);
        when(userRepository.findBySubjectId(subjectId)).thenReturn(Optional.of(entity));
        when(userRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));
        assertEquals(UserStatus.INACTIVE, service.disable(subjectId).status());
    }

    private IamUserEntity user(String status) {
        return IamUserEntity.builder()
                .id(UUID.randomUUID())
                .subjectId(subjectId)
                .username("zhangsan")
                .email("zhangsan@example.com")
                .status(status)
                .tenantId("tenant_01")
                .orgId("org_1")
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .build();
    }
}
