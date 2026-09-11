package com.example.iam.user.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.user.domain.UserStatus;
import com.example.iam.user.dto.IdentityMappingRequest;
import com.example.iam.user.entity.IamUserEntity;
import com.example.iam.user.repository.IamUserIdentityMappingRepository;
import com.example.iam.user.service.impl.IamIdentityMappingServiceImpl;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class IamIdentityMappingServiceTest {

    @Mock
    private IamUserIdentityMappingRepository mappingRepository;

    @Mock
    private IamUserService userService;

    private IamIdentityMappingService service;
    private UUID subjectId;
    private IamUserEntity user;

    @BeforeEach
    void setUp() {
        service = new IamIdentityMappingServiceImpl(mappingRepository, userService);
        subjectId = UUID.fromString("01999a2e-7c3a-7000-8000-000000000001");
        user = IamUserEntity.builder()
                .id(UUID.randomUUID())
                .subjectId(subjectId)
                .username("zhangsan")
                .status(UserStatus.ACTIVE)
                .tenantId("tenant_01")
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .build();
    }

    @Test
    void rejectsDuplicateSystemAndExternalUserId() {
        when(userService.requireUser(subjectId)).thenReturn(user);
        when(mappingRepository.existsBySystemCodeAndExternalUserId("SYSTEM_1", "E88271")).thenReturn(true);

        IamException ex = assertThrows(
                IamException.class,
                () -> service.create(subjectId, new IdentityMappingRequest("SYSTEM_1", "E88271", "zhangsan", "ACTIVE")));
        assertEquals(IamErrorCode.DUPLICATE_IDENTITY_MAPPING, ex.getErrorCode());
    }

    @Test
    void missingMappingReturnsExplicitError() {
        when(mappingRepository.findBySystemCodeAndExternalUserId("SYSTEM_1", "missing")).thenReturn(Optional.empty());
        IamException ex = assertThrows(
                IamException.class, () -> service.requireMapping("SYSTEM_1", "missing"));
        assertEquals(IamErrorCode.MAPPING_NOT_FOUND, ex.getErrorCode());
    }

    @Test
    void createHappyPath() {
        when(userService.requireUser(subjectId)).thenReturn(user);
        when(mappingRepository.existsBySystemCodeAndExternalUserId("SYSTEM_1", "E88271")).thenReturn(false);
        when(mappingRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        var response = service.create(
                subjectId, new IdentityMappingRequest("SYSTEM_1", "E88271", "zhangsan", "ACTIVE"));
        assertEquals(subjectId.toString(), response.subjectId());
        assertEquals("SYSTEM_1", response.systemCode());
        assertEquals("E88271", response.externalUserId());
    }

    @Test
    void updateRejectsDuplicatePair() {
        UUID mappingId = UUID.randomUUID();
        var existing = com.example.iam.user.entity.IamUserIdentityMappingEntity.builder()
                .id(mappingId)
                .subjectId(subjectId)
                .systemCode("SYSTEM_1")
                .externalUserId("OLD")
                .mappingStatus(UserStatus.ACTIVE)
                .createdAt(Instant.now())
                .build();
        when(mappingRepository.findById(mappingId)).thenReturn(Optional.of(existing));
        when(mappingRepository.findBySystemCodeAndExternalUserId("SYSTEM_1", "E88271"))
                .thenReturn(Optional.of(com.example.iam.user.entity.IamUserIdentityMappingEntity.builder()
                        .id(UUID.randomUUID())
                        .subjectId(UUID.randomUUID())
                        .systemCode("SYSTEM_1")
                        .externalUserId("E88271")
                        .build()));
        IamException ex = assertThrows(
                IamException.class,
                () -> service.update(mappingId, new IdentityMappingRequest("SYSTEM_1", "E88271", "x", "ACTIVE")));
        assertEquals(IamErrorCode.DUPLICATE_IDENTITY_MAPPING, ex.getErrorCode());
    }

    @Test
    void deleteMissingMapping() {
        UUID mappingId = UUID.randomUUID();
        when(mappingRepository.findById(mappingId)).thenReturn(Optional.empty());
        IamException ex = assertThrows(IamException.class, () -> service.delete(mappingId));
        assertEquals(IamErrorCode.MAPPING_NOT_FOUND, ex.getErrorCode());
    }
}
