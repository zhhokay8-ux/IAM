package com.example.iam.migration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.user.dto.IdentityMappingResponse;
import com.example.iam.user.entity.IamUserEntity;
import com.example.iam.user.service.IamIdentityMappingService;
import com.example.iam.user.service.IamUserService;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class IdentityMappingResolverTest {

    private static final String SUBJECT = "01999a2e-7c3a-7000-8000-000000000086";

    @Mock
    private IamIdentityMappingService mappingService;

    @Mock
    private IamUserService userService;

    private IdentityMappingResolverImpl resolver;

    @BeforeEach
    void setUp() {
        resolver = new IdentityMappingResolverImpl(mappingService, userService);
    }

    @Test
    void resolvesActiveMapping() {
        IdentityMappingResponse mapping = mapping();
        when(mappingService.requireMapping("portal", "zhangsan")).thenReturn(mapping);
        when(userService.requireUser(UUID.fromString(SUBJECT))).thenReturn(new IamUserEntity());
        assertEquals(SUBJECT, resolver.resolve("portal", "zhangsan", null).subjectId());
    }

    @Test
    void mappingMissingPropagates() {
        when(mappingService.requireMapping("portal", "missing"))
                .thenThrow(new IamException(IamErrorCode.MAPPING_NOT_FOUND, "missing"));
        IamException ex = assertThrows(IamException.class, () -> resolver.resolve("portal", "missing", null));
        assertEquals(IamErrorCode.MAPPING_NOT_FOUND, ex.getErrorCode());
    }

    @Test
    void wrongUserIsRejected() {
        when(mappingService.requireMapping("portal", "zhangsan")).thenReturn(mapping());
        when(userService.requireUser(UUID.fromString(SUBJECT))).thenReturn(new IamUserEntity());
        IamException ex = assertThrows(
                IamException.class,
                () -> resolver.resolve("portal", "zhangsan", "01999a2e-7c3a-7000-8000-000000000099"));
        assertEquals(IamErrorCode.MIGRATION_USER_MISMATCH, ex.getErrorCode());
    }

    private static IdentityMappingResponse mapping() {
        return new IdentityMappingResponse(
                UUID.randomUUID(), SUBJECT, "portal", "zhangsan", "zhangsan", "ACTIVE", Instant.parse("2026-09-10T07:00:00Z"));
    }
}
