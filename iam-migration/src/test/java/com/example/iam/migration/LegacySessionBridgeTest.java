package com.example.iam.migration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.common.util.HashUtils;
import com.example.iam.session.IamSession;
import com.example.iam.user.dto.IdentityMappingResponse;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class LegacySessionBridgeTest {

    @Mock
    private LegacySessionValidator validator;

    @Mock
    private MigrationTicketService ticketService;

    @Mock
    private IdentityMappingResolver mappingResolver;

    private MigrationProperties properties;
    private LegacySessionBridge bridge;
    private CurrentUserResolver currentUserResolver;

    @BeforeEach
    void setUp() {
        properties = new MigrationProperties();
        bridge = new LegacySessionBridge(validator, ticketService, properties);
        currentUserResolver = new CurrentUserResolver(properties, mappingResolver);
    }

    @Test
    void startHashesLegacySessionAndDoesNotPutItInRedirect() {
        when(validator.requireValid("PORTAL_LEGACY_SESSION"))
                .thenReturn(new LegacyPrincipal("portal", "zhangsan", "zhangsan", "t1", List.of("user"), "PORTAL_LEGACY_SESSION"));
        when(ticketService.issue(any()))
                .thenReturn(new CreateMigrationTicketResponse(
                        "t-1", Instant.parse("2026-09-10T07:00:45Z"), "/migration/login?ticket=t-1"));
        CreateMigrationTicketResponse result =
                bridge.start("PORTAL_LEGACY_SESSION", "portal", "nonce", "https://portal.example.com/login/callback");
        assertEquals("/migration/login?ticket=t-1", result.loginPath());
        assertFalse(result.loginPath().contains("PORTAL_LEGACY_SESSION"));
        assertEquals(HashUtils.sha256Hex("PORTAL_LEGACY_SESSION"), CurrentUserResolver.browserBinding("PORTAL_LEGACY_SESSION"));
    }

    @Test
    void dualModePrefersIamSessionForCurrentUser() {
        properties.getMigration().setMode("dual");
        IamSession session = new IamSession(
                "sid", "u-100086", Instant.now(), Instant.now(), Instant.now(), "pwd", "portal", "ACTIVE");
        CurrentUser user = currentUserResolver.resolve(Optional.of(session), Optional.empty());
        assertEquals("u-100086", user.subjectId());
    }

    @Test
    void rollbackUsesLegacyPrincipal() {
        properties.setEnabled(false);
        LegacyPrincipal legacy =
                new LegacyPrincipal("portal", "zhangsan", "zhangsan", "tenant-1", List.of("portal_user"), "sid");
        CurrentUser user = currentUserResolver.fromLegacyOnly(legacy);
        assertEquals("legacy:zhangsan", user.subjectId());
        assertEquals("zhangsan", user.username());
        IamException ex = assertThrows(
                IamException.class,
                () -> bridge.start("PORTAL_LEGACY_SESSION", "portal", "n", "https://portal.example.com/cb"));
        assertEquals(IamErrorCode.MIGRATION_DISABLED, ex.getErrorCode());
    }

    @Test
    void dualModeMapsLegacyUserWhenIamSessionMissing() {
        properties.getMigration().setMode("dual");
        when(mappingResolver.resolve("portal", "zhangsan", null))
                .thenReturn(new IdentityMappingResponse(
                        UUID.randomUUID(),
                        "u-100086",
                        "portal",
                        "zhangsan",
                        "zhangsan",
                        "ACTIVE",
                        Instant.now()));
        CurrentUser user = currentUserResolver.resolve(
                Optional.empty(),
                Optional.of(new LegacyPrincipal("portal", "zhangsan", "zhangsan", "t1", List.of(), "sid")));
        assertEquals("u-100086", user.subjectId());
        assertTrue(properties.legacyLoginEnabled());
        assertTrue(properties.iamLoginEnabled());
    }
}
