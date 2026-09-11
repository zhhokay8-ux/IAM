package com.example.iam.admin.web.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.iam.admin.rbac.AdminPermissions;
import com.example.iam.admin.rbac.AdminRoles;
import com.example.iam.admin.security.AdminAuthenticationFilter;
import com.example.iam.admin.security.AdminAuthenticationService;
import com.example.iam.admin.security.AdminAuthorizationInterceptor;
import com.example.iam.admin.security.AdminPrincipal;
import com.example.iam.admin.web.AdminSecurityProbeController;
import com.example.iam.admin.web.client.AdminClientController;
import com.example.iam.admin.web.permission.AdminPermissionController;
import com.example.iam.admin.web.resource.AdminResourceController;
import com.example.iam.admin.web.scope.AdminScopeController;
import com.example.iam.admin.web.session.AdminSessionController;
import com.example.iam.admin.web.token.AdminRefreshTokenController;
import com.example.iam.admin.web.token.AdminRefreshTokenResponse;
import com.example.iam.admin.web.token.AdminRefreshTokenService;
import com.example.iam.admin.web.user.AdminIdentityMappingController;
import com.example.iam.admin.web.user.AdminUserController;
import com.example.iam.admin.web.user.AdminUserLifecycleService;
import com.example.iam.audit.AuditEvent;
import com.example.iam.audit.IamAuditService;
import com.example.iam.clientregistry.dto.ClientResponse;
import com.example.iam.clientregistry.dto.PermissionResponse;
import com.example.iam.clientregistry.dto.ResourceResponse;
import com.example.iam.clientregistry.dto.ScopeResponse;
import com.example.iam.clientregistry.service.IamClientService;
import com.example.iam.clientregistry.service.IamPermissionService;
import com.example.iam.clientregistry.service.IamResourceService;
import com.example.iam.clientregistry.service.IamScopeService;
import com.example.iam.common.web.GlobalExceptionHandler;
import com.example.iam.session.IamSession;
import com.example.iam.session.IamSessionService;
import com.example.iam.user.dto.IdentityMappingResponse;
import com.example.iam.user.dto.UserResponse;
import com.example.iam.user.service.IamIdentityMappingService;
import com.example.iam.user.service.IamUserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

@ExtendWith(MockitoExtension.class)
class AdminAuditWriteCoverageMvcTest {

    @Mock
    private AdminAuthenticationService authenticationService;

    @Mock
    private IamAuditService auditService;

    @Mock
    private IamClientService clientService;

    @Mock
    private IamPermissionService permissionService;

    @Mock
    private IamResourceService resourceService;

    @Mock
    private IamScopeService scopeService;

    @Mock
    private IamUserService userService;

    @Mock
    private AdminUserLifecycleService lifecycleService;

    @Mock
    private IamIdentityMappingService mappingService;

    @Mock
    private IamSessionService sessionService;

    @Mock
    private AdminRefreshTokenService refreshTokenService;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());
        mockMvc = MockMvcBuilders.standaloneSetup(
                        new AdminClientController(clientService, permissionService, auditService),
                        new AdminResourceController(resourceService, auditService),
                        new AdminScopeController(scopeService, auditService),
                        new AdminPermissionController(permissionService, auditService),
                        new AdminUserController(userService, lifecycleService, mappingService, auditService),
                        new AdminIdentityMappingController(mappingService, auditService),
                        new AdminSessionController(sessionService, auditService),
                        new AdminRefreshTokenController(refreshTokenService, auditService),
                        new AdminSecurityProbeController(auditService))
                .addFilters(new AdminAuthenticationFilter(authenticationService, mapper))
                .addInterceptors(new AdminAuthorizationInterceptor(auditService))
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
        when(authenticationService.authenticate(any())).thenReturn(principal());
    }

    @Test
    void eachAdminWriteEmitsNamedAuditEvent() throws Exception {
        Instant now = Instant.parse("2026-09-11T02:00:00Z");
        UUID subjectId = UUID.randomUUID();
        UUID userPk = UUID.randomUUID();
        UUID refreshId = UUID.randomUUID();
        when(clientService.disable("app-1"))
                .thenReturn(new ClientResponse(
                        UUID.randomUUID(),
                        "app-1",
                        "App",
                        "confidential",
                        "INACTIVE",
                        "client_secret_basic",
                        600,
                        86400,
                        true,
                        "iam",
                        List.of(),
                        now,
                        now));
        when(resourceService.disable("RES-1"))
                .thenReturn(new ResourceResponse(UUID.randomUUID(), "RES-1", "R", "aud", "INACTIVE", "iam", now));
        when(scopeService.disable("RES-1", "openid"))
                .thenReturn(new ScopeResponse(UUID.randomUUID(), UUID.randomUUID(), "RES-1", "openid", "OpenID", "d", "INACTIVE"));
        when(permissionService.disable(any(), any(), any(), any()))
                .thenReturn(new PermissionResponse(
                        UUID.randomUUID(), "app-1", "RES-1", "aud", "openid", "AUTHORIZATION_CODE", "INACTIVE", now));
        when(lifecycleService.disable(subjectId))
                .thenReturn(new UserResponse(
                        userPk, subjectId.toString(), "u", "U", "u@example.com", "INACTIVE", "admin-cli", null, now, now));
        when(mappingService.create(eq(subjectId), any()))
                .thenReturn(new IdentityMappingResponse(
                        UUID.randomUUID(), subjectId.toString(), "SYS", "E1", "u", "ACTIVE", now));
        IamSession session = new IamSession("sid-1", subjectId.toString(), now, now, now, "pwd", "portal", "REVOKED");
        when(sessionService.inspect("sid-1")).thenReturn(Optional.of(session));
        when(refreshTokenService.revokeById(refreshId))
                .thenReturn(new AdminRefreshTokenResponse(
                        refreshId,
                        userPk,
                        subjectId.toString(),
                        UUID.randomUUID(),
                        UUID.randomUUID(),
                        now,
                        now,
                        now,
                        "REVOKED",
                        "openid",
                        "aud"));

        mockMvc.perform(post("/api/admin/clients/app-1/disable")).andExpect(status().isOk());
        mockMvc.perform(post("/api/admin/resources/RES-1/disable")).andExpect(status().isOk());
        mockMvc.perform(post("/api/admin/scopes/RES-1/openid/disable")).andExpect(status().isOk());
        mockMvc.perform(post("/api/admin/permissions/disable")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"client_id":"app-1","resource_code":"RES-1","scope_code":"openid","grant_type":"AUTHORIZATION_CODE"}
                                """))
                .andExpect(status().isOk());
        mockMvc.perform(post("/api/admin/users/" + subjectId + "/disable")).andExpect(status().isOk());
        mockMvc.perform(post("/api/admin/identity-mappings")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"subject_id":"%s","system_code":"SYS","external_user_id":"E1"}
                                """.formatted(subjectId)))
                .andExpect(status().isOk());
        mockMvc.perform(post("/api/admin/sessions/sid-1/revoke")).andExpect(status().isOk());
        mockMvc.perform(post("/api/admin/refresh-tokens/" + refreshId + "/revoke")).andExpect(status().isOk());
        mockMvc.perform(post("/api/admin/security/write-probe")).andExpect(status().isOk());

        ArgumentCaptor<AuditEvent> events = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditService, times(10))
                .recordAdmin(events.capture(), any(), any(), any(), any(), any(), any(), any(), anyBoolean(), any());
        assertThat(events.getAllValues())
                .contains(
                        AuditEvent.CLIENT_DISABLED,
                        AuditEvent.RESOURCE_DISABLED,
                        AuditEvent.SCOPE_DISABLED,
                        AuditEvent.POLICY_CHANGED,
                        AuditEvent.USER_DISABLED,
                        AuditEvent.SESSION_REVOKED,
                        AuditEvent.USER_UPDATED,
                        AuditEvent.TOKEN_REVOKED,
                        AuditEvent.ADMIN_WRITE);
    }

    private static AdminPrincipal principal() {
        return new AdminPrincipal(
                UUID.randomUUID(),
                "tester",
                "tenant",
                Set.of(AdminRoles.IAM_ADMIN),
                Set.of(
                        AdminPermissions.CLIENT_WRITE,
                        AdminPermissions.RESOURCE_WRITE,
                        AdminPermissions.SCOPE_WRITE,
                        AdminPermissions.POLICY_WRITE,
                        AdminPermissions.USER_WRITE,
                        AdminPermissions.SESSION_REVOKE,
                        AdminPermissions.TOKEN_REVOKE,
                        AdminPermissions.AUDIT_READ),
                AdminPrincipal.AuthMethod.BEARER);
    }
}
