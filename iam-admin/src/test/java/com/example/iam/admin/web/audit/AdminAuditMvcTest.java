package com.example.iam.admin.web.audit;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.iam.admin.rbac.AdminPermissions;
import com.example.iam.admin.rbac.AdminRoles;
import com.example.iam.admin.security.AdminAuthenticationFilter;
import com.example.iam.admin.security.AdminAuthenticationService;
import com.example.iam.admin.security.AdminAuthorizationInterceptor;
import com.example.iam.admin.security.AdminPrincipal;
import com.example.iam.audit.AuditEvent;
import com.example.iam.audit.IamAuditLogView;
import com.example.iam.audit.IamAuditService;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.common.web.GlobalExceptionHandler;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

@ExtendWith(MockitoExtension.class)
class AdminAuditMvcTest {

    @Mock
    private AdminAuthenticationService authenticationService;

    @Mock
    private IamAuditService auditService;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());
        mockMvc = MockMvcBuilders.standaloneSetup(new AdminAuditController(auditService))
                .addFilters(new AdminAuthenticationFilter(authenticationService, mapper))
                .addInterceptors(new AdminAuthorizationInterceptor(auditService))
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
    }

    @Test
    void unauthenticatedSearchIs401() throws Exception {
        when(authenticationService.authenticate(any()))
                .thenThrow(new IamException(IamErrorCode.UNAUTHORIZED, "Admin authentication required"));
        mockMvc.perform(get("/api/admin/audit")).andExpect(status().isUnauthorized());
    }

    @Test
    void auditorCanSearchAndDetailDoesNotEchoSecrets() throws Exception {
        when(authenticationService.authenticate(any()))
                .thenReturn(principal(AdminRoles.IAM_AUDITOR, AdminPermissions.AUDIT_READ));
        UUID id = UUID.randomUUID();
        IamAuditLogView view = new IamAuditLogView(
                id,
                "tr-9",
                AuditEvent.CLIENT_DISABLED.name(),
                UUID.randomUUID(),
                null,
                null,
                "client",
                "127.0.0.1",
                "JUnit",
                "SUCCESS",
                true,
                null,
                "admin_disable_client; client_id=app-1",
                "tester",
                "tenant",
                Instant.parse("2026-09-11T02:00:00Z"));
        when(auditService.search(any(), any()))
                .thenReturn(new PageImpl<>(List.of(view), PageRequest.of(0, 20), 1));
        when(auditService.get(id)).thenReturn(view);

        mockMvc.perform(get("/api/admin/audit")
                        .param("event_type", AuditEvent.CLIENT_DISABLED.name())
                        .param("operator", "tester")
                        .param("success", "true")
                        .param("ip", "127.0.0.1")
                        .param("trace_id", "tr-9"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].eventType").value(AuditEvent.CLIENT_DISABLED.name()))
                .andExpect(jsonPath("$.content[0].operatorName").value("tester"))
                .andExpect(jsonPath("$.content[0].sourceIp").value("127.0.0.1"))
                .andExpect(jsonPath("$.content[0].traceId").value("tr-9"))
                .andExpect(content().string(Matchers.not(Matchers.containsString("client_secret"))))
                .andExpect(content().string(Matchers.not(Matchers.containsString("access_token"))));

        mockMvc.perform(get("/api/admin/audit/" + id))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(id.toString()))
                .andExpect(jsonPath("$.userAgent").value("JUnit"));
    }

    @Test
    void eventsCatalogIncludesNamedAdminEvents() throws Exception {
        when(authenticationService.authenticate(any()))
                .thenReturn(principal(AdminRoles.IAM_AUDITOR, AdminPermissions.AUDIT_READ));
        mockMvc.perform(get("/api/admin/audit/events"))
                .andExpect(status().isOk())
                .andExpect(content().string(Matchers.containsString(AuditEvent.CLIENT_DISABLED.name())))
                .andExpect(content().string(Matchers.containsString(AuditEvent.SECRET_ROTATED.name())))
                .andExpect(content().string(Matchers.containsString(AuditEvent.SIGNING_KEY_ROTATED.name())))
                .andExpect(content().string(Matchers.containsString(AuditEvent.EMBED_POLICY_CHANGED.name())));
    }

    private static AdminPrincipal principal(String role, String... permissions) {
        return new AdminPrincipal(
                UUID.randomUUID(),
                "tester",
                "tenant",
                Set.of(role),
                Set.of(permissions),
                AdminPrincipal.AuthMethod.BEARER);
    }
}
