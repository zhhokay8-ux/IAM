package com.example.iam.admin.web.session;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.iam.admin.rbac.AdminPermissions;
import com.example.iam.admin.rbac.AdminRoles;
import com.example.iam.admin.security.AdminAuthenticationFilter;
import com.example.iam.admin.security.AdminAuthenticationService;
import com.example.iam.admin.security.AdminAuthorizationInterceptor;
import com.example.iam.admin.security.AdminPrincipal;
import com.example.iam.audit.IamAuditService;
import com.example.iam.common.web.GlobalExceptionHandler;
import com.example.iam.session.IamSession;
import com.example.iam.session.IamSessionService;
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
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

@ExtendWith(MockitoExtension.class)
class AdminSessionMvcTest {

    @Mock
    private AdminAuthenticationService authenticationService;

    @Mock
    private IamAuditService auditService;

    @Mock
    private IamSessionService sessionService;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());
        mockMvc = MockMvcBuilders.standaloneSetup(new AdminSessionController(sessionService, auditService))
                .addFilters(new AdminAuthenticationFilter(authenticationService, mapper))
                .addInterceptors(new AdminAuthorizationInterceptor(auditService))
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
    }

    @Test
    void auditorCannotRevokeSession() throws Exception {
        when(authenticationService.authenticate(any()))
                .thenReturn(principal(AdminRoles.IAM_AUDITOR, AdminPermissions.SESSION_READ));
        mockMvc.perform(post("/api/admin/sessions/sid-1/revoke"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("IAM-4081"));
        verify(sessionService, never()).revoke(any());
    }

    @Test
    void operatorCanListSessionsBySubject() throws Exception {
        when(authenticationService.authenticate(any()))
                .thenReturn(principal(AdminRoles.IAM_OPERATOR, AdminPermissions.SESSION_READ));
        Instant now = Instant.parse("2026-09-11T02:00:00Z");
        when(sessionService.listBySubject("sub-1"))
                .thenReturn(List.of(new IamSession("sid-1", "sub-1", now, now, now, "pwd", "portal", "ACTIVE")));
        mockMvc.perform(get("/api/admin/sessions").param("subject_id", "sub-1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].sid").value("sid-1"));
    }

    @Test
    void getInspectsRevokedSession() throws Exception {
        when(authenticationService.authenticate(any()))
                .thenReturn(principal(AdminRoles.IAM_OPERATOR, AdminPermissions.SESSION_READ));
        Instant now = Instant.parse("2026-09-11T02:00:00Z");
        when(sessionService.inspect("sid-1"))
                .thenReturn(Optional.of(new IamSession("sid-1", "sub-1", now, now, now, "pwd", "portal", "REVOKED")));
        mockMvc.perform(get("/api/admin/sessions/sid-1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("REVOKED"));
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
