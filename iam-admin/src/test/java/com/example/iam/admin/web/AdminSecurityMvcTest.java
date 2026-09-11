package com.example.iam.admin.web;

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
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.common.web.GlobalExceptionHandler;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
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
class AdminSecurityMvcTest {

    @Mock
    private AdminAuthenticationService authenticationService;

    @Mock
    private IamAuditService auditService;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());
        AdminAuthenticationFilter filter = new AdminAuthenticationFilter(authenticationService, mapper);
        AdminAuthorizationInterceptor interceptor = new AdminAuthorizationInterceptor(auditService);
        mockMvc = MockMvcBuilders.standaloneSetup(
                        new AdminMeController(), new AdminSecurityProbeController(auditService))
                .addFilters(filter)
                .addInterceptors(interceptor)
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
    }

    @Test
    void unauthenticatedReturns401() throws Exception {
        org.mockito.Mockito.when(authenticationService.authenticate(org.mockito.ArgumentMatchers.any()))
                .thenThrow(new IamException(IamErrorCode.UNAUTHORIZED, "Admin authentication required"));
        mockMvc.perform(get("/api/admin/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("IAM-4010"));
    }

    @Test
    void iamAdminAllowedOnWriteProbe() throws Exception {
        org.mockito.Mockito.when(authenticationService.authenticate(org.mockito.ArgumentMatchers.any()))
                .thenReturn(principal(AdminRoles.IAM_ADMIN, AdminPermissions.CLIENT_WRITE, AdminPermissions.AUDIT_READ));
        mockMvc.perform(post("/api/admin/security/write-probe")).andExpect(status().isOk());
        mockMvc.perform(get("/api/admin/security/read-probe")).andExpect(status().isOk());
    }

    @Test
    void auditorReadAllowedWriteDenied() throws Exception {
        org.mockito.Mockito.when(authenticationService.authenticate(org.mockito.ArgumentMatchers.any()))
                .thenReturn(principal(AdminRoles.IAM_AUDITOR, AdminPermissions.AUDIT_READ));
        mockMvc.perform(get("/api/admin/security/read-probe")).andExpect(status().isOk());
        mockMvc.perform(post("/api/admin/security/write-probe"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("IAM-4081"));
    }

    @Test
    void operatorTokenRevokeAllowedClientWriteDenied() throws Exception {
        org.mockito.Mockito.when(authenticationService.authenticate(org.mockito.ArgumentMatchers.any()))
                .thenReturn(principal(AdminRoles.IAM_OPERATOR, AdminPermissions.TOKEN_REVOKE, AdminPermissions.AUDIT_READ));
        mockMvc.perform(post("/api/admin/security/token-revoke-probe")).andExpect(status().isOk());
        mockMvc.perform(post("/api/admin/security/write-probe"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("IAM-4081"));
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
