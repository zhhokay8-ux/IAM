package com.example.iam.admin.web.client;

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
import com.example.iam.admin.web.AdminMeController;
import com.example.iam.admin.web.AdminSecurityProbeController;
import com.example.iam.audit.IamAuditService;
import com.example.iam.clientregistry.service.IamClientService;
import com.example.iam.clientregistry.service.IamPermissionService;
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
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

@ExtendWith(MockitoExtension.class)
class AdminClientMvcTest {

    @Mock
    private AdminAuthenticationService authenticationService;

    @Mock
    private IamAuditService auditService;

    @Mock
    private IamClientService clientService;

    @Mock
    private IamPermissionService permissionService;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());
        mockMvc = MockMvcBuilders.standaloneSetup(
                        new AdminMeController(),
                        new AdminSecurityProbeController(auditService),
                        new AdminClientController(clientService, permissionService, auditService))
                .addFilters(new AdminAuthenticationFilter(authenticationService, mapper))
                .addInterceptors(new AdminAuthorizationInterceptor(auditService))
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
    }

    @Test
    void auditorCannotCreateClient() throws Exception {
        when(authenticationService.authenticate(any()))
                .thenReturn(principal(AdminRoles.IAM_AUDITOR, AdminPermissions.CLIENT_READ));
        mockMvc.perform(post("/api/admin/clients")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"client_id\":\"x\",\"client_name\":\"X\",\"client_type\":\"confidential\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("IAM-4081"));
        verify(clientService, never()).create(any());
    }

    @Test
    void unauthenticatedListIs401() throws Exception {
        when(authenticationService.authenticate(any()))
                .thenThrow(new IamException(IamErrorCode.UNAUTHORIZED, "Admin authentication required"));
        mockMvc.perform(get("/api/admin/clients")).andExpect(status().isUnauthorized());
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
