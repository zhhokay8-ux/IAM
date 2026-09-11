package com.example.iam.admin.web.dashboard;

import static org.mockito.ArgumentMatchers.any;
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
import com.example.iam.admin.web.config.AdminConfigController;
import com.example.iam.admin.web.config.AdminConfigResponse;
import com.example.iam.admin.web.config.AdminConfigService;
import com.example.iam.audit.IamAuditService;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.common.web.GlobalExceptionHandler;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.util.List;
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
class AdminDashboardConfigMvcTest {

    @Mock
    private AdminAuthenticationService authenticationService;

    @Mock
    private IamAuditService auditService;

    @Mock
    private AdminDashboardService dashboardService;

    @Mock
    private AdminConfigService configService;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());
        mockMvc = MockMvcBuilders.standaloneSetup(
                        new AdminDashboardController(dashboardService), new AdminConfigController(configService))
                .addFilters(new AdminAuthenticationFilter(authenticationService, mapper))
                .addInterceptors(new AdminAuthorizationInterceptor(auditService))
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
    }

    @Test
    void unauthenticatedDashboardIs401() throws Exception {
        when(authenticationService.authenticate(any()))
                .thenThrow(new IamException(IamErrorCode.UNAUTHORIZED, "Admin authentication required"));
        mockMvc.perform(get("/api/admin/dashboard")).andExpect(status().isUnauthorized());
    }

    @Test
    void auditorCanReadDashboardAndConfig() throws Exception {
        when(authenticationService.authenticate(any()))
                .thenReturn(principal(
                        AdminRoles.IAM_AUDITOR, AdminPermissions.AUDIT_READ, AdminPermissions.CONFIG_READ));
        when(dashboardService.snapshot(7))
                .thenReturn(new AdminDashboardResponse(
                        new AdminDashboardResponse.AdminDashboardCounts(1, 1, 1, 1, 1, 2, false, false, 3),
                        new AdminDashboardResponse.AdminDashboardTrends(
                                7, List.of(), List.of(), List.of(), List.of(), List.of()),
                        List.of()));
        when(configService.snapshot())
                .thenReturn(new AdminConfigResponse(
                        true,
                        true,
                        List.of(new AdminConfigResponse.AdminConfigSection(
                                "issuer",
                                true,
                                List.of(new AdminConfigResponse.AdminConfigItem(
                                        "iam.issuer", "https://auth.example.com", false, true, true))))));

        mockMvc.perform(get("/api/admin/dashboard"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.counts.clientCount").value(1))
                .andExpect(jsonPath("$.counts.activeSessionCount").value(2));
        mockMvc.perform(get("/api/admin/config"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.readOnly").value(true))
                .andExpect(jsonPath("$.restartRequired").value(true))
                .andExpect(jsonPath("$.sections[0].items[0].key").value("iam.issuer"));
    }

    @Test
    void operatorWithoutConfigReadIs403OnConfig() throws Exception {
        when(authenticationService.authenticate(any()))
                .thenReturn(principal(AdminRoles.IAM_OPERATOR, AdminPermissions.AUDIT_READ));
        mockMvc.perform(get("/api/admin/config"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("IAM-4081"));
    }

    @Test
    void configMutationIsRejected() throws Exception {
        when(authenticationService.authenticate(any()))
                .thenReturn(principal(AdminRoles.IAM_ADMIN, AdminPermissions.CONFIG_READ));
        org.mockito.Mockito.doThrow(new IamException(IamErrorCode.FORBIDDEN, "READ_ONLY"))
                .when(configService)
                .rejectMutation();
        mockMvc.perform(post("/api/admin/config"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("IAM-4030"));
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
