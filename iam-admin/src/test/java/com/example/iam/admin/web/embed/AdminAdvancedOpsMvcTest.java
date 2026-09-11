package com.example.iam.admin.web.embed;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.iam.admin.rbac.AdminPermissions;
import com.example.iam.admin.rbac.AdminRoles;
import com.example.iam.admin.security.AdminAuthenticationFilter;
import com.example.iam.admin.security.AdminAuthenticationService;
import com.example.iam.admin.security.AdminAuthorizationInterceptor;
import com.example.iam.admin.security.AdminPrincipal;
import com.example.iam.admin.web.exchange.AdminTokenExchangeController;
import com.example.iam.admin.web.key.AdminSigningKeyController;
import com.example.iam.audit.IamAuditService;
import com.example.iam.clientregistry.service.IamPermissionService;
import com.example.iam.common.web.GlobalExceptionHandler;
import com.example.iam.embed.EmbedPolicyService;
import com.example.iam.token.signing.SigningKeyRotationService;
import com.example.iam.token.signing.SigningKeyService;
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
class AdminAdvancedOpsMvcTest {

    @Mock
    private AdminAuthenticationService authenticationService;

    @Mock
    private IamAuditService auditService;

    @Mock
    private EmbedPolicyService embedPolicyService;

    @Mock
    private IamPermissionService permissionService;

    @Mock
    private SigningKeyService signingKeyService;

    @Mock
    private SigningKeyRotationService rotationService;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());
        mockMvc = MockMvcBuilders.standaloneSetup(
                        new AdminEmbedPolicyController(embedPolicyService, auditService),
                        new AdminTokenExchangeController(permissionService, auditService),
                        new AdminSigningKeyController(signingKeyService, rotationService, auditService))
                .addFilters(new AdminAuthenticationFilter(authenticationService, mapper))
                .addInterceptors(new AdminAuthorizationInterceptor(auditService))
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
    }

    @Test
    void auditorCannotWriteEmbedPolicy() throws Exception {
        when(authenticationService.authenticate(any()))
                .thenReturn(principal(AdminRoles.IAM_AUDITOR, AdminPermissions.EMBED_READ));
        mockMvc.perform(post("/api/admin/embed-policies")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"parent_client_id":"p","child_client_id":"c","parent_origin":"https://p.example","allowed_path":"/x"}
                                """))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("IAM-4081"));
        verify(embedPolicyService, never()).create(any(), any(), any(), any());
    }

    @Test
    void auditorCannotDisableTokenExchange() throws Exception {
        when(authenticationService.authenticate(any()))
                .thenReturn(principal(AdminRoles.IAM_AUDITOR, AdminPermissions.POLICY_READ));
        mockMvc.perform(post("/api/admin/token-exchange/permissions/disable")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"client_id":"c","resource_code":"r","scope_code":"s","grant_type":"TOKEN_EXCHANGE"}
                                """))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("IAM-4081"));
        verify(permissionService, never()).disable(any(), any(), any(), any());
    }

    @Test
    void auditorCannotRotateSigningKey() throws Exception {
        when(authenticationService.authenticate(any()))
                .thenReturn(principal(AdminRoles.IAM_AUDITOR, AdminPermissions.KEY_READ));
        mockMvc.perform(post("/api/admin/signing-keys/rotate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"confirm\":true}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("IAM-4081"));
        verify(rotationService, never()).rotate();
    }

    @Test
    void rotateWithoutConfirmIsRejected() throws Exception {
        when(authenticationService.authenticate(any()))
                .thenReturn(principal(AdminRoles.IAM_ADMIN, AdminPermissions.KEY_ROTATE));
        mockMvc.perform(post("/api/admin/signing-keys/rotate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"confirm\":false}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("IAM-4000"));
        verify(rotationService, never()).rotate();
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
