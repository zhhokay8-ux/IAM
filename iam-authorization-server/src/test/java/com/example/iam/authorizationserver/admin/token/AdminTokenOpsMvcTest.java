package com.example.iam.authorizationserver.admin.token;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
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
import com.example.iam.audit.IamAuditService;
import com.example.iam.authorizationserver.oauth.introspect.TokenIntrospectionResponse;
import com.example.iam.authorizationserver.oauth.introspect.TokenIntrospectionService;
import com.example.iam.authorizationserver.oauth.revoke.TokenRevocationService;
import com.example.iam.common.web.GlobalExceptionHandler;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
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
class AdminTokenOpsMvcTest {

    @Mock
    private AdminAuthenticationService authenticationService;

    @Mock
    private IamAuditService auditService;

    @Mock
    private TokenIntrospectionService introspectionService;

    @Mock
    private TokenRevocationService revocationService;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        ObjectMapper mapper = new ObjectMapper();
        mockMvc = MockMvcBuilders.standaloneSetup(
                        new AdminTokenOpsController(introspectionService, revocationService, auditService))
                .addFilters(new AdminAuthenticationFilter(authenticationService, mapper))
                .addInterceptors(new AdminAuthorizationInterceptor(auditService))
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
    }

    @Test
    void auditorCannotRevokePresentedToken() throws Exception {
        when(authenticationService.authenticate(any()))
                .thenReturn(principal(AdminRoles.IAM_AUDITOR, AdminPermissions.TOKEN_READ));
        mockMvc.perform(post("/api/admin/tokens/revoke")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"secret-token-value\",\"token_type_hint\":\"access_token\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("IAM-4081"));
        verify(revocationService, never()).revoke(any(), any());
    }

    @Test
    void introspectDoesNotEchoTokenAndWarns() throws Exception {
        when(authenticationService.authenticate(any()))
                .thenReturn(principal(AdminRoles.IAM_OPERATOR, AdminPermissions.TOKEN_READ));
        when(introspectionService.introspect("secret-token-value"))
                .thenReturn(new TokenIntrospectionResponse(
                        true, "sub", List.of("aud"), "client", "openid", "Bearer", 1L, 1L, "jti-1"));
        mockMvc.perform(post("/api/admin/tokens/introspect")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"secret-token-value\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(true))
                .andExpect(jsonPath("$.warning").value(AdminTokenIntrospectResponse.HIGH_RISK_WARNING))
                .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString(
                        "secret-token-value"))));
    }

    @Test
    void revokeAuditsWithoutToken() throws Exception {
        when(authenticationService.authenticate(any()))
                .thenReturn(principal(AdminRoles.IAM_OPERATOR, AdminPermissions.TOKEN_REVOKE));
        when(revocationService.revoke("secret-token-value", "access_token")).thenReturn(true);
        mockMvc.perform(post("/api/admin/tokens/revoke")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"secret-token-value\",\"token_type_hint\":\"access_token\"}"))
                .andExpect(status().isOk());
        ArgumentCaptor<String> detail = ArgumentCaptor.forClass(String.class);
        verify(auditService)
                .recordAdmin(
                        eq(AuditEvent.TOKEN_REVOKED),
                        any(),
                        any(),
                        any(),
                        eq("token"),
                        any(),
                        any(),
                        any(),
                        eq(true),
                        detail.capture());
        org.assertj.core.api.Assertions.assertThat(detail.getValue()).doesNotContain("secret-token-value");
        org.assertj.core.api.Assertions.assertThat(detail.getValue()).contains("token_type_hint=access_token");
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
