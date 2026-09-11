package com.example.iam.admin.web.token;

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
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.time.Instant;
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
class AdminRefreshTokenMvcTest {

    @Mock
    private AdminAuthenticationService authenticationService;

    @Mock
    private IamAuditService auditService;

    @Mock
    private AdminRefreshTokenService refreshTokenService;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());
        mockMvc = MockMvcBuilders.standaloneSetup(new AdminRefreshTokenController(refreshTokenService, auditService))
                .addFilters(new AdminAuthenticationFilter(authenticationService, mapper))
                .addInterceptors(new AdminAuthorizationInterceptor(auditService))
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
    }

    @Test
    void auditorCannotRevokeRefreshToken() throws Exception {
        when(authenticationService.authenticate(any()))
                .thenReturn(principal(AdminRoles.IAM_AUDITOR, AdminPermissions.TOKEN_READ));
        UUID id = UUID.randomUUID();
        mockMvc.perform(post("/api/admin/refresh-tokens/" + id + "/revoke"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("IAM-4081"));
        verify(refreshTokenService, never()).revokeById(any());
    }

    @Test
    void metadataResponseOmitsHash() throws Exception {
        when(authenticationService.authenticate(any()))
                .thenReturn(principal(AdminRoles.IAM_OPERATOR, AdminPermissions.TOKEN_READ));
        UUID id = UUID.randomUUID();
        UUID userPk = UUID.randomUUID();
        UUID family = UUID.randomUUID();
        Instant now = Instant.parse("2026-09-11T02:00:00Z");
        when(refreshTokenService.listByJwtSubject(any()))
                .thenReturn(List.of(new AdminRefreshTokenResponse(
                        id,
                        userPk,
                        UUID.randomUUID().toString(),
                        UUID.randomUUID(),
                        family,
                        now,
                        now,
                        null,
                        "ACTIVE",
                        "openid",
                        "aud")));
        mockMvc.perform(get("/api/admin/refresh-tokens").param("subject_id", UUID.randomUUID().toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].id").value(id.toString()))
                .andExpect(jsonPath("$.content[0].familyId").value(family.toString()))
                .andExpect(jsonPath("$.content[0].tokenHash").doesNotExist())
                .andExpect(jsonPath("$.content[0].token").doesNotExist());
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
