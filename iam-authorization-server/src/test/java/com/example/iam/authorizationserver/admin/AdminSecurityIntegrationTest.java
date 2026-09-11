package com.example.iam.authorizationserver.admin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.iam.admin.entity.IamAdminUserRoleEntity;
import com.example.iam.admin.rbac.AdminPermissions;
import com.example.iam.admin.rbac.AdminRoles;
import com.example.iam.admin.repository.IamAdminRoleRepository;
import com.example.iam.admin.repository.IamAdminUserRoleRepository;
import com.example.iam.audit.AuditEvent;
import com.example.iam.audit.entity.IamAuditLogEntity;
import com.example.iam.audit.repository.IamAuditLogRepository;
import com.example.iam.authorizationserver.AbstractIamIntegrationTest;
import com.example.iam.authorizationserver.IamAuthorizationServerApplication;
import com.example.iam.token.signing.JwtSigner;
import com.example.iam.user.dto.CreateUserRequest;
import com.example.iam.user.dto.UserResponse;
import com.example.iam.user.service.IamUserService;
import com.nimbusds.jwt.JWTClaimsSet;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest(classes = IamAuthorizationServerApplication.class)
@AutoConfigureMockMvc
@TestPropertySource(
        properties = {
            "iam.issuer=https://auth.example.com",
            "iam.admin.legacy-token.enabled=false",
            "iam.admin.access-token=legacy-secret"
        })
class AdminSecurityIntegrationTest extends AbstractIamIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private IamUserService userService;

    @Autowired
    private IamAdminRoleRepository roleRepository;

    @Autowired
    private IamAdminUserRoleRepository userRoleRepository;

    @Autowired
    private JwtSigner jwtSigner;

    @Autowired
    private IamAuditLogRepository auditLogRepository;

    private String suffix;

    @BeforeEach
    void suffix() {
        suffix = UUID.randomUUID().toString().substring(0, 8);
    }

    @Test
    void unauthenticatedIs401() throws Exception {
        mockMvc.perform(get("/api/admin/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("IAM-4010"));
    }

    @Test
    void regularUserIs403() throws Exception {
        UserResponse user = user("plain");
        mockMvc.perform(get("/api/admin/me").header("Authorization", bearer(user.subjectId())))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("IAM-4082"));
    }

    @Test
    void iamAdminAllowedAndWriteAudited() throws Exception {
        UserResponse user = user("adm");
        bind(user, AdminRoles.IAM_ADMIN);
        mockMvc.perform(get("/api/admin/me").header("Authorization", bearer(user.subjectId())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.roles[0]").value(AdminRoles.IAM_ADMIN));
        mockMvc.perform(post("/api/admin/security/write-probe").header("Authorization", bearer(user.subjectId())))
                .andExpect(status().isOk());
        List<IamAuditLogEntity> writes = auditLogRepository.findAll().stream()
                .filter(row -> AuditEvent.ADMIN_WRITE.name().equals(row.getEventType()))
                .filter(row -> user.username().equals(row.getOperatorName()))
                .toList();
        assertThat(writes).isNotEmpty();
        assertThat(writes.get(0).getDetail()).doesNotContain("legacy-secret");
    }

    @Test
    void auditorReadOkWriteForbidden() throws Exception {
        UserResponse user = user("aud");
        bind(user, AdminRoles.IAM_AUDITOR);
        mockMvc.perform(get("/api/admin/security/read-probe").header("Authorization", bearer(user.subjectId())))
                .andExpect(status().isOk());
        mockMvc.perform(post("/api/admin/security/write-probe").header("Authorization", bearer(user.subjectId())))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("IAM-4081"));
    }

    @Test
    void operatorScopedPermissions() throws Exception {
        UserResponse user = user("opr");
        bind(user, AdminRoles.IAM_OPERATOR);
        mockMvc.perform(post("/api/admin/security/token-revoke-probe")
                        .header("Authorization", bearer(user.subjectId())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.permission").value(AdminPermissions.TOKEN_REVOKE));
        mockMvc.perform(post("/api/admin/security/write-probe").header("Authorization", bearer(user.subjectId())))
                .andExpect(status().isForbidden());
    }

    @Test
    void legacyTokenDisabledByDefault() throws Exception {
        mockMvc.perform(get("/api/admin/me").header("X-IAM-Admin-Token", "legacy-secret"))
                .andExpect(status().isUnauthorized());
    }

    private UserResponse user(String prefix) {
        return userService.create(new CreateUserRequest(
                prefix + suffix, prefix, prefix + "@example.com", "admin-test", null, "ACTIVE"));
    }

    private void bind(UserResponse user, String roleCode) {
        UUID roleId = roleRepository.findByRoleCode(roleCode).orElseThrow().getId();
        userRoleRepository.save(IamAdminUserRoleEntity.builder()
                .subjectId(UUID.fromString(user.subjectId()))
                .roleId(roleId)
                .createdAt(Instant.now())
                .build());
    }

    private String bearer(String subjectId) {
        Instant now = Instant.now();
        return "Bearer "
                + jwtSigner
                        .sign(new JWTClaimsSet.Builder()
                                .subject(subjectId)
                                .issueTime(Date.from(now))
                                .expirationTime(Date.from(now.plusSeconds(600)))
                                .build())
                        .serialize();
    }
}
