package com.example.iam.authorizationserver.admin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.iam.admin.entity.IamAdminUserRoleEntity;
import com.example.iam.admin.rbac.AdminRoles;
import com.example.iam.admin.repository.IamAdminRoleRepository;
import com.example.iam.admin.repository.IamAdminUserRoleRepository;
import com.example.iam.audit.AuditEvent;
import com.example.iam.audit.repository.IamAuditLogRepository;
import com.example.iam.authorizationserver.AbstractIamIntegrationTest;
import com.example.iam.authorizationserver.IamAuthorizationServerApplication;
import com.example.iam.clientregistry.domain.RegistryStatus;
import com.example.iam.clientregistry.repository.IamClientRepository;
import com.example.iam.session.IamSessionService;
import com.example.iam.token.signing.JwtSigner;
import com.example.iam.user.dto.CreateUserRequest;
import com.example.iam.user.dto.UserResponse;
import com.example.iam.user.repository.IamUserRepository;
import com.example.iam.user.service.IamUserService;
import com.nimbusds.jwt.JWTClaimsSet;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

@SpringBootTest(classes = IamAuthorizationServerApplication.class)
@AutoConfigureMockMvc
@TestPropertySource(properties = {"iam.issuer=https://auth.example.com", "iam.sso.cookie-secure=false"})
class AdminDashboardConfigIntegrationTest extends AbstractIamIntegrationTest {

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
    private IamClientRepository clientRepository;

    @Autowired
    private IamUserRepository userRepository;

    @Autowired
    private IamAuditLogRepository auditLogRepository;

    @Autowired
    private IamSessionService sessionService;

    private String suffix;
    private String adminBearer;

    @BeforeEach
    void setUp() {
        suffix = UUID.randomUUID().toString().substring(0, 8);
        UserResponse admin = userService.create(new CreateUserRequest(
                "a9adm" + suffix, "Admin", "a9adm" + suffix + "@example.com", "admin-cli", null, "ACTIVE"));
        bind(admin, AdminRoles.IAM_ADMIN);
        adminBearer = bearer(admin.subjectId());
    }

    @Test
    void dashboardCountsMatchRuntimeTablesAndConfigIssuerMatchesOidc() throws Exception {
        String clientId = "a9-" + suffix;
        mockMvc.perform(post("/api/admin/clients")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"client_id":"%s","client_name":"A9","client_type":"confidential",
                                 "redirect_uris":[{"redirectUri":"https://app.example.com/login/callback","uriType":"LOGIN_CALLBACK"}]}
                                """.formatted(clientId)))
                .andExpect(status().isOk());
        mockMvc.perform(post("/api/admin/clients/" + clientId + "/enable")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer))
                .andExpect(status().isOk());
        sessionService.create(UUID.randomUUID().toString(), clientId, "pwd");

        long clients = clientRepository.count();
        long activeClients = clientRepository.countByStatus(RegistryStatus.ACTIVE);
        long users = userRepository.count();
        long loginSuccess = auditLogRepository.findAll().stream()
                .filter(row -> AuditEvent.CLIENT_ENABLED.name().equals(row.getEventType()))
                .count();

        MvcResult dashboard = mockMvc.perform(get("/api/admin/dashboard")
                        .param("days", "7")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.counts.clientCount").value((int) clients))
                .andExpect(jsonPath("$.counts.activeClientCount").value((int) activeClients))
                .andExpect(jsonPath("$.counts.userCount").value((int) users))
                .andReturn();
        String body = dashboard.getResponse().getContentAsString();
        assertThat(com.jayway.jsonpath.JsonPath.<Number>read(body, "$.counts.activeSessionCount").longValue())
                .isGreaterThanOrEqualTo(1L);
        assertThat(auditLogRepository.findByOperatorNameIsNotNull(
                        org.springframework.data.domain.PageRequest.of(0, 20)))
                .anyMatch(row -> AuditEvent.CLIENT_ENABLED.name().equals(row.getEventType()));
        assertThat(loginSuccess).isGreaterThan(0);

        mockMvc.perform(get("/api/admin/config").header(HttpHeaders.AUTHORIZATION, adminBearer))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.readOnly").value(true))
                .andExpect(jsonPath("$.restartRequired").value(true));
        mockMvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").value("https://auth.example.com"));
        mockMvc.perform(post("/api/admin/config")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"iam.issuer\":\"https://evil.example\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("IAM-4030"));
        assertThat(clientRepository.findByClientId(clientId).orElseThrow().getStatus())
                .isEqualTo(RegistryStatus.ACTIVE);
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
