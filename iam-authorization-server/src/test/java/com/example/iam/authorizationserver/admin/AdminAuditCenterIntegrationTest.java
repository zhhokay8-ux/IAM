package com.example.iam.authorizationserver.admin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
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
import com.example.iam.authorizationserver.sso.SsoCookieService;
import com.example.iam.clientregistry.domain.RegistryStatus;
import com.example.iam.clientregistry.dto.CreatePermissionRequest;
import com.example.iam.clientregistry.dto.CreateResourceRequest;
import com.example.iam.clientregistry.dto.CreateScopeRequest;
import com.example.iam.clientregistry.repository.IamClientRepository;
import com.example.iam.clientregistry.service.IamPermissionService;
import com.example.iam.clientregistry.service.IamResourceService;
import com.example.iam.clientregistry.service.IamScopeService;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.policy.IamPolicyEvaluator;
import com.example.iam.token.signing.JwtSigner;
import com.example.iam.user.dto.CreateUserRequest;
import com.example.iam.user.dto.UserResponse;
import com.example.iam.user.service.IamUserService;
import com.nimbusds.jwt.JWTClaimsSet;
import jakarta.servlet.http.Cookie;
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
class AdminAuditCenterIntegrationTest extends AbstractIamIntegrationTest {

    private static final String LOGIN = "https://app.example.com/login/callback";
    private static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

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
    private IamPolicyEvaluator policyEvaluator;

    @Autowired
    private IamAuditLogRepository auditLogRepository;

    @Autowired
    private IamResourceService resourceService;

    @Autowired
    private IamScopeService scopeService;

    @Autowired
    private IamPermissionService permissionService;

    private String suffix;
    private String adminBearer;
    private String auditorBearer;

    @BeforeEach
    void setUp() {
        suffix = UUID.randomUUID().toString().substring(0, 8);
        UserResponse admin = userService.create(new CreateUserRequest(
                "a7adm" + suffix, "Admin", "a7adm" + suffix + "@example.com", "admin-cli", null, "ACTIVE"));
        bind(admin, AdminRoles.IAM_ADMIN);
        adminBearer = bearer(admin.subjectId());
        UserResponse auditor = userService.create(new CreateUserRequest(
                "a7aud" + suffix, "Aud", "a7aud" + suffix + "@example.com", "admin-cli", null, "ACTIVE"));
        bind(auditor, AdminRoles.IAM_AUDITOR);
        auditorBearer = bearer(auditor.subjectId());
    }

    @Test
    void disableClientThenAuditQueryReadsSameRuntimeRow() throws Exception {
        String clientId = "a7-" + suffix;
        MvcResult created = mockMvc.perform(post("/api/admin/clients")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"client_id":"%s","client_name":"A7","client_type":"confidential",
                                 "redirect_uris":[{"redirectUri":"%s","uriType":"LOGIN_CALLBACK"}]}
                                """.formatted(clientId, LOGIN)))
                .andExpect(status().isOk())
                .andReturn();
        String secret = com.jayway.jsonpath.JsonPath.read(created.getResponse().getContentAsString(), "$.client_secret");

        mockMvc.perform(post("/api/admin/clients/" + clientId + "/enable")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer))
                .andExpect(status().isOk());
        String resource = "OIDC-" + clientId;
        resourceService.create(new CreateResourceRequest(resource, "OIDC", "oidc-" + clientId, RegistryStatus.ACTIVE, "iam"));
        scopeService.create(new CreateScopeRequest(resource, "openid", "OpenID", "openid", RegistryStatus.ACTIVE));
        permissionService.create(
                new CreatePermissionRequest(clientId, resource, "openid", "authorization_code", RegistryStatus.ACTIVE));
        UserResponse user = userService.create(new CreateUserRequest(
                "u" + clientId, "U", "u" + clientId + "@example.com", "admin-cli", null, "ACTIVE"));
        MvcResult login = mockMvc.perform(post("/sso/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"%s","tenant_id":"admin-cli","client_id":"%s"}
                                """.formatted(user.username(), clientId)))
                .andExpect(status().isOk())
                .andReturn();
        Cookie session = login.getResponse().getCookie(SsoCookieService.COOKIE_NAME);

        mockMvc.perform(post("/api/admin/clients/" + clientId + "/disable")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer)
                        .header(HttpHeaders.USER_AGENT, "AuditCenter/1.0"))
                .andExpect(status().isOk());

        assertThat(clientRepository.findByClientId(clientId).orElseThrow().getStatus()).isEqualTo(RegistryStatus.INACTIVE);
        assertThatThrownBy(() -> policyEvaluator.validateClient(clientId))
                .isInstanceOf(IamException.class)
                .extracting(ex -> ((IamException) ex).getErrorCode())
                .isEqualTo(IamErrorCode.CLIENT_INACTIVE);
        mockMvc.perform(get("/oauth2/authorize")
                        .param("client_id", clientId)
                        .param("redirect_uri", LOGIN)
                        .param("response_type", "code")
                        .param("scope", "openid")
                        .param("state", "st")
                        .param("nonce", "nn")
                        .param("code_challenge", CHALLENGE)
                        .param("code_challenge_method", "S256")
                        .cookie(session))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value(IamErrorCode.CLIENT_INACTIVE.getCode()));

        assertThat(auditLogRepository.findAll())
                .anyMatch(row -> AuditEvent.CLIENT_DISABLED.name().equals(row.getEventType())
                        && "SUCCESS".equals(row.getResult())
                        && row.getOperatorName() != null
                        && row.getTraceId() != null);

        MvcResult queried = mockMvc.perform(get("/api/admin/audit")
                        .param("event_type", AuditEvent.CLIENT_DISABLED.name())
                        .param("success", "true")
                        .header(HttpHeaders.AUTHORIZATION, auditorBearer))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].eventType").value(AuditEvent.CLIENT_DISABLED.name()))
                .andExpect(jsonPath("$.content[0].success").value(true))
                .andExpect(jsonPath("$.content[0].operatorName").isNotEmpty())
                .andExpect(jsonPath("$.content[0].traceId").isNotEmpty())
                .andReturn();
        String body = queried.getResponse().getContentAsString();
        assertThat(body).doesNotContain(secret);
        assertThat(body.toLowerCase()).doesNotContain("client_secret=");
        String auditId = com.jayway.jsonpath.JsonPath.read(body, "$.content[0].id");
        mockMvc.perform(get("/api/admin/audit/" + auditId).header(HttpHeaders.AUTHORIZATION, auditorBearer))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.eventType").value(AuditEvent.CLIENT_DISABLED.name()))
                .andExpect(jsonPath("$.userAgent").value("AuditCenter/1.0"));
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
