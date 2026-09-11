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
import com.example.iam.clientregistry.dto.CreateClientRequest;
import com.example.iam.clientregistry.dto.CreateResourceRequest;
import com.example.iam.clientregistry.dto.CreateScopeRequest;
import com.example.iam.clientregistry.dto.RedirectUriInput;
import com.example.iam.clientregistry.service.IamClientService;
import com.example.iam.clientregistry.service.IamPermissionService;
import com.example.iam.clientregistry.service.IamResourceService;
import com.example.iam.clientregistry.service.IamScopeService;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.common.security.CsrfTokenService;
import com.example.iam.embed.EmbedPolicyService;
import com.example.iam.embed.repository.IamEmbedPolicyRepository;
import com.example.iam.policy.IamPolicyEvaluator;
import com.example.iam.policy.TokenExchangePolicyService;
import com.example.iam.token.oauth.AccessTokenClaims;
import com.example.iam.token.oauth.AccessTokenService;
import com.example.iam.token.signing.JwtSigner;
import com.example.iam.token.signing.SigningKeyService;
import com.example.iam.user.dto.CreateUserRequest;
import com.example.iam.user.dto.UserResponse;
import com.example.iam.user.service.IamUserService;
import com.nimbusds.jwt.JWTClaimsSet;
import jakarta.servlet.http.Cookie;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
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
class AdminAdvancedOperationsIntegrationTest extends AbstractIamIntegrationTest {

    private static final String LOGIN = "https://app.example.com/login/callback";
    private static final String ORIGIN = "https://portal.example.com";
    private static final String SECRET = "phase8-secret";
    private static final String EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";
    private static final String ACCESS_TYPE = "urn:ietf:params:oauth:token-type:access_token";

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
    private IamClientService clientService;

    @Autowired
    private IamResourceService resourceService;

    @Autowired
    private IamScopeService scopeService;

    @Autowired
    private IamPermissionService permissionService;

    @Autowired
    private IamPolicyEvaluator policyEvaluator;

    @Autowired
    private TokenExchangePolicyService tokenExchangePolicyService;

    @Autowired
    private EmbedPolicyService embedPolicyService;

    @Autowired
    private IamEmbedPolicyRepository embedPolicyRepository;

    @Autowired
    private IamAuditLogRepository auditLogRepository;

    @Autowired
    private AccessTokenService accessTokenService;

    @Autowired
    private SigningKeyService signingKeyService;

    private String suffix;
    private String adminBearer;
    private String auditorBearer;

    @BeforeEach
    void setUp() {
        suffix = UUID.randomUUID().toString().substring(0, 8);
        UserResponse admin = userService.create(new CreateUserRequest(
                "p8adm" + suffix, "Admin", "p8adm" + suffix + "@example.com", "admin-cli", null, "ACTIVE"));
        bind(admin, AdminRoles.IAM_ADMIN);
        adminBearer = bearer(admin.subjectId());
        UserResponse auditor = userService.create(new CreateUserRequest(
                "p8aud" + suffix, "Aud", "p8aud" + suffix + "@example.com", "admin-cli", null, "ACTIVE"));
        bind(auditor, AdminRoles.IAM_AUDITOR);
        auditorBearer = bearer(auditor.subjectId());
    }

    @Test
    void embedPolicyDisableStopsEmbedCodeAndAudits() throws Exception {
        String parentId = "p8p-" + suffix;
        String childId = "p8c-" + suffix;
        clientService.create(new CreateClientRequest(
                parentId, "P", "confidential", RegistryStatus.ACTIVE, "client_secret_basic", 600, 86400, true, "iam",
                List.of(new RedirectUriInput(LOGIN, "LOGIN_CALLBACK")), SECRET));
        clientService.create(new CreateClientRequest(
                childId, "C", "confidential", RegistryStatus.ACTIVE, "client_secret_basic", 600, 86400, true, "iam",
                List.of(new RedirectUriInput("https://child.example.com/cb", "LOGIN_CALLBACK")), SECRET));
        UserResponse user = userService.create(new CreateUserRequest(
                "p8u" + suffix, "U", "p8u" + suffix + "@example.com", "admin-cli", null, "ACTIVE"));

        mockMvc.perform(post("/api/admin/embed-policies")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"parent_client_id":"%s","child_client_id":"%s","parent_origin":"*","allowed_path":"/orders/*"}
                                """.formatted(parentId, childId)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value(IamErrorCode.INVALID_ORIGIN.getCode()));

        MvcResult created = mockMvc.perform(post("/api/admin/embed-policies")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"parent_client_id":"%s","child_client_id":"%s","parent_origin":"%s","allowed_path":"/orders/*"}
                                """.formatted(parentId, childId, ORIGIN)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(RegistryStatus.INACTIVE))
                .andReturn();
        String policyId = com.jayway.jsonpath.JsonPath.read(created.getResponse().getContentAsString(), "$.id");
        mockMvc.perform(post("/api/admin/embed-policies/" + policyId + "/enable")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(RegistryStatus.ACTIVE));

        assertThat(embedPolicyRepository.findById(UUID.fromString(policyId)).orElseThrow().getStatus())
                .isEqualTo(RegistryStatus.ACTIVE);
        embedPolicyService.requireActive(parentId, childId, ORIGIN, "/orders/1");

        MvcResult login = mockMvc.perform(post("/sso/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"%s","tenant_id":"admin-cli","client_id":"%s"}
                                """.formatted(user.username(), parentId)))
                .andExpect(status().isOk())
                .andReturn();
        Cookie session = login.getResponse().getCookie(SsoCookieService.COOKIE_NAME);
        Cookie csrf = login.getResponse().getCookie(CsrfTokenService.COOKIE);
        mockMvc.perform(post("/api/embed/code")
                        .cookie(session, csrf)
                        .header(CsrfTokenService.HEADER, csrf.getValue())
                        .header(HttpHeaders.ORIGIN, ORIGIN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"child_client_id":"%s","path":"/orders/1","origin":"%s","nonce":"n1"}
                                """.formatted(childId, ORIGIN)))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/admin/embed-policies/" + policyId + "/disable")
                        .header(HttpHeaders.AUTHORIZATION, auditorBearer))
                .andExpect(status().isForbidden());
        mockMvc.perform(post("/api/admin/embed-policies/" + policyId + "/disable")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(RegistryStatus.INACTIVE));
        assertThat(embedPolicyRepository.findById(UUID.fromString(policyId)).orElseThrow().getStatus())
                .isEqualTo(RegistryStatus.INACTIVE);
        assertThatThrownBy(() -> embedPolicyService.requireActive(parentId, childId, ORIGIN, "/orders/1"))
                .extracting(ex -> ((IamException) ex).getErrorCode())
                .isEqualTo(IamErrorCode.EMBED_POLICY_DISABLED);
        mockMvc.perform(post("/api/embed/code")
                        .cookie(session, csrf)
                        .header(CsrfTokenService.HEADER, csrf.getValue())
                        .header(HttpHeaders.ORIGIN, ORIGIN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"child_client_id":"%s","path":"/orders/1","origin":"%s","nonce":"n2"}
                                """.formatted(childId, ORIGIN)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value(IamErrorCode.EMBED_POLICY_DISABLED.getCode()));
        assertThat(auditLogRepository.findAll())
                .anyMatch(row -> AuditEvent.EMBED_POLICY_CHANGED.name().equals(row.getEventType()));
    }

    @Test
    void tokenExchangeAdminApiDisableHitsEvaluatorAndProtocol() throws Exception {
        String clientId = "p8x-" + suffix;
        clientService.create(new CreateClientRequest(
                clientId, "X", "confidential", RegistryStatus.ACTIVE, "client_secret_basic", 600, 86400, true, "iam",
                List.of(new RedirectUriInput(LOGIN, "LOGIN_CALLBACK")), SECRET));
        UserResponse user = userService.create(new CreateUserRequest(
                "p8xu" + suffix, "U", "p8xu" + suffix + "@example.com", "admin-cli", null, "ACTIVE"));
        String src = "SRC8-" + suffix;
        String te = "TE8-" + suffix;
        resourceService.create(new CreateResourceRequest(src, "S", "src8-" + suffix, RegistryStatus.ACTIVE, "iam"));
        scopeService.create(new CreateScopeRequest(src, "openid", "OpenID", "openid", RegistryStatus.ACTIVE));
        resourceService.create(new CreateResourceRequest(te, "T", "te8-" + suffix, RegistryStatus.ACTIVE, "iam"));
        scopeService.create(new CreateScopeRequest(te, "order.read", "R", "r", RegistryStatus.ACTIVE));
        mockMvc.perform(post("/api/admin/token-exchange/permissions")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"client_id":"%s","resource_code":"%s","scope_code":"order.read","grant_type":"TOKEN_EXCHANGE"}
                                """.formatted(clientId, te)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(RegistryStatus.INACTIVE));
        mockMvc.perform(post("/api/admin/token-exchange/permissions/enable")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"client_id":"%s","resource_code":"%s","scope_code":"order.read","grant_type":"TOKEN_EXCHANGE"}
                                """.formatted(clientId, te)))
                .andExpect(status().isOk());
        Instant now = Instant.now();
        String subjectToken = accessTokenService.issue(new AccessTokenClaims(
                user.subjectId(),
                List.of("src8-" + suffix),
                clientId,
                "openid",
                List.of(),
                "admin-cli",
                null,
                now,
                now.plusSeconds(600),
                "jti-p8-" + suffix,
                null,
                null));
        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .header(HttpHeaders.AUTHORIZATION, "Basic " + HttpHeaders.encodeBasicAuth(clientId, SECRET, StandardCharsets.UTF_8))
                        .param("grant_type", EXCHANGE_GRANT)
                        .param("subject_token", subjectToken)
                        .param("subject_token_type", ACCESS_TYPE)
                        .param("audience", "te8-" + suffix)
                        .param("scope", "order.read"))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/admin/token-exchange/permissions/disable")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"client_id":"%s","resource_code":"%s","scope_code":"order.read","grant_type":"TOKEN_EXCHANGE"}
                                """.formatted(clientId, te)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(RegistryStatus.INACTIVE));
        assertThatThrownBy(() ->
                        tokenExchangePolicyService.requireExchangePermission(clientId, "te8-" + suffix, List.of("order.read")))
                .extracting(ex -> ((IamException) ex).getErrorCode())
                .isEqualTo(IamErrorCode.TOKEN_EXCHANGE_NOT_ALLOWED);
        assertThatThrownBy(() -> policyEvaluator.validateTokenExchangePermission(clientId, "te8-" + suffix, "order.read"))
                .extracting(ex -> ((IamException) ex).getErrorCode())
                .isEqualTo(IamErrorCode.TOKEN_EXCHANGE_NOT_ALLOWED);
        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .header(HttpHeaders.AUTHORIZATION, "Basic " + HttpHeaders.encodeBasicAuth(clientId, SECRET, StandardCharsets.UTF_8))
                        .param("grant_type", EXCHANGE_GRANT)
                        .param("subject_token", subjectToken)
                        .param("subject_token_type", ACCESS_TYPE)
                        .param("audience", "te8-" + suffix)
                        .param("scope", "order.read"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value(IamErrorCode.TOKEN_EXCHANGE_NOT_ALLOWED.getCode()));
        assertThat(auditLogRepository.findAll())
                .anyMatch(row -> AuditEvent.POLICY_CHANGED.name().equals(row.getEventType())
                        && row.getDetail() != null
                        && row.getDetail().contains("TOKEN_EXCHANGE"));
    }

    @Test
    void signingKeyRotateUpdatesJwksAndKeepsOldJwt() throws Exception {
        String oldKid = signingKeyService.getActiveKey().kid();
        Instant now = Instant.now();
        String oldJwt = jwtSigner
                .sign(new JWTClaimsSet.Builder()
                        .subject("p8-sub")
                        .issueTime(Date.from(now))
                        .expirationTime(Date.from(now.plusSeconds(600)))
                        .build())
                .serialize();

        mockMvc.perform(post("/api/admin/signing-keys/rotate")
                        .header(HttpHeaders.AUTHORIZATION, auditorBearer)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"confirm\":true}"))
                .andExpect(status().isForbidden());
        mockMvc.perform(post("/api/admin/signing-keys/rotate")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest());

        MvcResult rotated = mockMvc.perform(post("/api/admin/signing-keys/rotate")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"confirm\":true}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.kid").isNotEmpty())
                .andExpect(jsonPath("$.algorithm").value("RS256"))
                .andExpect(jsonPath("$.privateKey").doesNotExist())
                .andReturn();
        String body = rotated.getResponse().getContentAsString();
        assertThat(body).doesNotContain("BEGIN");
        assertThat(body.toLowerCase()).doesNotContain("private");
        String newKid = com.jayway.jsonpath.JsonPath.read(body, "$.kid");
        assertThat(newKid).isNotEqualTo(oldKid);
        assertThat(signingKeyService.getActiveKey().kid()).isEqualTo(newKid);

        MvcResult jwks = mockMvc.perform(get("/.well-known/jwks.json")).andExpect(status().isOk()).andReturn();
        String jwksBody = jwks.getResponse().getContentAsString();
        assertThat(jwksBody).contains(oldKid);
        assertThat(jwksBody).contains(newKid);
        assertThat(jwksBody).doesNotContain("BEGIN PRIVATE");

        assertThat(jwtSigner.verify(oldJwt).getJWTClaimsSet().getSubject()).isEqualTo("p8-sub");
        mockMvc.perform(get("/api/admin/signing-keys").header(HttpHeaders.AUTHORIZATION, auditorBearer))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].kid").isNotEmpty());
        assertThat(auditLogRepository.findAll())
                .anyMatch(row -> AuditEvent.SIGNING_KEY_ROTATED.name().equals(row.getEventType())
                        && row.getDetail() != null
                        && row.getDetail().contains(newKid)
                        && !row.getDetail().toLowerCase().contains("private"));
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
