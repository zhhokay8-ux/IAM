package com.example.iam.authorizationserver.admin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
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
import com.example.iam.authorizationserver.sso.SsoTestPassword;
import com.example.iam.clientregistry.domain.RegistryStatus;
import com.example.iam.clientregistry.dto.CreatePermissionRequest;
import com.example.iam.clientregistry.dto.CreateResourceRequest;
import com.example.iam.clientregistry.dto.CreateScopeRequest;
import com.example.iam.clientregistry.entity.IamClientEntity;
import com.example.iam.clientregistry.repository.IamClientRepository;
import com.example.iam.clientregistry.service.IamPermissionService;
import com.example.iam.clientregistry.service.IamResourceService;
import com.example.iam.clientregistry.service.IamScopeService;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.common.util.HashUtils;
import com.example.iam.policy.IamPolicyEvaluator;
import com.example.iam.token.signing.JwtSigner;
import com.example.iam.user.dto.CreateUserRequest;
import com.example.iam.user.dto.UserResponse;
import com.example.iam.user.service.IamUserService;
import com.nimbusds.jwt.JWTClaimsSet;
import jakarta.servlet.http.Cookie;
import java.nio.charset.StandardCharsets;
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
class AdminClientManagementIntegrationTest extends AbstractIamIntegrationTest {

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

    @BeforeEach
    void setUp() {
        suffix = UUID.randomUUID().toString().substring(0, 8);
        UserResponse admin = userService.create(new CreateUserRequest(
                "cadm" + suffix, "Admin", "cadm" + suffix + "@example.com", "admin-cli", null, "ACTIVE"));
        bind(admin, AdminRoles.IAM_ADMIN);
        adminBearer = bearer(admin.subjectId());
    }

    @Test
    void createDefaultsInactiveAndRuntimeRejectsUntilEnableThenDisableStopsAuthorize() throws Exception {
        String clientId = "app-" + suffix;
        MvcResult created = mockMvc.perform(post("/api/admin/clients")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"client_id":"%s","client_name":"App","client_type":"confidential",
                                 "redirect_uris":[{"redirectUri":"%s","uriType":"LOGIN_CALLBACK"}]}
                                """.formatted(clientId, LOGIN)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.client.status").value(RegistryStatus.INACTIVE))
                .andExpect(jsonPath("$.client_secret").isNotEmpty())
                .andExpect(jsonPath("$.client.clientSecretHash").doesNotExist())
                .andReturn();
        String secret = com.jayway.jsonpath.JsonPath.read(created.getResponse().getContentAsString(), "$.client_secret");
        assertThat(created.getResponse().getContentAsString()).doesNotContain("client_secret_hash");

        IamClientEntity row = clientRepository.findByClientId(clientId).orElseThrow();
        assertThat(row.getStatus()).isEqualTo(RegistryStatus.INACTIVE);
        assertThat(row.getClientSecretHash()).isEqualTo(HashUtils.sha256Hex(secret));
        assertThatThrownBy(() -> policyEvaluator.validateClient(clientId))
                .isInstanceOf(IamException.class)
                .extracting(ex -> ((IamException) ex).getErrorCode())
                .isEqualTo(IamErrorCode.CLIENT_INACTIVE);

        mockMvc.perform(get("/api/admin/clients/" + clientId).header(HttpHeaders.AUTHORIZATION, adminBearer))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.client_secret").doesNotExist())
                .andExpect(jsonPath("$.clientSecret").doesNotExist());

        mockMvc.perform(post("/api/admin/clients/" + clientId + "/enable")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(RegistryStatus.ACTIVE));
        assertThat(clientRepository.findByClientId(clientId).orElseThrow().getStatus()).isEqualTo(RegistryStatus.ACTIVE);
        assertThat(policyEvaluator.validateClient(clientId).getClientId()).isEqualTo(clientId);

        grantAuthorize(clientId);
        Cookie session = sso(clientId);
        mockMvc.perform(authorize(clientId, session, "on"))
                .andExpect(status().isFound())
                .andExpect(result -> assertThat(result.getResponse().getHeader(HttpHeaders.LOCATION)).contains("code="));

        mockMvc.perform(post("/api/admin/clients/" + clientId + "/disable")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(RegistryStatus.INACTIVE));
        assertThat(clientRepository.findByClientId(clientId).orElseThrow().getStatus()).isEqualTo(RegistryStatus.INACTIVE);
        assertThatThrownBy(() -> policyEvaluator.validateClient(clientId))
                .extracting(ex -> ((IamException) ex).getErrorCode())
                .isEqualTo(IamErrorCode.CLIENT_INACTIVE);
        mockMvc.perform(authorize(clientId, session, "off"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value(IamErrorCode.CLIENT_INACTIVE.getCode()));
        assertThat(auditLogRepository.findAll())
                .anyMatch(rowAudit -> AuditEvent.CLIENT_DISABLED.name().equals(rowAudit.getEventType())
                        && rowAudit.getDetail() != null
                        && rowAudit.getDetail().contains(clientId));
        assertThat(auditLogRepository.findAll())
                .noneMatch(rowAudit -> rowAudit.getDetail() != null && rowAudit.getDetail().contains(secret));
    }

    @Test
    void rotateSecretInvalidatesOldSecretOnTokenEndpoint() throws Exception {
        String clientId = "rot-" + suffix;
        MvcResult created = mockMvc.perform(post("/api/admin/clients")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"client_id":"%s","client_name":"Rot","client_type":"confidential",
                                 "redirect_uris":[{"redirectUri":"%s","uriType":"LOGIN_CALLBACK"}]}
                                """.formatted(clientId, LOGIN)))
                .andExpect(status().isOk())
                .andReturn();
        String oldSecret =
                com.jayway.jsonpath.JsonPath.read(created.getResponse().getContentAsString(), "$.client_secret");
        mockMvc.perform(post("/api/admin/clients/" + clientId + "/enable")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer))
                .andExpect(status().isOk());
        String resource = "RES-" + suffix;
        String audience = "aud-" + suffix;
        resourceService.create(new CreateResourceRequest(resource, "R", audience, RegistryStatus.ACTIVE, "iam"));
        scopeService.create(new CreateScopeRequest(resource, "data.read", "Read", "r", RegistryStatus.ACTIVE));
        permissionService.create(new CreatePermissionRequest(
                clientId, resource, "data.read", "client_credentials", RegistryStatus.ACTIVE));

        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .header(
                                HttpHeaders.AUTHORIZATION,
                                "Basic " + HttpHeaders.encodeBasicAuth(clientId, oldSecret, StandardCharsets.UTF_8))
                        .param("grant_type", "client_credentials")
                        .param("audience", audience)
                        .param("scope", "data.read"))
                .andExpect(status().isOk());

        String oldHash = clientRepository.findByClientId(clientId).orElseThrow().getClientSecretHash();
        MvcResult rotated = mockMvc.perform(post("/api/admin/clients/" + clientId + "/rotate-secret")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.client_secret").isNotEmpty())
                .andReturn();
        String newSecret =
                com.jayway.jsonpath.JsonPath.read(rotated.getResponse().getContentAsString(), "$.client_secret");
        assertThat(newSecret).isNotEqualTo(oldSecret);
        assertThat(clientRepository.findByClientId(clientId).orElseThrow().getClientSecretHash())
                .isNotEqualTo(oldHash)
                .isEqualTo(HashUtils.sha256Hex(newSecret));

        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .header(
                                HttpHeaders.AUTHORIZATION,
                                "Basic " + HttpHeaders.encodeBasicAuth(clientId, oldSecret, StandardCharsets.UTF_8))
                        .param("grant_type", "client_credentials")
                        .param("audience", audience)
                        .param("scope", "data.read"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value(IamErrorCode.INVALID_CLIENT.getCode()));
        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .header(
                                HttpHeaders.AUTHORIZATION,
                                "Basic " + HttpHeaders.encodeBasicAuth(clientId, newSecret, StandardCharsets.UTF_8))
                        .param("grant_type", "client_credentials")
                        .param("audience", audience)
                        .param("scope", "data.read"))
                .andExpect(status().isOk());
        assertThat(auditLogRepository.findAll())
                .anyMatch(row -> AuditEvent.SECRET_ROTATED.name().equals(row.getEventType()));
    }

    @Test
    void redirectUriChangeIsEnforcedByAuthorize() throws Exception {
        String clientId = "uri-" + suffix;
        mockMvc.perform(post("/api/admin/clients")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"client_id":"%s","client_name":"Uri","client_type":"confidential",
                                 "redirect_uris":[{"redirectUri":"%s","uriType":"LOGIN_CALLBACK"}]}
                                """.formatted(clientId, LOGIN)))
                .andExpect(status().isOk());
        mockMvc.perform(post("/api/admin/clients/" + clientId + "/enable")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer))
                .andExpect(status().isOk());
        String next = "https://app.example.com/new/callback";
        mockMvc.perform(put("/api/admin/clients/" + clientId + "/redirect-uris")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("[{\"redirectUri\":\"%s\",\"uriType\":\"LOGIN_CALLBACK\"}]".formatted(next)))
                .andExpect(status().isOk());
        grantAuthorize(clientId);
        Cookie session = sso(clientId);
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
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value(IamErrorCode.INVALID_REDIRECT_URI.getCode()));
        mockMvc.perform(get("/oauth2/authorize")
                        .param("client_id", clientId)
                        .param("redirect_uri", next)
                        .param("response_type", "code")
                        .param("scope", "openid")
                        .param("state", "st2")
                        .param("nonce", "nn2")
                        .param("code_challenge", CHALLENGE)
                        .param("code_challenge_method", "S256")
                        .cookie(session))
                .andExpect(status().isFound())
                .andExpect(result -> assertThat(result.getResponse().getHeader(HttpHeaders.LOCATION)).contains("code="));
    }

    @Test
    void duplicateAndWildcardAndAuditor() throws Exception {
        String clientId = "dup-" + suffix;
        mockMvc.perform(post("/api/admin/clients")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"client_id":"%s","client_name":"Dup","client_type":"confidential",
                                 "redirect_uris":[{"redirectUri":"%s","uriType":"LOGIN_CALLBACK"}]}
                                """.formatted(clientId, LOGIN)))
                .andExpect(status().isOk());
        mockMvc.perform(post("/api/admin/clients")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"client_id":"%s","client_name":"Dup","client_type":"confidential"}
                                """.formatted(clientId)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value(IamErrorCode.DUPLICATE_CLIENT_ID.getCode()));
        mockMvc.perform(post("/api/admin/clients")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"client_id":"wild-%s","client_name":"W","client_type":"confidential",
                                 "redirect_uris":[{"redirectUri":"https://evil.example.com/*","uriType":"LOGIN_CALLBACK"}]}
                                """.formatted(suffix)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value(IamErrorCode.INVALID_REDIRECT_URI.getCode()));

        UserResponse auditor = userService.create(new CreateUserRequest(
                "audc" + suffix, "A", "audc" + suffix + "@example.com", "admin-cli", null, "ACTIVE"));
        bind(auditor, AdminRoles.IAM_AUDITOR);
        mockMvc.perform(post("/api/admin/clients")
                        .header(HttpHeaders.AUTHORIZATION, bearer(auditor.subjectId()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"client_id":"nope-%s","client_name":"Nope","client_type":"confidential"}
                                """.formatted(suffix)))
                .andExpect(status().isForbidden());
        assertThat(clientRepository.findByClientId("nope-" + suffix)).isEmpty();

        mockMvc.perform(get("/api/admin/clients").param("q", clientId).header(HttpHeaders.AUTHORIZATION, adminBearer))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].clientId").value(clientId))
                .andExpect(jsonPath("$.totalElements").value(1));
    }

    private void grantAuthorize(String clientId) {
        String resource = "OIDC-" + clientId;
        resourceService.create(
                new CreateResourceRequest(resource, "OIDC", "oidc-" + clientId, RegistryStatus.ACTIVE, "iam"));
        scopeService.create(new CreateScopeRequest(resource, "openid", "OpenID", "openid", RegistryStatus.ACTIVE));
        permissionService.create(
                new CreatePermissionRequest(clientId, resource, "openid", "authorization_code", RegistryStatus.ACTIVE));
    }

    private Cookie sso(String clientId) throws Exception {
        UserResponse user = userService.create(new CreateUserRequest(
                "u" + clientId, "U", "u" + clientId + "@example.com", "admin-cli", null, "ACTIVE", SsoTestPassword.RAW));
        MvcResult result = mockMvc.perform(post("/sso/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"%s","password":"%s","tenant_id":"admin-cli","client_id":"%s"}
                                """.formatted(user.username(), SsoTestPassword.RAW, clientId)))
                .andExpect(status().isOk())
                .andReturn();
        return result.getResponse().getCookie(SsoCookieService.COOKIE_NAME);
    }

    private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder authorize(
            String clientId, Cookie session, String tag) {
        return get("/oauth2/authorize")
                .param("client_id", clientId)
                .param("redirect_uri", LOGIN)
                .param("response_type", "code")
                .param("scope", "openid")
                .param("state", tag + suffix)
                .param("nonce", tag + "n" + suffix)
                .param("code_challenge", CHALLENGE)
                .param("code_challenge_method", "S256")
                .cookie(session);
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
