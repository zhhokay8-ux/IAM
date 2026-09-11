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
import com.example.iam.clientregistry.dto.RedirectUriInput;
import com.example.iam.clientregistry.entity.IamClientResourcePermissionEntity;
import com.example.iam.clientregistry.repository.IamClientResourcePermissionRepository;
import com.example.iam.clientregistry.repository.IamResourceServerRepository;
import com.example.iam.clientregistry.repository.IamScopeRepository;
import com.example.iam.clientregistry.service.IamClientService;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.policy.IamPolicyEvaluator;
import com.example.iam.token.oauth.AccessTokenClaims;
import com.example.iam.token.oauth.AccessTokenService;
import com.example.iam.token.signing.JwtSigner;
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
class AdminResourceScopePermissionIntegrationTest extends AbstractIamIntegrationTest {

    private static final String LOGIN = "https://app.example.com/login/callback";
    private static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private static final String SECRET = "phase4-secret";
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
    private IamResourceServerRepository resourceRepository;

    @Autowired
    private IamScopeRepository scopeRepository;

    @Autowired
    private IamClientResourcePermissionRepository permissionRepository;

    @Autowired
    private IamPolicyEvaluator policyEvaluator;

    @Autowired
    private IamAuditLogRepository auditLogRepository;

    @Autowired
    private AccessTokenService accessTokenService;

    private String suffix;
    private String adminBearer;
    private String clientId;
    private UserResponse endUser;

    @BeforeEach
    void setUp() {
        suffix = UUID.randomUUID().toString().substring(0, 8);
        UserResponse admin = userService.create(new CreateUserRequest(
                "radm" + suffix, "Admin", "radm" + suffix + "@example.com", "admin-cli", null, "ACTIVE"));
        bind(admin, AdminRoles.IAM_ADMIN);
        adminBearer = bearer(admin.subjectId());
        clientId = "p4-" + suffix;
        clientService.create(new CreateClientRequest(
                clientId,
                "P4",
                "confidential",
                RegistryStatus.ACTIVE,
                "client_secret_basic",
                600,
                86400,
                true,
                "iam",
                List.of(new RedirectUriInput(LOGIN, "LOGIN_CALLBACK")),
                SECRET));
        endUser = userService.create(new CreateUserRequest(
                "u" + suffix, "U", "u" + suffix + "@example.com", "admin-cli", null, "ACTIVE"));
    }

    @Test
    void disableResourceStopsClientCredentials() throws Exception {
        String resource = "RES-" + suffix;
        String audience = "aud-" + suffix;
        String scope = "data.read";
        createEnabledResource(resource, audience);
        createEnabledScope(resource, scope);
        createEnabledPermission(clientId, resource, scope, "client_credentials");

        mockMvc.perform(cc(audience, scope)).andExpect(status().isOk());
        assertThat(policyEvaluator.validateAudience(audience).getResourceCode()).isEqualTo(resource);

        mockMvc.perform(post("/api/admin/resources/" + resource + "/disable")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(RegistryStatus.INACTIVE));
        assertThat(resourceRepository.findByResourceCode(resource).orElseThrow().getStatus())
                .isEqualTo(RegistryStatus.INACTIVE);
        assertThatThrownBy(() -> policyEvaluator.validateAudience(audience))
                .isInstanceOf(IamException.class)
                .extracting(ex -> ((IamException) ex).getErrorCode())
                .isEqualTo(IamErrorCode.FORBIDDEN);
        mockMvc.perform(cc(audience, scope))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value(IamErrorCode.FORBIDDEN.getCode()));
        assertThat(auditLogRepository.findAll())
                .anyMatch(row -> AuditEvent.RESOURCE_DISABLED.name().equals(row.getEventType())
                        && row.getDetail() != null
                        && row.getDetail().contains(resource));
    }

    @Test
    void disableScopeStopsAuthorize() throws Exception {
        String resource = "OIDC-" + suffix;
        String audience = "oidc-" + suffix;
        createEnabledResource(resource, audience);
        createEnabledScope(resource, "openid");
        createEnabledPermission(clientId, resource, "openid", "authorization_code");
        policyEvaluator.validateScope(audience, "openid");
        Cookie session = sso();
        mockMvc.perform(authorize(session, "on"))
                .andExpect(status().isFound())
                .andExpect(result -> assertThat(result.getResponse().getHeader(HttpHeaders.LOCATION)).contains("code="));

        mockMvc.perform(post("/api/admin/scopes/" + resource + "/openid/disable")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(RegistryStatus.INACTIVE));
        assertThat(scopeRepository
                        .findByResourceIdAndScopeCode(
                                resourceRepository.findByResourceCode(resource).orElseThrow().getId(), "openid")
                        .orElseThrow()
                        .getStatus())
                .isEqualTo(RegistryStatus.INACTIVE);
        assertThatThrownBy(() -> policyEvaluator.validateScope(audience, "openid"))
                .extracting(ex -> ((IamException) ex).getErrorCode())
                .isEqualTo(IamErrorCode.SCOPE_INACTIVE);
        mockMvc.perform(authorize(session, "off"))
                .andExpect(status().isFound())
                .andExpect(result ->
                        assertThat(result.getResponse().getHeader(HttpHeaders.LOCATION)).contains("error=invalid_scope"));
        assertThat(auditLogRepository.findAll())
                .anyMatch(row -> AuditEvent.SCOPE_DISABLED.name().equals(row.getEventType())
                        && row.getDetail() != null
                        && row.getDetail().contains("openid"));
    }

    @Test
    void permissionDisableAffectsCcExchangeAndAuthorize() throws Exception {
        String ccResource = "CC-" + suffix;
        String ccAudience = "cc-aud-" + suffix;
        String teResource = "TE-" + suffix;
        String teAudience = "te-aud-" + suffix;
        String srcResource = "SRC-" + suffix;
        String srcAudience = "src-aud-" + suffix;
        String oidcResource = "OIDC2-" + suffix;
        String oidcAudience = "oidc2-" + suffix;

        createEnabledResource(ccResource, ccAudience);
        createEnabledScope(ccResource, "data.read");
        createEnabledPermission(clientId, ccResource, "data.read", "client_credentials");

        createEnabledResource(srcResource, srcAudience);
        createEnabledScope(srcResource, "openid");
        createEnabledResource(teResource, teAudience);
        createEnabledScope(teResource, "order.read");
        createEnabledPermission(clientId, teResource, "order.read", "TOKEN_EXCHANGE");

        createEnabledResource(oidcResource, oidcAudience);
        createEnabledScope(oidcResource, "openid");
        createEnabledPermission(clientId, oidcResource, "openid", "authorization_code");

        mockMvc.perform(cc(ccAudience, "data.read")).andExpect(status().isOk());
        String subjectToken = issueSubjectToken(srcAudience);
        mockMvc.perform(exchange(subjectToken, teAudience, "order.read")).andExpect(status().isOk());
        Cookie session = sso();
        mockMvc.perform(authorize(session, "ok"))
                .andExpect(status().isFound())
                .andExpect(result -> assertThat(result.getResponse().getHeader(HttpHeaders.LOCATION)).contains("code="));

        disablePermission(clientId, ccResource, "data.read", "client_credentials");
        assertPermStatus(clientId, ccResource, "CLIENT_CREDENTIALS", RegistryStatus.INACTIVE);
        assertThatThrownBy(() ->
                        policyEvaluator.validateClientCredentialsPermission(clientId, ccAudience, "data.read"))
                .extracting(ex -> ((IamException) ex).getErrorCode())
                .isEqualTo(IamErrorCode.CLIENT_CREDENTIALS_NOT_ALLOWED);
        mockMvc.perform(cc(ccAudience, "data.read"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value(IamErrorCode.PERMISSION_DENIED.getCode()));

        disablePermission(clientId, teResource, "order.read", "TOKEN_EXCHANGE");
        assertPermStatus(clientId, teResource, "TOKEN_EXCHANGE", RegistryStatus.INACTIVE);
        assertThatThrownBy(() ->
                        policyEvaluator.validateTokenExchangePermission(clientId, teAudience, "order.read"))
                .extracting(ex -> ((IamException) ex).getErrorCode())
                .isEqualTo(IamErrorCode.TOKEN_EXCHANGE_NOT_ALLOWED);
        mockMvc.perform(exchange(subjectToken, teAudience, "order.read"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value(IamErrorCode.TOKEN_EXCHANGE_NOT_ALLOWED.getCode()));

        disablePermission(clientId, oidcResource, "openid", "authorization_code");
        assertPermStatus(clientId, oidcResource, "AUTHORIZATION_CODE", RegistryStatus.INACTIVE);
        assertThatThrownBy(() -> policyEvaluator.validateAuthorizationCodeScopes(clientId, List.of("openid")))
                .extracting(ex -> ((IamException) ex).getErrorCode())
                .isEqualTo(IamErrorCode.PERMISSION_DENIED);
        mockMvc.perform(authorize(session, "deny"))
                .andExpect(status().isFound())
                .andExpect(result ->
                        assertThat(result.getResponse().getHeader(HttpHeaders.LOCATION)).contains("error=invalid_scope"));

        assertThat(auditLogRepository.findAll())
                .filteredOn(row -> AuditEvent.POLICY_CHANGED.name().equals(row.getEventType()))
                .anyMatch(row -> row.getDetail() != null && row.getDetail().contains("TOKEN_EXCHANGE"))
                .anyMatch(row -> row.getDetail() != null && row.getDetail().contains("CLIENT_CREDENTIALS"))
                .anyMatch(row -> row.getDetail() != null && row.getDetail().contains("AUTHORIZATION_CODE"));
    }

    @Test
    void duplicateIllegalBindAndAuditor() throws Exception {
        String resource = "DUP-" + suffix;
        createEnabledResource(resource, "dup-" + suffix);
        mockMvc.perform(post("/api/admin/resources")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"resource_code":"%s","resource_name":"Dup","audience":"other-%s"}
                                """.formatted(resource, suffix)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value(IamErrorCode.DUPLICATE_RESOURCE.getCode()));

        mockMvc.perform(post("/api/admin/scopes")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"resource_code":"missing-%s","scope_code":"x","scope_name":"X"}
                                """.formatted(suffix)))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.code").value(IamErrorCode.RESOURCE_NOT_FOUND.getCode()));

        createEnabledScope(resource, "a.read");
        mockMvc.perform(post("/api/admin/scopes")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"resource_code":"%s","scope_code":"a.read","scope_name":"A"}
                                """.formatted(resource)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value(IamErrorCode.DUPLICATE_SCOPE.getCode()));

        UserResponse auditor = userService.create(new CreateUserRequest(
                "raud" + suffix, "A", "raud" + suffix + "@example.com", "admin-cli", null, "ACTIVE"));
        bind(auditor, AdminRoles.IAM_AUDITOR);
        mockMvc.perform(post("/api/admin/resources")
                        .header(HttpHeaders.AUTHORIZATION, bearer(auditor.subjectId()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"resource_code":"nope-%s","resource_name":"Nope","audience":"nope-%s"}
                                """.formatted(suffix, suffix)))
                .andExpect(status().isForbidden());
        assertThat(resourceRepository.findByResourceCode("nope-" + suffix)).isEmpty();

        mockMvc.perform(get("/api/admin/resources")
                        .param("q", resource)
                        .header(HttpHeaders.AUTHORIZATION, adminBearer))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].resourceCode").value(resource));
    }

    private void createEnabledResource(String resourceCode, String audience) throws Exception {
        mockMvc.perform(post("/api/admin/resources")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"resource_code":"%s","resource_name":"%s","audience":"%s"}
                                """.formatted(resourceCode, resourceCode, audience)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(RegistryStatus.INACTIVE));
        mockMvc.perform(post("/api/admin/resources/" + resourceCode + "/enable")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer))
                .andExpect(status().isOk());
    }

    private void createEnabledScope(String resourceCode, String scopeCode) throws Exception {
        mockMvc.perform(post("/api/admin/scopes")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"resource_code":"%s","scope_code":"%s","scope_name":"%s"}
                                """.formatted(resourceCode, scopeCode, scopeCode)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(RegistryStatus.INACTIVE));
        mockMvc.perform(post("/api/admin/scopes/" + resourceCode + "/" + scopeCode + "/enable")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer))
                .andExpect(status().isOk());
    }

    private void createEnabledPermission(String client, String resource, String scope, String grant) throws Exception {
        mockMvc.perform(post("/api/admin/permissions")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"client_id":"%s","resource_code":"%s","scope_code":"%s","grant_type":"%s"}
                                """.formatted(client, resource, scope, grant)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(RegistryStatus.INACTIVE));
        mockMvc.perform(post("/api/admin/permissions/enable")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"client_id":"%s","resource_code":"%s","scope_code":"%s","grant_type":"%s"}
                                """.formatted(client, resource, scope, grant)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(RegistryStatus.ACTIVE));
    }

    private void disablePermission(String client, String resource, String scope, String grant) throws Exception {
        mockMvc.perform(post("/api/admin/permissions/disable")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"client_id":"%s","resource_code":"%s","scope_code":"%s","grant_type":"%s"}
                                """.formatted(client, resource, scope, grant)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(RegistryStatus.INACTIVE));
    }

    private void assertPermStatus(String client, String resource, String grantName, String status) {
        UUID clientPk = clientService.get(client).id();
        UUID resourcePk = resourceRepository.findByResourceCode(resource).orElseThrow().getId();
        List<IamClientResourcePermissionEntity> rows =
                permissionRepository.findByClientIdAndResourceId(clientPk, resourcePk);
        assertThat(rows)
                .anyMatch(row -> grantName.equals(row.getGrantType()) && status.equals(row.getStatus()));
    }

    private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder cc(
            String audience, String scope) {
        return post("/oauth2/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header(
                        HttpHeaders.AUTHORIZATION,
                        "Basic " + HttpHeaders.encodeBasicAuth(clientId, SECRET, StandardCharsets.UTF_8))
                .param("grant_type", "client_credentials")
                .param("audience", audience)
                .param("scope", scope);
    }

    private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder exchange(
            String subjectToken, String audience, String scope) {
        return post("/oauth2/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header(
                        HttpHeaders.AUTHORIZATION,
                        "Basic " + HttpHeaders.encodeBasicAuth(clientId, SECRET, StandardCharsets.UTF_8))
                .param("grant_type", EXCHANGE_GRANT)
                .param("subject_token", subjectToken)
                .param("subject_token_type", ACCESS_TYPE)
                .param("audience", audience)
                .param("scope", scope);
    }

    private String issueSubjectToken(String audience) {
        Instant now = Instant.now();
        return accessTokenService.issue(new AccessTokenClaims(
                endUser.subjectId(),
                List.of(audience),
                clientId,
                "openid",
                List.of(),
                "admin-cli",
                null,
                now,
                now.plusSeconds(600),
                "jti-" + suffix,
                null,
                null));
    }

    private Cookie sso() throws Exception {
        MvcResult result = mockMvc.perform(post("/sso/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"%s","tenant_id":"admin-cli","client_id":"%s"}
                                """.formatted(endUser.username(), clientId)))
                .andExpect(status().isOk())
                .andReturn();
        return result.getResponse().getCookie(SsoCookieService.COOKIE_NAME);
    }

    private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder authorize(Cookie session, String tag) {
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
