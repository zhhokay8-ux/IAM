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
import com.example.iam.authorizationserver.oauth.introspect.TokenIntrospectionService;
import com.example.iam.authorizationserver.sso.SsoCookieService;
import com.example.iam.clientregistry.domain.RegistryStatus;
import com.example.iam.clientregistry.dto.CreateClientRequest;
import com.example.iam.clientregistry.dto.CreatePermissionRequest;
import com.example.iam.clientregistry.dto.CreateResourceRequest;
import com.example.iam.clientregistry.dto.CreateScopeRequest;
import com.example.iam.clientregistry.dto.RedirectUriInput;
import com.example.iam.clientregistry.service.IamClientService;
import com.example.iam.clientregistry.service.IamPermissionService;
import com.example.iam.clientregistry.service.IamResourceService;
import com.example.iam.clientregistry.service.IamScopeService;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.session.IamSessionService;
import com.example.iam.token.entity.IamRefreshTokenEntity;
import com.example.iam.token.oauth.AccessTokenClaims;
import com.example.iam.token.oauth.AccessTokenService;
import com.example.iam.token.oauth.RefreshTokenService;
import com.example.iam.token.repository.IamRefreshTokenRepository;
import com.example.iam.token.signing.JwtSigner;
import com.example.iam.user.domain.UserStatus;
import com.example.iam.user.dto.UserResponse;
import com.example.iam.user.repository.IamUserIdentityMappingRepository;
import com.example.iam.user.repository.IamUserRepository;
import com.example.iam.user.service.IamUserService;
import com.nimbusds.jwt.JWTClaimsSet;
import jakarta.servlet.http.Cookie;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
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
class AdminUserManagementIntegrationTest extends AbstractIamIntegrationTest {

    private static final String LOGIN = "https://app.example.com/login/callback";
    private static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private static final String SECRET = "phase5-secret";
    private static final String EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";
    private static final String ACCESS_TYPE = "urn:ietf:params:oauth:token-type:access_token";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private IamUserService userService;

    @Autowired
    private IamUserRepository userRepository;

    @Autowired
    private IamUserIdentityMappingRepository mappingRepository;

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
    private IamSessionService sessionService;

    @Autowired
    private IamAuditLogRepository auditLogRepository;

    @Autowired
    private AccessTokenService accessTokenService;

    @Autowired
    private RefreshTokenService refreshTokenService;

    @Autowired
    private IamRefreshTokenRepository refreshTokenRepository;

    @Autowired
    private TokenIntrospectionService introspectionService;

    private String suffix;
    private String adminBearer;
    private String clientId;
    private String audience;

    @BeforeEach
    void setUp() {
        suffix = UUID.randomUUID().toString().substring(0, 8);
        UserResponse admin = userService.create(new com.example.iam.user.dto.CreateUserRequest(
                "uadm" + suffix, "Admin", "uadm" + suffix + "@example.com", "admin-cli", null, "ACTIVE"));
        bind(admin, AdminRoles.IAM_ADMIN);
        adminBearer = bearer(admin.subjectId());
        clientId = "u5-" + suffix;
        audience = "aud-u5-" + suffix;
        clientService.create(new CreateClientRequest(
                clientId,
                "U5",
                "confidential",
                RegistryStatus.ACTIVE,
                "client_secret_basic",
                600,
                86400,
                true,
                "iam",
                List.of(new RedirectUriInput(LOGIN, "LOGIN_CALLBACK")),
                SECRET));
        String resource = "OIDC-U5-" + suffix;
        resourceService.create(new CreateResourceRequest(resource, "OIDC", audience, RegistryStatus.ACTIVE, "iam"));
        scopeService.create(new CreateScopeRequest(resource, "openid", "OpenID", "openid", RegistryStatus.ACTIVE));
        permissionService.create(
                new CreatePermissionRequest(clientId, resource, "openid", "authorization_code", RegistryStatus.ACTIVE));
        permissionService.create(
                new CreatePermissionRequest(clientId, resource, "openid", "TOKEN_EXCHANGE", RegistryStatus.ACTIVE));
    }

    @Test
    void disableUserRevokesSessionRefreshAccessSsoAndExchange() throws Exception {
        MvcResult created = mockMvc.perform(post("/api/admin/users")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"tgt%s","display_name":"T","email":"tgt%s@example.com","tenant_id":"admin-cli"}
                                """.formatted(suffix, suffix)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(UserStatus.INACTIVE))
                .andReturn();
        String subjectId = com.jayway.jsonpath.JsonPath.read(created.getResponse().getContentAsString(), "$.subjectId");
        mockMvc.perform(post("/api/admin/users/" + subjectId + "/enable")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(UserStatus.ACTIVE));

        Cookie session = sso("tgt" + suffix);
        String sid = session.getValue();
        sessionService.require(sid);

        Instant now = Instant.now();
        String accessToken = accessTokenService.issue(new AccessTokenClaims(
                subjectId,
                List.of(audience),
                clientId,
                "openid",
                List.of(),
                "admin-cli",
                null,
                now,
                now.plusSeconds(600),
                "jti-u5-" + suffix,
                null,
                null));
        assertThat(introspectionService.introspect(accessToken).active()).isTrue();

        UUID userPk = userRepository.findBySubjectId(UUID.fromString(subjectId)).orElseThrow().getId();
        UUID clientPk = clientService.get(clientId).id();
        RefreshTokenService.IssuedRefreshToken issued = refreshTokenService.issue(
                userPk, clientPk, UUID.randomUUID(), "openid", audience, Duration.ofHours(1));

        mockMvc.perform(post("/api/admin/users/" + subjectId + "/disable")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(UserStatus.INACTIVE));

        assertThat(userRepository.findBySubjectId(UUID.fromString(subjectId)).orElseThrow().getStatus())
                .isEqualTo(UserStatus.INACTIVE);
        assertThatThrownBy(() -> userService.requireActiveForToken(UUID.fromString(subjectId)))
                .isInstanceOf(IamException.class)
                .extracting(ex -> ((IamException) ex).getErrorCode())
                .isEqualTo(IamErrorCode.USER_INACTIVE);
        assertThatThrownBy(() -> sessionService.require(sid))
                .extracting(ex -> ((IamException) ex).getErrorCode())
                .isEqualTo(IamErrorCode.SESSION_REVOKED);
        IamRefreshTokenEntity refreshRow = refreshTokenRepository.findByTokenHash(
                com.example.iam.common.util.HashUtils.sha256Hex(issued.token())).orElseThrow();
        assertThat(refreshRow.getStatus()).isEqualTo("REVOKED");
        assertThat(introspectionService.introspect(accessToken).active()).isFalse();

        mockMvc.perform(post("/sso/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"tgt%s","tenant_id":"admin-cli","client_id":"%s"}
                                """.formatted(suffix, clientId)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value(IamErrorCode.USER_INACTIVE.getCode()));

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
                .andExpect(jsonPath("$.code").value(IamErrorCode.SESSION_REVOKED.getCode()));

        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .header(
                                HttpHeaders.AUTHORIZATION,
                                "Basic " + HttpHeaders.encodeBasicAuth(clientId, SECRET, StandardCharsets.UTF_8))
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", issued.token()))
                .andExpect(status().isBadRequest());

        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .header(
                                HttpHeaders.AUTHORIZATION,
                                "Basic " + HttpHeaders.encodeBasicAuth(clientId, SECRET, StandardCharsets.UTF_8))
                        .param("grant_type", EXCHANGE_GRANT)
                        .param("subject_token", accessToken)
                        .param("subject_token_type", ACCESS_TYPE)
                        .param("audience", audience)
                        .param("scope", "openid"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value(IamErrorCode.USER_INACTIVE.getCode()));

        assertThat(auditLogRepository.findAll())
                .anyMatch(row -> AuditEvent.USER_DISABLED.name().equals(row.getEventType())
                        && row.getDetail() != null
                        && row.getDetail().contains(subjectId));
    }

    @Test
    void mappingCrudDuplicateAndAuditorAndSearch() throws Exception {
        MvcResult created = mockMvc.perform(post("/api/admin/users")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"map%s","display_name":"M","email":"map%s@example.com","tenant_id":"admin-cli"}
                                """.formatted(suffix, suffix)))
                .andExpect(status().isOk())
                .andReturn();
        String subjectId = com.jayway.jsonpath.JsonPath.read(created.getResponse().getContentAsString(), "$.subjectId");
        mockMvc.perform(post("/api/admin/users/" + subjectId + "/enable")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer))
                .andExpect(status().isOk());

        MvcResult mapping = mockMvc.perform(post("/api/admin/identity-mappings")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"subject_id":"%s","system_code":"SYS-%s","external_user_id":"E-%s","external_username":"map"}
                                """.formatted(subjectId, suffix, suffix)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.systemCode").value("SYS-" + suffix))
                .andReturn();
        String mappingId = com.jayway.jsonpath.JsonPath.read(mapping.getResponse().getContentAsString(), "$.id");

        mockMvc.perform(post("/api/admin/identity-mappings")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"subject_id":"%s","system_code":"SYS-%s","external_user_id":"E-%s"}
                                """.formatted(subjectId, suffix, suffix)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value(IamErrorCode.DUPLICATE_IDENTITY_MAPPING.getCode()));

        mockMvc.perform(get("/api/admin/identity-mappings")
                        .param("system_code", "SYS-" + suffix)
                        .param("external_user_id", "E-" + suffix)
                        .header(HttpHeaders.AUTHORIZATION, adminBearer))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(1));

        mockMvc.perform(get("/api/admin/users").param("q", "map" + suffix).header(HttpHeaders.AUTHORIZATION, adminBearer))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].username").value("map" + suffix));

        UserResponse auditor = userService.create(new com.example.iam.user.dto.CreateUserRequest(
                "uaud" + suffix, "A", "uaud" + suffix + "@example.com", "admin-cli", null, "ACTIVE"));
        bind(auditor, AdminRoles.IAM_AUDITOR);
        mockMvc.perform(post("/api/admin/users")
                        .header(HttpHeaders.AUTHORIZATION, bearer(auditor.subjectId()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"nope%s","display_name":"N","tenant_id":"admin-cli"}
                                """.formatted(suffix)))
                .andExpect(status().isForbidden());

        UserResponse plain = userService.create(new com.example.iam.user.dto.CreateUserRequest(
                "plain" + suffix, "P", "plain" + suffix + "@example.com", "admin-cli", null, "ACTIVE"));
        mockMvc.perform(get("/api/admin/users").header(HttpHeaders.AUTHORIZATION, bearer(plain.subjectId())))
                .andExpect(status().isUnauthorized());

        assertThat(mappingRepository.findById(UUID.fromString(mappingId))).isPresent();
    }

    private Cookie sso(String username) throws Exception {
        MvcResult result = mockMvc.perform(post("/sso/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"%s","tenant_id":"admin-cli","client_id":"%s"}
                                """.formatted(username, clientId)))
                .andExpect(status().isOk())
                .andReturn();
        return result.getResponse().getCookie(SsoCookieService.COOKIE_NAME);
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
