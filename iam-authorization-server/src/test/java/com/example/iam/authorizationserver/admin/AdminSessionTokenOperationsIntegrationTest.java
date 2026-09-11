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
import com.example.iam.authorizationserver.admin.token.AdminTokenIntrospectResponse;
import com.example.iam.authorizationserver.oauth.introspect.TokenIntrospectionService;
import com.example.iam.authorizationserver.sso.SsoCookieService;
import com.example.iam.authorizationserver.sso.SsoTestPassword;
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
import com.example.iam.common.util.HashUtils;
import com.example.iam.session.IamSession;
import com.example.iam.session.IamSessionService;
import com.example.iam.session.repository.IamSessionRepository;
import com.example.iam.token.entity.IamRefreshTokenEntity;
import com.example.iam.token.oauth.AccessTokenClaims;
import com.example.iam.token.oauth.AccessTokenService;
import com.example.iam.token.oauth.RefreshTokenService;
import com.example.iam.token.repository.IamRefreshTokenRepository;
import com.example.iam.token.signing.JwtSigner;
import com.example.iam.user.dto.UserResponse;
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
class AdminSessionTokenOperationsIntegrationTest extends AbstractIamIntegrationTest {

    private static final String LOGIN = "https://app.example.com/login/callback";
    private static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private static final String SECRET = "phase6-secret";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private IamUserService userService;

    @Autowired
    private IamUserRepository userRepository;

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
    private IamSessionRepository sessionRepository;

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
    private String auditorBearer;
    private String clientId;
    private String audience;

    @BeforeEach
    void setUp() {
        suffix = UUID.randomUUID().toString().substring(0, 8);
        UserResponse admin = userService.create(new com.example.iam.user.dto.CreateUserRequest(
                "s6adm" + suffix, "Admin", "s6adm" + suffix + "@example.com", "admin-cli", null, "ACTIVE"));
        bind(admin, AdminRoles.IAM_ADMIN);
        adminBearer = bearer(admin.subjectId());
        UserResponse auditor = userService.create(new com.example.iam.user.dto.CreateUserRequest(
                "s6aud" + suffix, "Aud", "s6aud" + suffix + "@example.com", "admin-cli", null, "ACTIVE"));
        bind(auditor, AdminRoles.IAM_AUDITOR);
        auditorBearer = bearer(auditor.subjectId());
        clientId = "s6-" + suffix;
        audience = "aud-s6-" + suffix;
        clientService.create(new CreateClientRequest(
                clientId,
                "S6",
                "confidential",
                RegistryStatus.ACTIVE,
                "client_secret_basic",
                600,
                86400,
                true,
                "iam",
                List.of(new RedirectUriInput(LOGIN, "LOGIN_CALLBACK")),
                SECRET));
        String resource = "OIDC-S6-" + suffix;
        resourceService.create(new CreateResourceRequest(resource, "OIDC", audience, RegistryStatus.ACTIVE, "iam"));
        scopeService.create(new CreateScopeRequest(resource, "openid", "OpenID", "openid", RegistryStatus.ACTIVE));
        permissionService.create(
                new CreatePermissionRequest(clientId, resource, "openid", "authorization_code", RegistryStatus.ACTIVE));
    }

    @Test
    void revokeSessionRedisRuntimeAuthorizeAndAudit() throws Exception {
        UserResponse target = createActiveUser("s6tgt");
        Cookie session = sso("s6tgt" + suffix);
        String sid = session.getValue();

        mockMvc.perform(get("/api/admin/sessions").param("subject_id", target.subjectId()).header(HttpHeaders.AUTHORIZATION, adminBearer))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].sid").value(sid));

        mockMvc.perform(post("/api/admin/sessions/" + sid + "/revoke").header(HttpHeaders.AUTHORIZATION, auditorBearer))
                .andExpect(status().isForbidden());

        mockMvc.perform(post("/api/admin/sessions/" + sid + "/revoke").header(HttpHeaders.AUTHORIZATION, adminBearer))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(IamSession.STATUS_REVOKED));

        String raw = sessionRepository.get(sid).orElseThrow();
        assertThat(raw).contains("\"status\":\"REVOKED\"");
        assertThat(sessionService.inspect(sid).orElseThrow().status()).isEqualTo(IamSession.STATUS_REVOKED);
        assertThatThrownBy(() -> sessionService.require(sid))
                .isInstanceOf(IamException.class)
                .extracting(ex -> ((IamException) ex).getErrorCode())
                .isEqualTo(IamErrorCode.SESSION_REVOKED);

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

        assertThat(auditLogRepository.findAll())
                .anyMatch(row -> AuditEvent.SESSION_REVOKED.name().equals(row.getEventType())
                        && row.getDetail() != null
                        && row.getDetail().contains(sid));
    }

    @Test
    void revokeRefreshDbGrantFailsAndAudit() throws Exception {
        UserResponse target = createActiveUser("s6rf");
        UUID userPk = userRepository.findBySubjectId(UUID.fromString(target.subjectId())).orElseThrow().getId();
        UUID clientPk = clientService.get(clientId).id();
        UUID family = UUID.randomUUID();
        RefreshTokenService.IssuedRefreshToken issued =
                refreshTokenService.issue(userPk, clientPk, family, "openid", audience, Duration.ofHours(1));

        MvcResult listed = mockMvc.perform(get("/api/admin/refresh-tokens")
                        .param("subject_id", target.subjectId())
                        .header(HttpHeaders.AUTHORIZATION, adminBearer))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].tokenHash").doesNotExist())
                .andReturn();
        String body = listed.getResponse().getContentAsString();
        assertThat(body).doesNotContain(issued.token());
        assertThat(body.toLowerCase()).doesNotContain("tokenhash");

        String refreshId = com.jayway.jsonpath.JsonPath.read(body, "$.content[0].id");
        mockMvc.perform(post("/api/admin/refresh-tokens/" + refreshId + "/revoke")
                        .header(HttpHeaders.AUTHORIZATION, auditorBearer))
                .andExpect(status().isForbidden());

        mockMvc.perform(post("/api/admin/refresh-tokens/" + refreshId + "/revoke")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("REVOKED"));

        IamRefreshTokenEntity row =
                refreshTokenRepository.findByTokenHash(HashUtils.sha256Hex(issued.token())).orElseThrow();
        assertThat(row.getStatus()).isEqualTo("REVOKED");
        assertThat(introspectionService.introspect(issued.token()).active()).isFalse();

        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .header(
                                HttpHeaders.AUTHORIZATION,
                                "Basic " + HttpHeaders.encodeBasicAuth(clientId, SECRET, StandardCharsets.UTF_8))
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", issued.token()))
                .andExpect(status().isBadRequest());

        assertThat(auditLogRepository.findAll())
                .anyMatch(rowAudit -> AuditEvent.TOKEN_REVOKED.name().equals(rowAudit.getEventType())
                        && rowAudit.getDetail() != null
                        && !rowAudit.getDetail().contains(issued.token()));
    }

    @Test
    void introspectAndRevokePresentedAccessToken() throws Exception {
        UserResponse target = createActiveUser("s6at");
        Instant now = Instant.now();
        String marker = "phase6-secret-jwt-" + suffix;
        String accessToken = accessTokenService.issue(new AccessTokenClaims(
                target.subjectId(),
                List.of(audience),
                clientId,
                "openid",
                List.of(),
                "admin-cli",
                null,
                now,
                now.plusSeconds(600),
                "jti-s6-" + suffix,
                null,
                null));
        assertThat(accessToken).doesNotContain(marker);

        MvcResult introspected = mockMvc.perform(post("/api/admin/tokens/introspect")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"" + accessToken + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(true))
                .andExpect(jsonPath("$.warning").value(AdminTokenIntrospectResponse.HIGH_RISK_WARNING))
                .andReturn();
        String introspectBody = introspected.getResponse().getContentAsString();
        assertThat(introspectBody).doesNotContain(accessToken);

        mockMvc.perform(post("/api/admin/tokens/revoke")
                        .header(HttpHeaders.AUTHORIZATION, auditorBearer)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"" + accessToken + "\",\"token_type_hint\":\"access_token\"}"))
                .andExpect(status().isForbidden());

        mockMvc.perform(post("/api/admin/tokens/revoke")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"" + accessToken + "\",\"token_type_hint\":\"access_token\"}"))
                .andExpect(status().isOk());

        assertThat(introspectionService.introspect(accessToken).active()).isFalse();
        mockMvc.perform(post("/api/admin/tokens/introspect")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"" + accessToken + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(false));

        assertThat(auditLogRepository.findAll())
                .anyMatch(row -> AuditEvent.TOKEN_REVOKED.name().equals(row.getEventType())
                        && (row.getDetail() == null || !row.getDetail().contains(accessToken)));
        assertThat(auditLogRepository.findAll())
                .noneMatch(row -> row.getDetail() != null && row.getDetail().contains(accessToken));
    }

    private UserResponse createActiveUser(String prefix) throws Exception {
        MvcResult created = mockMvc.perform(post("/api/admin/users")
                        .header(HttpHeaders.AUTHORIZATION, adminBearer)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"%s%s","display_name":"T","email":"%s%s@example.com","tenant_id":"admin-cli","password":"%s"}
                                """.formatted(prefix, suffix, prefix, suffix, SsoTestPassword.RAW)))
                .andExpect(status().isOk())
                .andReturn();
        String subjectId = com.jayway.jsonpath.JsonPath.read(created.getResponse().getContentAsString(), "$.subjectId");
        mockMvc.perform(post("/api/admin/users/" + subjectId + "/enable").header(HttpHeaders.AUTHORIZATION, adminBearer))
                .andExpect(status().isOk());
        return userService.get(UUID.fromString(subjectId));
    }

    private Cookie sso(String username) throws Exception {
        MvcResult result = mockMvc.perform(post("/sso/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"%s","password":"%s","tenant_id":"admin-cli","client_id":"%s"}
                                """.formatted(username, SsoTestPassword.RAW, clientId)))
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
