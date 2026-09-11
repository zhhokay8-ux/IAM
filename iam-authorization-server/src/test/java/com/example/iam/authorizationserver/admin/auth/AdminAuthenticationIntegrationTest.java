package com.example.iam.authorizationserver.admin.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.iam.admin.entity.IamAdminUserRoleEntity;
import com.example.iam.admin.rbac.AdminRoles;
import com.example.iam.admin.repository.IamAdminRoleRepository;
import com.example.iam.admin.repository.IamAdminUserRoleRepository;
import com.example.iam.authorizationserver.AbstractIamIntegrationTest;
import com.example.iam.authorizationserver.IamAuthorizationServerApplication;
import com.example.iam.authorizationserver.sso.SsoCookieService;
import com.example.iam.authorizationserver.sso.SsoTestPassword;
import com.example.iam.clientregistry.service.IamClientService;
import com.example.iam.common.security.CsrfTokenService;
import com.example.iam.core.redis.RedisKeyConstants;
import com.example.iam.user.dto.CreateUserRequest;
import com.example.iam.user.dto.UserResponse;
import com.example.iam.user.service.IamUserService;
import jakarta.servlet.http.Cookie;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.util.UriComponentsBuilder;

@SpringBootTest(classes = IamAuthorizationServerApplication.class)
@AutoConfigureMockMvc
@TestPropertySource(
        properties = {
            "iam.issuer=https://auth.example.com",
            "iam.sso.cookie-secure=false",
            "iam.admin.oauth.client-secret=dev-only-admin-secret",
            "iam.admin.oauth.redirect-uri=http://localhost:8080/admin/callback",
            "iam.admin.oauth.post-login-uri=http://localhost:8080/admin"
        })
class AdminAuthenticationIntegrationTest extends AbstractIamIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private IamUserService userService;

    @Autowired
    private IamAdminRoleRepository roleRepository;

    @Autowired
    private IamAdminUserRoleRepository userRoleRepository;

    @Autowired
    private IamClientService clientService;

    @Autowired
    private StringRedisTemplate redisTemplate;

    @Autowired
    private AdminOAuthPendingRepository pendingRepository;

    private String suffix;

    @BeforeEach
    void setUp() {
        suffix = UUID.randomUUID().toString().substring(0, 8);
    }

    @Test
    void adminClientIsConfidentialWithExactRedirect() {
        var client = clientService.get("iam-admin");
        assertThat(client.clientType()).isEqualToIgnoringCase("confidential");
        assertThat(client.pkceRequired()).isTrue();
        assertThat(client.redirectUris())
                .anyMatch(uri -> "http://localhost:8080/admin/callback".equals(uri.redirectUri()));
        assertThat(client.redirectUris()).noneMatch(uri -> uri.redirectUri().contains("*"));
    }

    @Test
    void loginWithoutSessionFailsAtAuthorizeProtocol() throws Exception {
        MvcResult start = mockMvc.perform(get("/admin/login")).andExpect(status().isFound()).andReturn();
        String authorize = start.getResponse().getHeader(HttpHeaders.LOCATION);
        assertThat(authorize).startsWith("/oauth2/authorize");
        assertThat(authorize).contains("code_challenge_method=S256");
        assertThat(authorize).contains("state=");
        MvcResult denied = mockMvc.perform(get(authorize)).andExpect(status().isFound()).andReturn();
        String callback = denied.getResponse().getHeader(HttpHeaders.LOCATION);
        assertThat(callback).contains("/admin/callback");
        assertThat(callback).contains("error=");
        assertThat(callback).doesNotContain("code=");
        mockMvc.perform(get(toRequestUri(callback))).andExpect(status().isUnauthorized());
    }

    @Test
    void authorizationCodePkceLoginSetsSessionCookieAndMe() throws Exception {
        UserResponse user = createUser("adm");
        bind(user, AdminRoles.IAM_ADMIN);
        Cookie session = ssoLogin(user);
        Cookie csrf = csrfCookie(session);

        MvcResult start = mockMvc.perform(get("/admin/login").cookie(session)).andExpect(status().isFound()).andReturn();
        String authorizeUrl = start.getResponse().getHeader(HttpHeaders.LOCATION);
        String state = query(authorizeUrl, "state");
        assertThat(pendingRepository.findPending(state)).isPresent();
        assertThat(query(authorizeUrl, "nonce")).isNotBlank();
        assertThat(query(authorizeUrl, "code_challenge")).isNotBlank();
        assertThat(query(authorizeUrl, "redirect_uri")).isEqualTo("http://localhost:8080/admin/callback");

        MvcResult authorized = mockMvc.perform(get(authorizeUrl).cookie(session))
                .andExpect(status().isFound())
                .andReturn();
        String callbackUrl = authorized.getResponse().getHeader(HttpHeaders.LOCATION);
        assertThat(callbackUrl).contains("code=");
        assertThat(callbackUrl).doesNotContain("access_token");
        assertThat(callbackUrl).doesNotContain("refresh_token");
        assertThat(callbackUrl).doesNotContain("client_secret");

        MvcResult finished = mockMvc.perform(get(toRequestUri(callbackUrl)).cookie(session))
                .andExpect(status().isFound())
                .andExpect(header().string(HttpHeaders.LOCATION, "http://localhost:8080/admin"))
                .andReturn();
        String body = finished.getResponse().getContentAsString();
        assertThat(body).doesNotContain("access_token");
        assertThat(body).doesNotContain("refresh_token");
        assertThat(pendingRepository.findPending(state)).isEmpty();
        assertThat(Boolean.TRUE.equals(redisTemplate.hasKey(RedisKeyConstants.session(session.getValue())))).isTrue();

        mockMvc.perform(get("/api/admin/me").cookie(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value(user.username()))
                .andExpect(jsonPath("$.roles[0]").value(AdminRoles.IAM_ADMIN))
                .andExpect(jsonPath("$.authMethod").value("COOKIE"));

        mockMvc.perform(post("/admin/logout")
                        .cookie(session, csrf)
                        .header(CsrfTokenService.HEADER, csrf.getValue())
                        .header(HttpHeaders.ORIGIN, "http://localhost:8080"))
                .andExpect(status().isNoContent());
        mockMvc.perform(get("/api/admin/me").cookie(session)).andExpect(status().isUnauthorized());
        assertThat(Boolean.TRUE.equals(redisTemplate.hasKey(RedisKeyConstants.session(session.getValue())))).isFalse();
    }

    @Test
    void logoutWithoutCsrfIsForbidden() throws Exception {
        UserResponse user = createUser("csrf");
        bind(user, AdminRoles.IAM_ADMIN);
        Cookie session = ssoLogin(user);
        mockMvc.perform(post("/admin/logout")
                        .cookie(session)
                        .header(HttpHeaders.ORIGIN, "http://localhost:8080"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("IAM-4079"));
    }

    @Test
    void corsAllowsAdminOriginAndRejectsUnknown() throws Exception {
        mockMvc.perform(options("/api/admin/me").header(HttpHeaders.ORIGIN, "http://localhost:5173"))
                .andExpect(status().isNoContent())
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "http://localhost:5173"));
        mockMvc.perform(options("/api/admin/me").header(HttpHeaders.ORIGIN, "https://evil.example.com"))
                .andExpect(status().isNoContent())
                .andExpect(header().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN));
    }

    @Test
    void userWithoutAdminRoleGets403OnMe() throws Exception {
        UserResponse user = createUser("plain");
        Cookie session = ssoLogin(user);
        completeAdminOauth(session);
        mockMvc.perform(get("/api/admin/me").cookie(session))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("IAM-4082"));
    }

    @Test
    void auditorRoleIsVisibleOnMe() throws Exception {
        UserResponse user = createUser("aud");
        bind(user, AdminRoles.IAM_AUDITOR);
        Cookie session = ssoLogin(user);
        completeAdminOauth(session);
        Cookie csrf = csrfCookie(session);
        mockMvc.perform(get("/api/admin/me").cookie(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.roles[0]").value(AdminRoles.IAM_AUDITOR));
        mockMvc.perform(post("/api/admin/security/write-probe")
                        .cookie(session, csrf)
                        .header(CsrfTokenService.HEADER, csrf.getValue())
                        .header(HttpHeaders.ORIGIN, "http://localhost:8080"))
                .andExpect(status().isForbidden());
    }

    @Test
    void mismatchedStateIsUnauthorized() throws Exception {
        UserResponse user = createUser("st");
        bind(user, AdminRoles.IAM_ADMIN);
        Cookie session = ssoLogin(user);
        mockMvc.perform(get("/admin/login").cookie(session)).andExpect(status().isFound());
        mockMvc.perform(get("/admin/callback").param("code", "x").param("state", "not-the-state").cookie(session))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void redirectUriMismatchIsRejectedByRuntime() throws Exception {
        UserResponse user = createUser("uri");
        Cookie session = ssoLogin(user);
        mockMvc.perform(get("/oauth2/authorize")
                        .param("client_id", "iam-admin")
                        .param("redirect_uri", "http://localhost:8080/not-registered")
                        .param("response_type", "code")
                        .param("scope", "openid")
                        .param("state", "s-" + suffix)
                        .param("nonce", "n-" + suffix)
                        .param("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
                        .param("code_challenge_method", "S256")
                        .cookie(session))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("IAM-4001"));
    }

    private void completeAdminOauth(Cookie session) throws Exception {
        MvcResult start = mockMvc.perform(get("/admin/login").cookie(session)).andReturn();
        MvcResult authorized =
                mockMvc.perform(get(start.getResponse().getHeader(HttpHeaders.LOCATION)).cookie(session))
                        .andReturn();
        mockMvc.perform(get(toRequestUri(authorized.getResponse().getHeader(HttpHeaders.LOCATION))).cookie(session));
    }

    private UserResponse createUser(String prefix) {
        return userService.create(new CreateUserRequest(
                prefix + suffix,
                prefix,
                prefix + suffix + "@example.com",
                "admin-auth",
                null,
                "ACTIVE",
                SsoTestPassword.RAW));
    }

    private void bind(UserResponse user, String roleCode) {
        UUID roleId = roleRepository.findByRoleCode(roleCode).orElseThrow().getId();
        userRoleRepository.save(IamAdminUserRoleEntity.builder()
                .subjectId(UUID.fromString(user.subjectId()))
                .roleId(roleId)
                .createdAt(Instant.now())
                .build());
    }

    private Cookie ssoLogin(UserResponse user) throws Exception {
        MvcResult result = mockMvc.perform(post("/sso/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"%s","password":"%s","tenant_id":"admin-auth","client_id":"iam-admin"}
                                """.formatted(user.username(), SsoTestPassword.RAW)))
                .andExpect(status().isOk())
                .andReturn();
        Cookie cookie = result.getResponse().getCookie(SsoCookieService.COOKIE_NAME);
        assertThat(cookie).isNotNull();
        assertThat(cookie.isHttpOnly()).isTrue();
        assertThat(result.getResponse().getContentAsString()).doesNotContain("access_token");
        return cookie;
    }

    private Cookie csrfCookie(Cookie session) throws Exception {
        MvcResult result = mockMvc.perform(get("/sso/session").cookie(session)).andReturn();
        Cookie csrf = result.getResponse().getCookie(CsrfTokenService.COOKIE);
        assertThat(csrf).isNotNull();
        return csrf;
    }

    private static String query(String url, String name) {
        return UriComponentsBuilder.fromUriString(url).build(true).getQueryParams().getFirst(name);
    }

    private static String toRequestUri(String location) {
        java.net.URI uri = java.net.URI.create(location);
        if (uri.getRawQuery() == null || uri.getRawQuery().isBlank()) {
            return uri.getRawPath();
        }
        return uri.getRawPath() + "?" + uri.getRawQuery();
    }
}
