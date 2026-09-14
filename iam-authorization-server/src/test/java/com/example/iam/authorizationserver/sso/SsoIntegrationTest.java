package com.example.iam.authorizationserver.sso;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.iam.authorizationserver.AbstractIamIntegrationTest;
import com.example.iam.authorizationserver.IamAuthorizationServerApplication;
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
import com.example.iam.core.redis.RedisKeyConstants;
import com.example.iam.session.IamSessionService;
import com.example.iam.user.dto.CreateUserRequest;
import com.example.iam.user.dto.UserResponse;
import com.example.iam.user.service.IamUserService;
import jakarta.servlet.http.Cookie;
import java.nio.charset.StandardCharsets;
import java.util.List;
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
@TestPropertySource(properties = {"iam.issuer=https://auth.example.com", "iam.sso.cookie-secure=false"})
public class SsoIntegrationTest extends AbstractIamIntegrationTest {

    private static final String PORTAL_REDIRECT = "https://portal.example.com/login/callback";
    private static final String SYSTEM1_REDIRECT = "https://system1.example.com/login/callback";
    private static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private static final String SECRET = "super-secret";
    private static final String OPENID = "openid";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private IamClientService clientService;

    @Autowired
    private IamResourceService resourceService;

    @Autowired
    private IamScopeService scopeService;

    @Autowired
    private IamPermissionService permissionService;

    @Autowired
    private IamUserService userService;

    @Autowired
    private IamSessionService sessionService;

    @Autowired
    private StringRedisTemplate redisTemplate;

    private String suffix;
    private String portalClientId;
    private String system1ClientId;
    private String username;
    private String subject;
    private String system1Audience;
    private Cookie csrf;

    @BeforeEach
    void setUp() {
        suffix = UUID.randomUUID().toString().substring(0, 8);
        portalClientId = "portal-" + suffix;
        system1ClientId = "system1-" + suffix;
        username = "user-" + suffix;
        String portalResource = "OIDC-P-" + suffix;
        String system1Resource = "OIDC-S-" + suffix;
        system1Audience = "system1-api-" + suffix;
        clientService.create(new CreateClientRequest(
                portalClientId,
                "Portal",
                "confidential",
                RegistryStatus.ACTIVE,
                "client_secret_basic",
                600,
                86400,
                true,
                "iam",
                List.of(new RedirectUriInput(PORTAL_REDIRECT, "LOGIN_CALLBACK")),
                SECRET));
        clientService.create(new CreateClientRequest(
                system1ClientId,
                "System1",
                "confidential",
                RegistryStatus.ACTIVE,
                "client_secret_basic",
                600,
                86400,
                true,
                "iam",
                List.of(new RedirectUriInput(SYSTEM1_REDIRECT, "LOGIN_CALLBACK")),
                SECRET));
        resourceService.create(
                new CreateResourceRequest(portalResource, "Portal API", "portal-api-" + suffix, RegistryStatus.ACTIVE, "iam"));
        resourceService.create(
                new CreateResourceRequest(system1Resource, "System1 API", system1Audience, RegistryStatus.ACTIVE, "iam"));
        scopeService.create(new CreateScopeRequest(portalResource, OPENID, "OpenID", "openid", RegistryStatus.ACTIVE));
        scopeService.create(new CreateScopeRequest(system1Resource, OPENID, "OpenID", "openid", RegistryStatus.ACTIVE));
        permissionService.create(new CreatePermissionRequest(
                portalClientId, portalResource, OPENID, "authorization_code", RegistryStatus.ACTIVE));
        permissionService.create(new CreatePermissionRequest(
                system1ClientId, system1Resource, OPENID, "authorization_code", RegistryStatus.ACTIVE));
        UserResponse user = userService.create(
                new CreateUserRequest(
                        username, "User", username + "@example.com", "tenant-1", "org-1", "ACTIVE", SsoTestPassword.RAW));
        subject = user.subjectId();
    }

    @Test
    void portalLoginCreatesSessionAndSystem1ReusesItWithoutLogin() throws Exception {
        Cookie sessionCookie = login();
        assertThat(sessionCookie.isHttpOnly()).isTrue();
        assertThat(Boolean.TRUE.equals(redisTemplate.hasKey(RedisKeyConstants.session(sessionCookie.getValue()))))
                .isTrue();

        String portalLocation = authorize(portalClientId, PORTAL_REDIRECT, sessionCookie, "portal");
        assertThat(portalLocation).startsWith(PORTAL_REDIRECT);
        assertThat(portalLocation).contains("code=");
        assertThat(portalLocation).doesNotContain("access_token");
        assertThat(portalLocation).doesNotContain("/sso/login");

        String system1Location = authorize(system1ClientId, SYSTEM1_REDIRECT, sessionCookie, "system1");
        assertThat(system1Location).startsWith(SYSTEM1_REDIRECT);
        assertThat(system1Location).contains("code=");
        assertThat(system1Location).doesNotContain("/sso/login");
        String code = queryParam(system1Location, "code");

        MvcResult token = mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .header(
                                HttpHeaders.AUTHORIZATION,
                                "Basic " + HttpHeaders.encodeBasicAuth(system1ClientId, SECRET, StandardCharsets.UTF_8))
                        .param("grant_type", "authorization_code")
                        .param("code", code)
                        .param("redirect_uri", SYSTEM1_REDIRECT)
                        .param("code_verifier", VERIFIER))
                .andExpect(status().isOk())
                .andReturn();
        String body = token.getResponse().getContentAsString();
        assertThat(body).contains("\"access_token\"");
        assertThat(com.jayway.jsonpath.JsonPath.<String>read(body, "$.token_type")).isEqualTo("Bearer");
    }

    @Test
    void sessionExpiredIsRejected() throws Exception {
        Cookie sessionCookie = login();
        sessionService.expire(sessionCookie.getValue());
        mockMvc.perform(get("/sso/session").cookie(sessionCookie))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value(IamErrorCode.SESSION_EXPIRED.getCode()));
        MvcResult authorize = mockMvc.perform(authorizeRequest(system1ClientId, SYSTEM1_REDIRECT, sessionCookie, "exp"))
                .andReturn();
        assertThat(authorize.getResponse().getStatus()).isEqualTo(401);
    }

    @Test
    void sessionRevokedIsRejected() throws Exception {
        Cookie sessionCookie = login();
        sessionService.revoke(sessionCookie.getValue());
        mockMvc.perform(get("/sso/session").cookie(sessionCookie))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value(IamErrorCode.SESSION_REVOKED.getCode()));
    }

    @Test
    void sessionNotFoundIsRejected() throws Exception {
        mockMvc.perform(get("/sso/session").cookie(new Cookie(SsoCookieService.COOKIE_NAME, "missing-" + suffix)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value(IamErrorCode.SESSION_NOT_FOUND.getCode()));
    }

    @Test
    void tamperedCookieIsRejected() throws Exception {
        Cookie sessionCookie = login();
        Cookie tampered = new Cookie(SsoCookieService.COOKIE_NAME, sessionCookie.getValue() + "tampered");
        mockMvc.perform(get("/sso/session").cookie(tampered))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value(IamErrorCode.SESSION_NOT_FOUND.getCode()));
        MvcResult authorize = mockMvc.perform(authorizeRequest(portalClientId, PORTAL_REDIRECT, tampered, "tamper"))
                .andExpect(status().isFound())
                .andReturn();
        assertThat(authorize.getResponse().getHeader("Location")).contains("error=invalid_request");
        assertThat(authorize.getResponse().getHeader("Location")).doesNotContain("code=");
    }

    @Test
    void logoutInvalidatesSession() throws Exception {
        Cookie sessionCookie = login();
        mockMvc.perform(post("/oidc/logout")
                        .cookie(sessionCookie, csrf)
                        .header(com.example.iam.common.security.CsrfTokenService.HEADER, csrf.getValue())
                        .header(HttpHeaders.ORIGIN, "https://portal.example.com"))
                .andExpect(status().isNoContent());
        mockMvc.perform(get("/sso/session").cookie(sessionCookie))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value(IamErrorCode.SESSION_NOT_FOUND.getCode()));
        MvcResult authorize = mockMvc.perform(authorizeRequest(system1ClientId, SYSTEM1_REDIRECT, sessionCookie, "out"))
                .andExpect(status().isFound())
                .andReturn();
        assertThat(authorize.getResponse().getHeader("Location")).contains("error=invalid_request");
    }

    @Test
    void wrongPasswordDoesNotCreateSession() throws Exception {
        mockMvc.perform(post("/sso/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"%s","password":"wrong-pass","tenant_id":"tenant-1","client_id":"%s"}
                                """.formatted(username, portalClientId)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value(IamErrorCode.INVALID_CREDENTIALS.getCode()));
        assertThat(mockMvc.perform(post("/sso/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"%s","password":"%s","tenant_id":"tenant-1","client_id":"%s"}
                                """.formatted("missing-" + suffix, SsoTestPassword.RAW, portalClientId)))
                .andReturn()
                .getResponse()
                .getCookie(SsoCookieService.COOKIE_NAME)).isNull();
    }

    @Test
    void csrfEndpointIssuesReadableToken() throws Exception {
        MvcResult result = mockMvc.perform(get("/sso/csrf"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.csrf_token").isNotEmpty())
                .andReturn();
        Cookie cookie = result.getResponse().getCookie(com.example.iam.common.security.CsrfTokenService.COOKIE);
        assertThat(cookie).isNotNull();
        assertThat(cookie.getValue())
                .isEqualTo(com.jayway.jsonpath.JsonPath.read(result.getResponse().getContentAsString(), "$.csrf_token"));
    }

    @Test
    void passwordIsRequired() throws Exception {
        mockMvc.perform(post("/sso/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"%s","tenant_id":"tenant-1","client_id":"%s"}
                                """.formatted(username, portalClientId)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value(IamErrorCode.INVALID_ARGUMENT.getCode()));
    }

    @Test
    void inactiveUserWithCorrectPasswordIsRejected() throws Exception {
        userService.disable(UUID.fromString(subject));
        mockMvc.perform(post("/sso/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"%s","password":"%s","tenant_id":"tenant-1","client_id":"%s"}
                                """.formatted(username, SsoTestPassword.RAW, portalClientId)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value(IamErrorCode.USER_INACTIVE.getCode()));
    }

    private Cookie login() throws Exception {
        MvcResult result = mockMvc.perform(post("/sso/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"%s","password":"%s","tenant_id":"tenant-1","client_id":"%s"}
                                """.formatted(username, SsoTestPassword.RAW, portalClientId)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.subject_id").value(subject))
                .andReturn();
        String body = result.getResponse().getContentAsString();
        assertThat(body).doesNotContain("access_token");
        assertThat(body).doesNotContain("refresh_token");
        Cookie cookie = result.getResponse().getCookie(SsoCookieService.COOKIE_NAME);
        csrf = result.getResponse().getCookie(com.example.iam.common.security.CsrfTokenService.COOKIE);
        assertThat(cookie).isNotNull();
        assertThat(csrf).isNotNull();
        assertThat(cookie).isNotNull();
        assertThat(cookie.getValue()).isNotBlank();
        return cookie;
    }

    private String authorize(String clientId, String redirect, Cookie cookie, String tag) throws Exception {
        MvcResult result = mockMvc.perform(authorizeRequest(clientId, redirect, cookie, tag))
                .andExpect(status().isFound())
                .andReturn();
        return result.getResponse().getHeader("Location");
    }

    private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder authorizeRequest(
            String clientId, String redirect, Cookie cookie, String tag) {
        return get("/oauth2/authorize")
                .param("client_id", clientId)
                .param("redirect_uri", redirect)
                .param("response_type", "code")
                .param("scope", OPENID)
                .param("state", tag + "-state-" + suffix)
                .param("nonce", tag + "-nonce-" + suffix)
                .param("code_challenge", CHALLENGE)
                .param("code_challenge_method", "S256")
                .cookie(cookie);
    }

    private static String queryParam(String location, String name) {
        return UriComponentsBuilder.fromUriString(location).build(true).getQueryParams().getFirst(name);
    }
}
