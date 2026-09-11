package com.example.iam.authorizationserver.oauth.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.iam.authorizationserver.AbstractIamIntegrationTest;
import com.example.iam.authorizationserver.IamAuthorizationServerApplication;
import com.example.iam.authorizationserver.oauth.AuthorizationController;
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
import com.example.iam.session.IamSession;
import com.example.iam.session.IamSessionService;
import com.example.iam.token.signing.JwtSigner;
import com.example.iam.user.dto.CreateUserRequest;
import com.example.iam.user.dto.UserResponse;
import com.example.iam.user.service.IamUserService;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.Cookie;
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
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.util.UriComponentsBuilder;

@SpringBootTest(classes = IamAuthorizationServerApplication.class)
@AutoConfigureMockMvc
@TestPropertySource(properties = "iam.issuer=https://auth.example.com")
class TokenControllerTest extends AbstractIamIntegrationTest {

    private static final String REDIRECT = "https://portal.example.com/login/callback";
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

    @Autowired
    private JwtSigner jwtSigner;

    private String clientId;
    private String audience;
    private String ccAudience;
    private String lockedAudience;
    private String sessionId;
    private String subject;

    private String suffix;

    @BeforeEach
    void setUp() {
        suffix = UUID.randomUUID().toString().substring(0, 8);
        clientId = "portal-" + suffix;
        audience = "portal-api-" + suffix;
        ccAudience = "cc-api-" + suffix;
        lockedAudience = "locked-api-" + suffix;
        String oidcResource = "OIDC-" + suffix;
        String ccResource = "CC-" + suffix;
        String lockedResource = "LOCKED-" + suffix;
        clientService.create(new CreateClientRequest(
                clientId,
                "Portal",
                "confidential",
                RegistryStatus.ACTIVE,
                "client_secret_basic",
                600,
                86400,
                true,
                "iam",
                List.of(new RedirectUriInput(REDIRECT, "LOGIN_CALLBACK")),
                SECRET));
        resourceService.create(new CreateResourceRequest(oidcResource, "OIDC", audience, RegistryStatus.ACTIVE, "iam"));
        resourceService.create(new CreateResourceRequest(ccResource, "CC", ccAudience, RegistryStatus.ACTIVE, "iam"));
        resourceService.create(
                new CreateResourceRequest(lockedResource, "Locked", lockedAudience, RegistryStatus.ACTIVE, "iam"));
        scopeService.create(new CreateScopeRequest(oidcResource, OPENID, "OpenID", "openid", RegistryStatus.ACTIVE));
        scopeService.create(new CreateScopeRequest(ccResource, "cc.read", "CC Read", "cc", RegistryStatus.ACTIVE));
        scopeService.create(new CreateScopeRequest(lockedResource, "secret", "Secret", "no", RegistryStatus.ACTIVE));
        permissionService.create(new CreatePermissionRequest(
                clientId, oidcResource, OPENID, "authorization_code", RegistryStatus.ACTIVE));
        permissionService.create(new CreatePermissionRequest(
                clientId, ccResource, "cc.read", "client_credentials", RegistryStatus.ACTIVE));
        UserResponse user = userService.create(new CreateUserRequest(
                "user-" + suffix, "User", "user-" + suffix + "@example.com", "tenant-1", "org-1", "ACTIVE"));
        subject = user.subjectId();
        IamSession session = sessionService.create(subject, clientId, "pwd");
        sessionId = session.sid();
    }

    @Test
    void authorizationCodeWithPkceSuccess() throws Exception {
        String code = authorize("state-ok", "nonce-ok");
        String body = exchangeCode(code, VERIFIER);
        assertAccessToken(body, subject, audience);
        assertThat(json(body, "$.refresh_token")).isNotBlank();
        assertThat(json(body, "$.id_token")).isNotBlank();
        SignedJWT idToken = jwtSigner.verify(json(body, "$.id_token"));
        assertThat(idToken.getJWTClaimsSet().getStringClaim("nonce")).isEqualTo("nonce-ok-" + suffix);
        assertThat(idToken.getJWTClaimsSet().getAudience()).contains(clientId);
    }

    @Test
    void pkceFailure() throws Exception {
        String code = authorize("state-pkce", "nonce-pkce");
        mockMvc.perform(token()
                        .param("grant_type", "authorization_code")
                        .param("code", code)
                        .param("redirect_uri", REDIRECT)
                        .param("code_verifier", "a".repeat(43)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value(IamErrorCode.INVALID_PKCE.getCode()));
    }

    @Test
    void expiredCode() throws Exception {
        String code = authorize("state-exp", "nonce-exp");
        redisTemplate.expire(RedisKeyConstants.authorizationCode(code), Duration.ofMillis(1));
        Thread.sleep(30);
        mockMvc.perform(token()
                        .param("grant_type", "authorization_code")
                        .param("code", code)
                        .param("redirect_uri", REDIRECT)
                        .param("code_verifier", VERIFIER))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value(IamErrorCode.INVALID_GRANT.getCode()));
    }

    @Test
    void replayedCode() throws Exception {
        String code = authorize("state-replay", "nonce-replay");
        exchangeCode(code, VERIFIER);
        mockMvc.perform(token()
                        .param("grant_type", "authorization_code")
                        .param("code", code)
                        .param("redirect_uri", REDIRECT)
                        .param("code_verifier", VERIFIER))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value(IamErrorCode.INVALID_GRANT.getCode()));
    }

    @Test
    void invalidClient() throws Exception {
        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .header("Authorization", "Basic " + org.springframework.http.HttpHeaders.encodeBasicAuth(
                                "missing-client", SECRET, java.nio.charset.StandardCharsets.UTF_8))
                        .param("grant_type", "client_credentials")
                        .param("scope", "cc.read")
                        .param("audience", ccAudience))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value(IamErrorCode.INVALID_CLIENT.getCode()));
    }

    @Test
    void invalidSecret() throws Exception {
        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .header("Authorization", "Basic " + org.springframework.http.HttpHeaders.encodeBasicAuth(
                                clientId, "wrong-secret", java.nio.charset.StandardCharsets.UTF_8))
                        .param("grant_type", "client_credentials")
                        .param("scope", "cc.read")
                        .param("audience", ccAudience))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value(IamErrorCode.INVALID_CLIENT.getCode()));
    }

    @Test
    void refreshTokenAndRotation() throws Exception {
        String first = exchangeCode(authorize("state-rt", "nonce-rt"), VERIFIER);
        String refresh1 = json(first, "$.refresh_token");
        String second = mockMvc.perform(token()
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", refresh1))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();
        String refresh2 = json(second, "$.refresh_token");
        assertThat(refresh2).isNotEqualTo(refresh1);
        assertAccessToken(second, subject, audience);
        mockMvc.perform(token().param("grant_type", "refresh_token").param("refresh_token", refresh2))
                .andExpect(status().isOk());
        mockMvc.perform(token().param("grant_type", "refresh_token").param("refresh_token", refresh1))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value(IamErrorCode.INVALID_GRANT.getCode()));
    }

    @Test
    void refreshReuseRevokesFamily() throws Exception {
        String first = exchangeCode(authorize("state-reuse", "nonce-reuse"), VERIFIER);
        String refresh1 = json(first, "$.refresh_token");
        String second = mockMvc.perform(token()
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", refresh1))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();
        String refresh2 = json(second, "$.refresh_token");
        mockMvc.perform(token().param("grant_type", "refresh_token").param("refresh_token", refresh1))
                .andExpect(status().isBadRequest());
        mockMvc.perform(token().param("grant_type", "refresh_token").param("refresh_token", refresh2))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value(IamErrorCode.INVALID_GRANT.getCode()));
    }

    @Test
    void clientCredentials() throws Exception {
        String body = mockMvc.perform(token()
                        .param("grant_type", "client_credentials")
                        .param("scope", "cc.read")
                        .param("audience", ccAudience))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();
        assertAccessToken(body, "client:" + clientId, ccAudience);
        assertThat(body).doesNotContain("refresh_token");
    }

    @Test
    void scopeEscalationIsRejected() throws Exception {
        mockMvc.perform(token()
                        .param("grant_type", "client_credentials")
                        .param("scope", "secret")
                        .param("audience", ccAudience))
                .andExpect(status().isForbidden());
        String code = authorize("state-scope", "nonce-scope");
        mockMvc.perform(token()
                        .param("grant_type", "authorization_code")
                        .param("code", code)
                        .param("redirect_uri", REDIRECT)
                        .param("code_verifier", VERIFIER)
                        .param("scope", "secret"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value(IamErrorCode.PERMISSION_DENIED.getCode()));
    }

    @Test
    void audienceEscalationIsRejected() throws Exception {
        mockMvc.perform(token()
                        .param("grant_type", "client_credentials")
                        .param("scope", "cc.read")
                        .param("audience", lockedAudience))
                .andExpect(status().isForbidden());
        String code = authorize("state-aud", "nonce-aud");
        mockMvc.perform(token()
                        .param("grant_type", "authorization_code")
                        .param("code", code)
                        .param("redirect_uri", REDIRECT)
                        .param("code_verifier", VERIFIER)
                        .param("audience", lockedAudience))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value(IamErrorCode.PERMISSION_DENIED.getCode()));
    }

    private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder token() {
        return post("/oauth2/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header(
                        "Authorization",
                        "Basic "
                                + org.springframework.http.HttpHeaders.encodeBasicAuth(
                                        clientId, SECRET, java.nio.charset.StandardCharsets.UTF_8));
    }

    private String authorize(String state, String nonce) throws Exception {
        MvcResult result = mockMvc.perform(get("/oauth2/authorize")
                        .param("client_id", clientId)
                        .param("redirect_uri", REDIRECT)
                        .param("response_type", "code")
                        .param("scope", OPENID)
                        .param("state", state + "-" + suffix)
                        .param("nonce", nonce + "-" + suffix)
                        .param("code_challenge", CHALLENGE)
                        .param("code_challenge_method", "S256")
                        .cookie(new Cookie(AuthorizationController.SESSION_COOKIE, sessionId)))
                .andExpect(status().isFound())
                .andReturn();
        return UriComponentsBuilder.fromUriString(result.getResponse().getHeader("Location"))
                .build(true)
                .getQueryParams()
                .getFirst("code");
    }

    private String exchangeCode(String code, String verifier) throws Exception {
        return mockMvc.perform(token()
                        .param("grant_type", "authorization_code")
                        .param("code", code)
                        .param("redirect_uri", REDIRECT)
                        .param("code_verifier", verifier))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();
    }

    private void assertAccessToken(String body, String expectedSub, String expectedAud) throws Exception {
        String accessToken = json(body, "$.access_token");
        SignedJWT jwt = jwtSigner.verify(accessToken);
        JWTClaimsSet claims = jwt.getJWTClaimsSet();
        assertThat(claims.getIssuer()).isEqualTo("https://auth.example.com");
        assertThat(claims.getSubject()).isEqualTo(expectedSub);
        assertThat(claims.getAudience()).contains(expectedAud);
        assertThat(claims.getJWTID()).isNotBlank();
        Date exp = claims.getExpirationTime();
        Instant expectedExp = Instant.now().plusSeconds(600);
        assertThat(exp.toInstant()).isBetween(expectedExp.minusSeconds(30), expectedExp.plusSeconds(30));
        assertThat(json(body, "$.expires_in")).isEqualTo("600");
    }

    private static String json(String body, String path) {
        Object value = com.jayway.jsonpath.JsonPath.read(body, path);
        return value == null ? null : String.valueOf(value);
    }
}
