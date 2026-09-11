package com.example.iam.authorizationserver.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
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
import com.example.iam.clientregistry.dto.UpdateClientRequest;
import com.example.iam.clientregistry.service.IamClientService;
import com.example.iam.clientregistry.service.IamPermissionService;
import com.example.iam.clientregistry.service.IamResourceService;
import com.example.iam.clientregistry.service.IamScopeService;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.common.util.IdGenerator;
import com.example.iam.core.redis.RedisKeyConstants;
import com.example.iam.session.IamSession;
import com.example.iam.session.IamSessionService;
import com.example.iam.token.oauth.AuthorizationCodePayload;
import com.example.iam.token.oauth.AuthorizationCodeService;
import jakarta.servlet.http.Cookie;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.util.UriComponentsBuilder;

@SpringBootTest(classes = IamAuthorizationServerApplication.class)
@AutoConfigureMockMvc
class AuthorizationControllerTest extends AbstractIamIntegrationTest {

    private static final String REDIRECT = "https://portal.example.com/login/callback";
    private static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private static final String SCOPE = "openid";

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
    private IamSessionService sessionService;

    @Autowired
    private AuthorizationCodeService authorizationCodeService;

    @Autowired
    private StringRedisTemplate redisTemplate;

    private String clientId;
    private String subject;
    private String sessionId;

    @BeforeEach
    void setUpClient() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        clientId = "portal-" + suffix;
        String resourceCode = "OIDC-" + suffix;
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
                "secret"));
        resourceService.create(new CreateResourceRequest(resourceCode, "OIDC", "aud-" + suffix, RegistryStatus.ACTIVE, "iam"));
        scopeService.create(new CreateScopeRequest(resourceCode, SCOPE, "OpenID", "openid", RegistryStatus.ACTIVE));
        permissionService.create(new CreatePermissionRequest(
                clientId, resourceCode, SCOPE, "authorization_code", RegistryStatus.ACTIVE));
        subject = IdGenerator.next();
        IamSession session = sessionService.create(subject, clientId, "pwd");
        sessionId = session.sid();
    }

    @Test
    void successfulAuthorizationReturnsCodeAndStateOnly() throws Exception {
        String state = "state-ok";
        MvcResult result = mockMvc.perform(authorize(state, "nonce-ok", CHALLENGE, "S256"))
                .andExpect(status().isFound())
                .andReturn();
        String location = result.getResponse().getHeader("Location");
        assertThat(location).startsWith(REDIRECT);
        assertThat(location).contains("code=");
        assertThat(location).contains("state=" + state);
        assertThat(location).doesNotContain("token=");
        assertThat(location).doesNotContain("access_token");
        String code = queryParam(location, "code");
        AuthorizationCodePayload payload = authorizationCodeService.consume(code, clientId, REDIRECT);
        assertEquals(subject, payload.subject());
        assertEquals(clientId, payload.clientId());
        assertEquals(REDIRECT, payload.redirectUri());
        assertEquals(CHALLENGE, payload.codeChallenge());
    }

    @Test
    void invalidClient() throws Exception {
        mockMvc.perform(authorize("state", "nonce", CHALLENGE, "S256").param("client_id", "missing-client"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value(IamErrorCode.INVALID_CLIENT.getCode()));
    }

    @Test
    void invalidRedirectUri() throws Exception {
        mockMvc.perform(authorize("state", "nonce", CHALLENGE, "S256")
                        .param("redirect_uri", "https://evil.example.com/callback"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value(IamErrorCode.INVALID_REDIRECT_URI.getCode()));
    }

    @Test
    void redirectUriOneCharacterDifferenceIsRejected() throws Exception {
        mockMvc.perform(authorize("state", "nonce", CHALLENGE, "S256")
                        .param("redirect_uri", REDIRECT + "x"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value(IamErrorCode.INVALID_REDIRECT_URI.getCode()));
    }

    @Test
    void invalidScope() throws Exception {
        MvcResult result = mockMvc.perform(authorize("state-scope", "nonce-scope", CHALLENGE, "S256")
                        .param("scope", "not-a-real-scope"))
                .andExpect(status().isFound())
                .andReturn();
        String location = result.getResponse().getHeader("Location");
        assertThat(location).contains("error=invalid_scope");
        assertThat(location).contains("state=state-scope");
        assertThat(location).doesNotContain("code=");
    }

    @Test
    void missingState() throws Exception {
        MvcResult result = mockMvc.perform(authorize(null, "nonce-state", CHALLENGE, "S256"))
                .andExpect(status().isFound())
                .andReturn();
        String location = result.getResponse().getHeader("Location");
        assertThat(location).contains("error=invalid_request");
        assertThat(location).doesNotContain("code=");
        assertThat(location).doesNotContain("state=");
    }

    @Test
    void missingNonce() throws Exception {
        MvcResult result = mockMvc.perform(authorize("state-nonce", null, CHALLENGE, "S256"))
                .andExpect(status().isFound())
                .andReturn();
        String location = result.getResponse().getHeader("Location");
        assertThat(location).contains("error=invalid_request");
        assertThat(location).contains("state=state-nonce");
        assertThat(location).doesNotContain("code=");
    }

    @Test
    void missingCodeChallenge() throws Exception {
        MvcResult result = mockMvc.perform(authorize("state-ch", "nonce-ch", null, "S256"))
                .andExpect(status().isFound())
                .andReturn();
        assertThat(result.getResponse().getHeader("Location")).contains("error=invalid_request");
    }

    @Test
    void plainPkceIsRejected() throws Exception {
        MvcResult result = mockMvc.perform(authorize("state-plain", "nonce-plain", CHALLENGE, "plain"))
                .andExpect(status().isFound())
                .andReturn();
        assertThat(result.getResponse().getHeader("Location")).contains("error=invalid_request");
    }

    @Test
    void invalidCodeChallenge() throws Exception {
        MvcResult result = mockMvc.perform(authorize(
                        "state-bad-ch",
                        "nonce-bad-ch",
                        "!!!!not-a-challenge!!!!not-a-challenge!!!!",
                        "S256"))
                .andExpect(status().isFound())
                .andReturn();
        assertThat(result.getResponse().getHeader("Location")).contains("error=invalid_request");
    }

    @Test
    void codeReplayIsRejected() throws Exception {
        String location = mockMvc.perform(authorize("state-replay", "nonce-replay", CHALLENGE, "S256"))
                .andExpect(status().isFound())
                .andReturn()
                .getResponse()
                .getHeader("Location");
        String code = queryParam(location, "code");
        authorizationCodeService.consume(code, clientId, REDIRECT);
        IamException second = assertThrows(
                IamException.class, () -> authorizationCodeService.consume(code, clientId, REDIRECT));
        assertEquals(IamErrorCode.INVALID_GRANT, second.getErrorCode());
    }

    @Test
    void expiredCodeCannotBeExchanged() throws Exception {
        String location = mockMvc.perform(authorize("state-exp", "nonce-exp", CHALLENGE, "S256"))
                .andExpect(status().isFound())
                .andReturn()
                .getResponse()
                .getHeader("Location");
        String code = queryParam(location, "code");
        redisTemplate.expire(RedisKeyConstants.authorizationCode(code), Duration.ofMillis(1));
        Thread.sleep(20);
        IamException ex = assertThrows(
                IamException.class, () -> authorizationCodeService.consume(code, clientId, REDIRECT));
        assertEquals(IamErrorCode.INVALID_GRANT, ex.getErrorCode());
    }

    @Test
    void clientDisabled() throws Exception {
        clientService.update(
                clientId,
                new UpdateClientRequest(null, RegistryStatus.INACTIVE, null, null, null, null, null, null));
        mockMvc.perform(authorize("state-off", "nonce-off", CHALLENGE, "S256"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value(IamErrorCode.CLIENT_INACTIVE.getCode()));
    }

    private MockHttpServletRequestBuilder authorize(
            String state, String nonce, String challenge, String method) {
        MockHttpServletRequestBuilder builder = get("/oauth2/authorize")
                .param("client_id", clientId)
                .param("redirect_uri", REDIRECT)
                .param("response_type", "code")
                .param("scope", SCOPE)
                .cookie(new Cookie(AuthorizationController.SESSION_COOKIE, sessionId));
        if (state != null) {
            builder.param("state", state);
        }
        if (nonce != null) {
            builder.param("nonce", nonce);
        }
        if (challenge != null) {
            builder.param("code_challenge", challenge);
        }
        if (method != null) {
            builder.param("code_challenge_method", method);
        }
        return builder;
    }

    private static String queryParam(String location, String name) {
        return UriComponentsBuilder.fromUriString(location).build(true).getQueryParams().getFirst(name);
    }
}
