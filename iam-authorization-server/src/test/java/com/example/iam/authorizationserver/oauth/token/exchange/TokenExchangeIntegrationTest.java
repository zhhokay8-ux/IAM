package com.example.iam.authorizationserver.oauth.token.exchange;

import static org.assertj.core.api.Assertions.assertThat;
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
import com.example.iam.token.oauth.AccessTokenClaims;
import com.example.iam.token.oauth.AccessTokenService;
import com.example.iam.token.signing.JwtSigner;
import com.example.iam.user.dto.CreateUserRequest;
import com.example.iam.user.dto.UserResponse;
import com.example.iam.user.service.IamUserService;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
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
@TestPropertySource(properties = "iam.issuer=https://auth.example.com")
public class TokenExchangeIntegrationTest extends AbstractIamIntegrationTest {

    private static final String GRANT = TokenExchangeServiceImpl.GRANT;
    private static final String ACCESS = SubjectTokenValidator.ACCESS_TOKEN_TYPE;
    private static final String SECRET = "super-secret";
    private static final String REDIRECT = "https://system1.example.com/login/callback";

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
    private AccessTokenService accessTokenService;

    @Autowired
    private JwtSigner jwtSigner;

    private String suffix;
    private String system1ClientId;
    private String system1Audience;
    private String systemNAudience;
    private String subject;
    private String orderScope = "order.read";

    @BeforeEach
    void setUp() {
        suffix = UUID.randomUUID().toString().substring(0, 8);
        system1ClientId = "system-1-" + suffix;
        system1Audience = "system-1-api-" + suffix;
        systemNAudience = "system-n-api-" + suffix;
        String system1Resource = "SYSTEM_1_" + suffix;
        String systemNResource = "SYSTEM_N_" + suffix;
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
                List.of(new RedirectUriInput(REDIRECT, "LOGIN_CALLBACK")),
                SECRET));
        resourceService.create(new CreateResourceRequest(
                system1Resource, "System1 API", system1Audience, RegistryStatus.ACTIVE, "iam"));
        resourceService.create(new CreateResourceRequest(
                systemNResource, "SystemN API", systemNAudience, RegistryStatus.ACTIVE, "iam"));
        scopeService.create(new CreateScopeRequest(system1Resource, "openid", "OpenID", "openid", RegistryStatus.ACTIVE));
        scopeService.create(
                new CreateScopeRequest(systemNResource, orderScope, "Order read", "order", RegistryStatus.ACTIVE));
        permissionService.create(new CreatePermissionRequest(
                system1ClientId, system1Resource, "openid", "authorization_code", RegistryStatus.ACTIVE));
        permissionService.create(new CreatePermissionRequest(
                system1ClientId, systemNResource, orderScope, "TOKEN_EXCHANGE", RegistryStatus.ACTIVE));
        UserResponse user = userService.create(new CreateUserRequest(
                "user-" + suffix, "User", "user-" + suffix + "@example.com", "tenant-1", "org-1", "ACTIVE"));
        subject = user.subjectId();
    }

    @Test
    void system1ExchangesForSystemNTokenWithNewJtiAndSignature() throws Exception {
        String tokenA = issueSubjectToken(system1Audience, Instant.now().plusSeconds(600), "jti-a");
        MvcResult result = mockMvc.perform(exchange(tokenA, systemNAudience, orderScope)
                        .param("requested_token_type", ACCESS))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.issued_token_type").value(ACCESS))
                .andReturn();
        String tokenB = json(result.getResponse().getContentAsString(), "$.access_token");
        assertThat(tokenB).isNotEqualTo(tokenA);
        JWTClaimsSet a = jwtSigner.verify(tokenA).getJWTClaimsSet();
        JWTClaimsSet b = jwtSigner.verify(tokenB).getJWTClaimsSet();
        assertThat(b.getSubject()).isEqualTo(subject);
        assertThat(b.getIssuer()).isEqualTo("https://auth.example.com");
        assertThat(b.getAudience()).containsExactly(systemNAudience);
        assertThat(b.getAudience()).doesNotContain(system1Audience);
        assertThat(a.getAudience()).containsExactly(system1Audience);
        assertThat(b.getJWTID()).isNotBlank().isNotEqualTo(a.getJWTID());
        assertThat(b.getStringClaim("client_id")).isEqualTo(system1ClientId);
        assertThat(b.getStringClaim("scope")).isEqualTo(orderScope);
        SignedJWT signedA = SignedJWT.parse(tokenA);
        SignedJWT signedB = SignedJWT.parse(tokenB);
        assertThat(signedB.getSignature()).isNotEqualTo(signedA.getSignature());
    }

    @Test
    void systemNAudienceDoesNotAcceptSystem1Token() throws Exception {
        String tokenA = issueSubjectToken(system1Audience, Instant.now().plusSeconds(600), "jti-src");
        JWTClaimsSet claims = jwtSigner.verify(tokenA).getJWTClaimsSet();
        assertThat(claims.getAudience()).doesNotContain(systemNAudience);
        String tokenB = json(mockMvc.perform(exchange(tokenA, systemNAudience, orderScope))
                        .andExpect(status().isOk())
                        .andReturn()
                        .getResponse()
                        .getContentAsString(),
                "$.access_token");
        assertThat(jwtSigner.verify(tokenB).getJWTClaimsSet().getAudience()).containsExactly(systemNAudience);
    }

    @Test
    void expiredSubjectTokenIsRejected() throws Exception {
        String tokenA = issueSubjectToken(system1Audience, Instant.now().minusSeconds(30), "jti-exp");
        mockMvc.perform(exchange(tokenA, systemNAudience, orderScope))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value(IamErrorCode.JWT_EXPIRED.getCode()));
    }

    @Test
    void actorClaimIsIssuedWhenActorTokenPresent() throws Exception {
        String tokenA = issueSubjectToken(system1Audience, Instant.now().plusSeconds(600), "jti-sub");
        String actor = issueSubjectToken(system1Audience, Instant.now().plusSeconds(600), "jti-act");
        String body = mockMvc.perform(exchange(tokenA, systemNAudience, orderScope)
                        .param("actor_token", actor)
                        .param("actor_token_type", ACCESS))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();
        JWTClaimsSet claims = jwtSigner.verify(json(body, "$.access_token")).getJWTClaimsSet();
        @SuppressWarnings("unchecked")
        Map<String, Object> act = (Map<String, Object>) claims.getClaim("act");
        assertThat(act).isNotNull();
        assertThat(act.get("sub")).isEqualTo(subject);
    }

    private String issueSubjectToken(String audience, Instant exp, String jti) {
        Instant iat = exp.isBefore(Instant.now()) ? exp.minusSeconds(600) : Instant.now();
        return accessTokenService.issue(new AccessTokenClaims(
                subject,
                List.of(audience),
                system1ClientId,
                "openid",
                List.of(),
                "tenant-1",
                "org-1",
                iat,
                exp,
                jti,
                null,
                null));
    }

    private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder exchange(
            String subjectToken, String audience, String scope) {
        return post("/oauth2/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header(
                        HttpHeaders.AUTHORIZATION,
                        "Basic " + HttpHeaders.encodeBasicAuth(system1ClientId, SECRET, StandardCharsets.UTF_8))
                .param("grant_type", GRANT)
                .param("subject_token", subjectToken)
                .param("subject_token_type", ACCESS)
                .param("audience", audience)
                .param("scope", scope);
    }

    private static String json(String body, String path) {
        Object value = com.jayway.jsonpath.JsonPath.read(body, path);
        return value == null ? null : String.valueOf(value);
    }
}
