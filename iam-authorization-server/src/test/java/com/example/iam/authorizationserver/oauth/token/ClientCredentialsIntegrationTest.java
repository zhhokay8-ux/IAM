package com.example.iam.authorizationserver.oauth.token;

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
import com.example.iam.clientregistry.dto.UpdateClientRequest;
import com.example.iam.clientregistry.service.IamClientService;
import com.example.iam.clientregistry.service.IamPermissionService;
import com.example.iam.clientregistry.service.IamResourceService;
import com.example.iam.clientregistry.service.IamScopeService;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.token.signing.JwtSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import java.nio.charset.StandardCharsets;
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

@SpringBootTest(classes = IamAuthorizationServerApplication.class)
@AutoConfigureMockMvc
@TestPropertySource(properties = "iam.issuer=https://auth.example.com")
public class ClientCredentialsIntegrationTest extends AbstractIamIntegrationTest {

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
    private JwtSigner jwtSigner;

    private String suffix;
    private String system1ClientId;
    private String systemNAudience;
    private String scopeCode;

    @BeforeEach
    void setUp() {
        suffix = UUID.randomUUID().toString().substring(0, 8);
        system1ClientId = "system-1-" + suffix;
        systemNAudience = "system-n-api-" + suffix;
        scopeCode = "system-n.data.read";
        String resource = "SYSTEM_N_" + suffix;
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
        resourceService.create(
                new CreateResourceRequest(resource, "SystemN API", systemNAudience, RegistryStatus.ACTIVE, "iam"));
        scopeService.create(new CreateScopeRequest(resource, scopeCode, "N read", "n", RegistryStatus.ACTIVE));
        permissionService.create(new CreatePermissionRequest(
                system1ClientId, resource, scopeCode, "client_credentials", RegistryStatus.ACTIVE));
    }

    @Test
    void system1CallsSystemNWithServiceTokenAndNoUserContext() throws Exception {
        String body = mockMvc.perform(token()
                        .param("grant_type", "client_credentials")
                        .param("scope", scopeCode)
                        .param("audience", systemNAudience))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andReturn()
                .getResponse()
                .getContentAsString();
        assertThat(body).doesNotContain("refresh_token");
        JWTClaimsSet claims = jwtSigner.verify(json(body, "$.access_token")).getJWTClaimsSet();
        assertThat(claims.getSubject()).isEqualTo(ServiceTokenService.subjectFor(system1ClientId));
        assertThat(ServiceTokenService.isServiceSubject(claims.getSubject())).isTrue();
        assertThat(claims.getAudience()).containsExactly(systemNAudience);
        assertThat(claims.getStringClaim("client_id")).isEqualTo(system1ClientId);
        assertThat(claims.getStringClaim("scope")).isEqualTo(scopeCode);
        assertThat(claims.getStringClaim("token_use")).isEqualTo(ServiceTokenService.TOKEN_USE);
        assertThat(claims.getStringClaim("tenant_id")).isNull();
        assertThat(claims.getStringClaim("org_id")).isNull();
        assertThat(claims.getClaim("act")).isNull();
        assertThat(claims.getJWTID()).isNotBlank();
        assertThat(claims.getIssuer()).isEqualTo("https://auth.example.com");
    }

    @Test
    void invalidSecret() throws Exception {
        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "client_credentials")
                        .param("client_id", system1ClientId)
                        .param("client_secret", "wrong-secret")
                        .param("scope", scopeCode)
                        .param("audience", systemNAudience))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value(IamErrorCode.INVALID_CLIENT.getCode()));
    }

    @Test
    void disabledClient() throws Exception {
        clientService.update(
                system1ClientId,
                new UpdateClientRequest(null, RegistryStatus.INACTIVE, null, null, null, null, null, null));
        mockMvc.perform(token()
                        .param("grant_type", "client_credentials")
                        .param("scope", scopeCode)
                        .param("audience", systemNAudience))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value(IamErrorCode.CLIENT_INACTIVE.getCode()));
    }

    private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder token() {
        return post("/oauth2/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header(
                        HttpHeaders.AUTHORIZATION,
                        "Basic " + HttpHeaders.encodeBasicAuth(system1ClientId, SECRET, StandardCharsets.UTF_8));
    }

    private static String json(String body, String path) {
        Object value = com.jayway.jsonpath.JsonPath.read(body, path);
        return value == null ? null : String.valueOf(value);
    }
}
