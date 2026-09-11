package com.example.iam.authorizationserver.embed;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.iam.authorizationserver.AbstractIamIntegrationTest;
import com.example.iam.authorizationserver.IamAuthorizationServerApplication;
import com.example.iam.authorizationserver.sso.SsoCookieService;
import com.example.iam.authorizationserver.sso.SsoTestPassword;
import com.example.iam.clientregistry.domain.RegistryStatus;
import com.example.iam.clientregistry.dto.CreateClientRequest;
import com.example.iam.clientregistry.dto.RedirectUriInput;
import com.example.iam.clientregistry.service.IamClientService;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.embed.entity.IamEmbedPolicyEntity;
import com.example.iam.embed.repository.IamEmbedPolicyRepository;
import com.example.iam.user.dto.CreateUserRequest;
import com.example.iam.user.service.IamUserService;
import jakarta.servlet.http.Cookie;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
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
public class EmbedExchangeIntegrationTest extends AbstractIamIntegrationTest {

    private static final String SECRET = "super-secret";
    private static final String ORIGIN = "https://portal.example.com";
    private static final String PATH = "/orders/1";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private IamClientService clientService;

    @Autowired
    private IamUserService userService;

    @Autowired
    private IamEmbedPolicyRepository policyRepository;

    private String suffix;
    private String parentClientId;
    private String childClientId;
    private String username;
    private UUID parentId;
    private UUID childId;
    private Cookie csrf;

    @BeforeEach
    void setUp() {
        suffix = UUID.randomUUID().toString().substring(0, 8);
        parentClientId = "portal-" + suffix;
        childClientId = "system-n-" + suffix;
        username = "user-" + suffix;
        parentId = clientService.create(new CreateClientRequest(
                        parentClientId,
                        "Portal",
                        "confidential",
                        RegistryStatus.ACTIVE,
                        "client_secret_basic",
                        600,
                        86400,
                        true,
                        "iam",
                        List.of(new RedirectUriInput("https://portal.example.com/cb", "LOGIN_CALLBACK")),
                        SECRET))
                .id();
        childId = clientService.create(new CreateClientRequest(
                        childClientId,
                        "SystemN",
                        "confidential",
                        RegistryStatus.ACTIVE,
                        "client_secret_basic",
                        600,
                        86400,
                        true,
                        "iam",
                        List.of(new RedirectUriInput("https://systemn.example.com/cb", "LOGIN_CALLBACK")),
                        SECRET))
                .id();
        userService.create(new CreateUserRequest(
                username, "User", username + "@example.com", "tenant-1", "org-1", "ACTIVE", SsoTestPassword.RAW));
        policyRepository.save(IamEmbedPolicyEntity.builder()
                .parentClientId(parentId)
                .childClientId(childId)
                .parentOrigin(ORIGIN)
                .allowedPath("/orders/*")
                .status(RegistryStatus.ACTIVE)
                .createdAt(Instant.now())
                .build());
    }

    @Test
    void validEmbedCodeIsSingleUse() throws Exception {
        Cookie session = login();
        String code = issue(session, childClientId, PATH, ORIGIN, "nonce-" + suffix);
        MvcResult exchanged = mockMvc.perform(exchange(childClientId, code, ORIGIN, "nonce-" + suffix, session.getValue()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.child_client_id").value(childClientId))
                .andExpect(jsonPath("$.parent_client_id").value(parentClientId))
                .andReturn();
        assertThat(exchanged.getResponse().getContentAsString()).contains("subject_id");
        mockMvc.perform(exchange(childClientId, code, ORIGIN, "nonce-" + suffix, session.getValue()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value(IamErrorCode.EMBED_CODE_REPLAY.getCode()));
    }

    @Test
    void wrongChildCannotRedeem() throws Exception {
        Cookie session = login();
        String code = issue(session, childClientId, PATH, ORIGIN, "nonce-child-" + suffix);
        mockMvc.perform(exchange(parentClientId, code, ORIGIN, "nonce-child-" + suffix, session.getValue()))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value(IamErrorCode.EMBED_CLIENT_MISMATCH.getCode()));
    }

    @Test
    void wrongOriginIsRejected() throws Exception {
        Cookie session = login();
        mockMvc.perform(post("/api/embed/code")
                        .cookie(session, csrf)
                        .header(com.example.iam.common.security.CsrfTokenService.HEADER, csrf.getValue())
                        .header(HttpHeaders.ORIGIN, ORIGIN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"child_client_id":"%s","path":"%s","origin":"https://evil.example.com","nonce":"n"}
                                """.formatted(childClientId, PATH)))
                .andExpect(status().isForbidden());
    }

    @Test
    void policyDisabledIsRejected() throws Exception {
        policyRepository.deleteAll();
        policyRepository.save(IamEmbedPolicyEntity.builder()
                .parentClientId(parentId)
                .childClientId(childId)
                .parentOrigin(ORIGIN)
                .allowedPath("/orders/*")
                .status(RegistryStatus.INACTIVE)
                .createdAt(Instant.now())
                .build());
        Cookie session = login();
        mockMvc.perform(post("/api/embed/code")
                        .cookie(session, csrf)
                        .header(com.example.iam.common.security.CsrfTokenService.HEADER, csrf.getValue())
                        .header(HttpHeaders.ORIGIN, ORIGIN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"child_client_id":"%s","path":"%s","origin":"%s","nonce":"n"}
                                """.formatted(childClientId, PATH, ORIGIN)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value(IamErrorCode.EMBED_POLICY_DISABLED.getCode()));
    }

    @Test
    void iamEmbedScriptForbidsWildcardTargetOrigin() throws Exception {
        String script = mockMvc.perform(get("/iam-embed.js"))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();
        assertThat(script).contains("wildcard is forbidden");
        assertThat(script).doesNotContain("postMessage(message, \"*\")");
        assertThat(script).doesNotContain("postMessage(message, '*')");
    }

    private Cookie login() throws Exception {
        MvcResult result = mockMvc.perform(post("/sso/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"%s","password":"%s","tenant_id":"tenant-1","client_id":"%s"}
                                """.formatted(username, SsoTestPassword.RAW, parentClientId)))
                .andExpect(status().isOk())
                .andReturn();
        csrf = result.getResponse().getCookie(com.example.iam.common.security.CsrfTokenService.COOKIE);
        return result.getResponse().getCookie(SsoCookieService.COOKIE_NAME);
    }

    private String issue(Cookie session, String child, String path, String origin, String nonce) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/embed/code")
                        .cookie(session, csrf)
                        .header(com.example.iam.common.security.CsrfTokenService.HEADER, csrf.getValue())
                        .header(HttpHeaders.ORIGIN, ORIGIN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"child_client_id":"%s","path":"%s","origin":"%s","nonce":"%s"}
                                """.formatted(child, path, origin, nonce)))
                .andExpect(status().isOk())
                .andReturn();
        return com.jayway.jsonpath.JsonPath.read(result.getResponse().getContentAsString(), "$.code");
    }

    private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder exchange(
            String clientId, String code, String origin, String nonce, String sessionId) {
        return post("/api/embed/exchange")
                .contentType(MediaType.APPLICATION_JSON)
                .header(
                        HttpHeaders.AUTHORIZATION,
                        "Basic " + HttpHeaders.encodeBasicAuth(clientId, SECRET, StandardCharsets.UTF_8))
                .content("""
                        {"code":"%s","origin":"%s","nonce":"%s","session_id":"%s"}
                        """.formatted(code, origin, nonce, sessionId));
    }
}
