package com.example.iam.authorizationserver.migration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.iam.authorizationserver.AbstractIamIntegrationTest;
import com.example.iam.authorizationserver.IamAuthorizationServerApplication;
import com.example.iam.authorizationserver.sso.SsoCookieService;
import com.example.iam.clientregistry.domain.RegistryStatus;
import com.example.iam.clientregistry.dto.CreateClientRequest;
import com.example.iam.clientregistry.dto.RedirectUriInput;
import com.example.iam.clientregistry.service.IamClientService;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.core.redis.RedisKeyConstants;
import com.example.iam.migration.MigrationLoginController;
import com.example.iam.user.dto.CreateUserRequest;
import com.example.iam.user.dto.IdentityMappingRequest;
import com.example.iam.user.dto.UserResponse;
import com.example.iam.user.service.IamIdentityMappingService;
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

@SpringBootTest(classes = IamAuthorizationServerApplication.class)
@AutoConfigureMockMvc
@TestPropertySource(properties = {"iam.issuer=https://auth.example.com", "iam.sso.cookie-secure=false"})
public class MigrationLoginIntegrationTest extends AbstractIamIntegrationTest {

    private static final String RETURN_TO = "https://portal.example.com/login/callback";
    private static final String SECRET = "super-secret";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private IamClientService clientService;

    @Autowired
    private IamUserService userService;

    @Autowired
    private IamIdentityMappingService mappingService;

    @Autowired
    private StringRedisTemplate redisTemplate;

    private String clientId;
    private String subject;

    @BeforeEach
    void setUp() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        clientId = "portal-" + suffix;
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
                List.of(new RedirectUriInput(RETURN_TO, "LOGIN_CALLBACK")),
                SECRET));
        UserResponse user = userService.create(
                new CreateUserRequest("user-" + suffix, "User", "user-" + suffix + "@example.com", "tenant-1", "org-1", "ACTIVE"));
        subject = user.subjectId();
        mappingService.create(
                UUID.fromString(subject), new IdentityMappingRequest("portal", "zhangsan-" + suffix, "zhangsan", "ACTIVE"));
    }

    @Test
    void legacySessionMigratesToIamSsoViaOneTimeTicket() throws Exception {
        String browser = "browser-" + UUID.randomUUID();
        String nonce = "nonce-" + UUID.randomUUID();
        String mappingUser = mappingService.list(UUID.fromString(subject)).get(0).externalUserId();
        MvcResult issued = mockMvc.perform(post("/api/migration/ticket")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header(
                                HttpHeaders.AUTHORIZATION,
                                "Basic " + HttpHeaders.encodeBasicAuth(clientId, SECRET, StandardCharsets.UTF_8))
                        .content("""
                                {"client_id":"%s","client_secret":"%s","system_code":"portal",\
                                "external_user_id":"%s","browser_session":"%s","nonce":"%s",\
                                "return_to":"%s"}
                                """.formatted(clientId, SECRET, mappingUser, browser, nonce, RETURN_TO)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ticket").exists())
                .andReturn();
        String ticket = com.jayway.jsonpath.JsonPath.read(issued.getResponse().getContentAsString(), "$.ticket");
        assertThat(Boolean.TRUE.equals(redisTemplate.hasKey(RedisKeyConstants.migrationTicket(ticket)))).isTrue();

        MvcResult login = mockMvc.perform(get("/migration/login")
                        .param("ticket", ticket)
                        .cookie(new Cookie(MigrationLoginController.BROWSER_COOKIE, browser))
                        .cookie(new Cookie(MigrationLoginController.NONCE_COOKIE, nonce)))
                .andExpect(status().isFound())
                .andExpect(header().string(HttpHeaders.LOCATION, RETURN_TO))
                .andReturn();
        Cookie sso = login.getResponse().getCookie(SsoCookieService.COOKIE_NAME);
        assertThat(sso).isNotNull();
        assertThat(sso.isHttpOnly()).isTrue();
        assertThat(Boolean.TRUE.equals(redisTemplate.hasKey(RedisKeyConstants.migrationTicket(ticket)))).isFalse();

        mockMvc.perform(get("/sso/session").cookie(sso))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.subject_id").value(subject));

        mockMvc.perform(get("/migration/login")
                        .param("ticket", ticket)
                        .cookie(new Cookie(MigrationLoginController.BROWSER_COOKIE, browser))
                        .cookie(new Cookie(MigrationLoginController.NONCE_COOKIE, nonce)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value(IamErrorCode.MIGRATION_TICKET_REPLAY.getCode()));
    }

    @Test
    void sessionQueryIsRejected() throws Exception {
        mockMvc.perform(get("/migration/login").param("session", "PORTAL_LEGACY_SESSION"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value(IamErrorCode.MIGRATION_LEGACY_IN_URL.getCode()));
    }
}
