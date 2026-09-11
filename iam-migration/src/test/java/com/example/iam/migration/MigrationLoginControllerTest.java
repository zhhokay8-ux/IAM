package com.example.iam.migration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.session.IamSession;
import com.example.iam.session.IamSessionService;
import jakarta.servlet.http.Cookie;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class MigrationLoginControllerTest {

    @Mock
    private MigrationTicketService ticketService;

    @Mock
    private MigrationClientAuthenticator clientAuthenticator;

    @Mock
    private IamSessionService sessionService;

    @Mock
    private MigrationSsoCookieWriter cookieWriter;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(
                        new MigrationLoginController(ticketService, clientAuthenticator, sessionService, cookieWriter))
                .setControllerAdvice(new com.example.iam.common.web.GlobalExceptionHandler())
                .build();
    }

    @Test
    void issuesTicketForConfidentialClient() throws Exception {
        when(ticketService.issue(any()))
                .thenReturn(new CreateMigrationTicketResponse(
                        "t-1", Instant.parse("2026-09-10T07:00:45Z"), "/migration/login?ticket=t-1"));
        mockMvc.perform(post("/api/migration/ticket")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"client_id":"portal","client_secret":"s","system_code":"portal",\
                                "external_user_id":"zhangsan","browser_session":"b","nonce":"n",\
                                "return_to":"https://portal.example.com/login/callback"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ticket").value("t-1"));
        verify(clientAuthenticator).authenticateConfidential("portal", "s");
    }

    @Test
    void loginRedeemsTicketAndRedirectsToPortal() throws Exception {
        MigrationTicket ticket = new MigrationTicket(
                "t-1",
                "portal",
                "u-1",
                "b",
                "n",
                "https://portal.example.com/login/callback",
                Instant.parse("2026-09-10T07:00:00Z"),
                Instant.parse("2026-09-10T07:00:45Z"));
        when(ticketService.redeem(any())).thenReturn(ticket);
        IamSession session = new IamSession(
                "sid", "u-1", Instant.now(), Instant.now(), Instant.now(), "migration", "portal", "ACTIVE");
        when(sessionService.create("u-1", "portal", "migration")).thenReturn(session);
        when(sessionService.ttl()).thenReturn(Duration.ofHours(8));
        mockMvc.perform(get("/migration/login")
                        .param("ticket", "t-1")
                        .cookie(new Cookie(MigrationLoginController.BROWSER_COOKIE, "b"))
                        .cookie(new Cookie(MigrationLoginController.NONCE_COOKIE, "n")))
                .andExpect(status().isFound())
                .andExpect(header().string("Location", "https://portal.example.com/login/callback"));
        verify(cookieWriter).write(any(), eq(session), eq(Duration.ofHours(8)));
    }

    @Test
    void sessionQueryParameterIsRejected() throws Exception {
        mockMvc.perform(get("/migration/login").param("session", "PORTAL_LEGACY_SESSION"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value(IamErrorCode.MIGRATION_LEGACY_IN_URL.getCode()));
    }
}
