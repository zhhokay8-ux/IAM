package com.example.iam.authorizationserver.oidc.logout;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.iam.authorizationserver.sso.SsoCookieService;
import com.example.iam.session.IamSession;
import com.example.iam.session.IamSessionService;
import com.example.iam.token.oauth.RefreshTokenFamilyService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class LogoutServiceTest {

    private static final UUID SUBJECT = UUID.fromString("01999a2e-7c3a-7000-8000-000000000001");
    private static final String SID = "sid-1";

    @Mock
    private SsoCookieService cookieService;

    @Mock
    private IamSessionService sessionService;

    @Mock
    private RefreshTokenFamilyService refreshTokenFamilyService;

    @Mock
    private BackChannelLogoutService backChannelLogoutService;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    private LogoutServiceImpl service;

    @BeforeEach
    void setUp() {
        service = new LogoutServiceImpl(
                cookieService,
                sessionService,
                refreshTokenFamilyService,
                backChannelLogoutService,
                org.mockito.Mockito.mock(com.example.iam.audit.IamAuditService.class));
    }

    @Test
    void localLogoutClearsCookieOnly() {
        when(cookieService.readSid(request)).thenReturn(SID);
        when(sessionService.find(SID)).thenReturn(Optional.of(session()));
        service.logout(request, response, "local");
        verify(cookieService).clear(response);
        verify(sessionService, never()).delete(any());
        verify(refreshTokenFamilyService, never()).revokeAllForSubject(any());
        verify(backChannelLogoutService, never()).notifyClients(any(), any());
    }

    @Test
    void globalLogoutDeletesSessionRevokesRefreshAndNotifiesClients() {
        when(cookieService.readSid(request)).thenReturn(SID);
        when(sessionService.find(SID)).thenReturn(Optional.of(session()));
        service.logout(request, response, "global");
        verify(sessionService).delete(SID);
        verify(refreshTokenFamilyService).revokeAllForSubject(SUBJECT);
        verify(backChannelLogoutService).notifyClients(eq(SUBJECT.toString()), eq(SID));
        verify(cookieService).clear(response);
    }

    @Test
    void defaultLogoutTypeIsGlobal() {
        when(cookieService.readSid(request)).thenReturn(SID);
        when(sessionService.find(SID)).thenReturn(Optional.of(session()));
        service.logout(request, response, null);
        verify(sessionService).delete(SID);
        verify(backChannelLogoutService).notifyClients(SUBJECT.toString(), SID);
    }

    @Test
    void globalLogoutWithoutSessionStillClearsCookie() {
        when(cookieService.readSid(request)).thenReturn(null);
        assertDoesNotThrow(() -> service.logout(request, response, "global"));
        verify(cookieService).clear(response);
        verify(sessionService, never()).delete(any());
    }

    private static IamSession session() {
        Instant now = Instant.parse("2026-09-10T06:00:00Z");
        return new IamSession(SID, SUBJECT.toString(), now, now, now.plusSeconds(3600), "pwd", "portal", "ACTIVE");
    }
}
