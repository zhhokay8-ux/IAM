package com.example.iam.authorizationserver.oidc.logout;

import com.example.iam.audit.AuditEvent;
import com.example.iam.audit.IamAuditService;
import com.example.iam.authorizationserver.sso.SsoCookieService;
import com.example.iam.session.IamSession;
import com.example.iam.session.IamSessionService;
import com.example.iam.token.oauth.RefreshTokenFamilyService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Locale;
import java.util.UUID;
import org.springframework.stereotype.Service;

@Service
public class LogoutServiceImpl implements LogoutService {

    static final String TYPE_LOCAL = "local";
    static final String TYPE_GLOBAL = "global";

    private final SsoCookieService cookieService;
    private final IamSessionService sessionService;
    private final RefreshTokenFamilyService refreshTokenFamilyService;
    private final BackChannelLogoutService backChannelLogoutService;
    private final IamAuditService auditService;

    public LogoutServiceImpl(
            SsoCookieService cookieService,
            IamSessionService sessionService,
            RefreshTokenFamilyService refreshTokenFamilyService,
            BackChannelLogoutService backChannelLogoutService,
            IamAuditService auditService) {
        this.cookieService = cookieService;
        this.sessionService = sessionService;
        this.refreshTokenFamilyService = refreshTokenFamilyService;
        this.backChannelLogoutService = backChannelLogoutService;
        this.auditService = auditService;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, String logoutType) {
        String sid = cookieService.readSid(request);
        IamSession session = null;
        if (sid != null) {
            try {
                session = sessionService.find(sid).orElse(null);
            } catch (RuntimeException ignored) {
                session = null;
            }
        }
        if (TYPE_LOCAL.equalsIgnoreCase(normalize(logoutType))) {
            localLogout(response);
            return;
        }
        globalLogout(session, response);
    }

    @Override
    public void localLogout(HttpServletResponse response) {
        cookieService.clear(response);
    }

    @Override
    public void globalLogout(IamSession session, HttpServletResponse response) {
        if (session != null) {
            sessionService.delete(session.sid());
            revokeRefreshTokens(session.subjectId());
            backChannelLogoutService.notifyClients(session.subjectId(), session.sid());
            auditService.success(AuditEvent.LOGOUT, session.subjectId(), session.clientId(), "type=global");
        }
        cookieService.clear(response);
    }

    private void revokeRefreshTokens(String subjectId) {
        if (subjectId == null || subjectId.isBlank()) {
            return;
        }
        try {
            refreshTokenFamilyService.revokeAllForSubject(UUID.fromString(subjectId));
        } catch (IllegalArgumentException ignored) {
            // subject is not a UUID; SSO session still deleted
        }
    }

    private static String normalize(String logoutType) {
        if (logoutType == null || logoutType.isBlank()) {
            return TYPE_GLOBAL;
        }
        return logoutType.trim().toLowerCase(Locale.ROOT);
    }
}
