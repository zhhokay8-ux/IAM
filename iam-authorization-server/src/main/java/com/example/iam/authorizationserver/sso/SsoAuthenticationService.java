package com.example.iam.authorizationserver.sso;

import com.example.iam.audit.AuditEvent;
import com.example.iam.audit.IamAuditService;
import com.example.iam.clientregistry.service.IamClientService;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.session.IamSession;
import com.example.iam.session.IamSessionService;
import com.example.iam.user.entity.IamUserEntity;
import com.example.iam.user.service.IamUserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Optional;
import org.springframework.stereotype.Service;

@Service
public class SsoAuthenticationService {

    private final IamUserService userService;
    private final IamClientService clientService;
    private final IamSessionService sessionService;
    private final SsoCookieService cookieService;
    private final IamAuditService auditService;

    public SsoAuthenticationService(
            IamUserService userService,
            IamClientService clientService,
            IamSessionService sessionService,
            SsoCookieService cookieService,
            IamAuditService auditService) {
        this.userService = userService;
        this.clientService = clientService;
        this.sessionService = sessionService;
        this.cookieService = cookieService;
        this.auditService = auditService;
    }

    public IamSession login(SsoLoginRequest request, HttpServletResponse response) {
        try {
            if (request == null) {
                throw new IamException(IamErrorCode.INVALID_ARGUMENT, "login request is required");
            }
            clientService.requireActiveClient(request.clientId());
            IamUserEntity user = userService.requireActiveByUsernameAndTenantId(request.username(), request.tenantId());
            IamSession session = sessionService.create(user.getSubjectId().toString(), request.clientId(), "pwd");
            cookieService.write(response, session, sessionService.ttl());
            auditService.success(AuditEvent.LOGIN_SUCCESS, user.getSubjectId().toString(), request.clientId(), null);
            return session;
        } catch (RuntimeException ex) {
            auditService.failure(
                    AuditEvent.LOGIN_FAILURE,
                    null,
                    request == null ? null : request.clientId(),
                    ex.getMessage());
            throw ex;
        }
    }

    public IamSession requireCurrent(HttpServletRequest request) {
        String sid = cookieService.readSid(request);
        if (sid == null) {
            throw new IamException(IamErrorCode.SESSION_NOT_FOUND, "SSO session not found");
        }
        return sessionService.touch(sid);
    }

    public Optional<IamSession> findCurrent(HttpServletRequest request) {
        String sid = cookieService.readSid(request);
        if (sid == null) {
            return Optional.empty();
        }
        return sessionService.find(sid);
    }

    public String subjectFromRequest(HttpServletRequest request) {
        return findCurrent(request).map(IamSession::subjectId).orElse(null);
    }
}
