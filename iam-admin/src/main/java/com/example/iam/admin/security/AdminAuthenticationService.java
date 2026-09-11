package com.example.iam.admin.security;

import com.example.iam.admin.config.IamAdminProperties;
import com.example.iam.admin.rbac.AdminRbacService;
import com.example.iam.audit.AuditEvent;
import com.example.iam.audit.IamAuditService;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.session.IamSession;
import com.example.iam.session.IamSessionService;
import com.example.iam.token.signing.JwtSigner;
import com.example.iam.user.context.UserContext;
import com.example.iam.user.service.IamUserService;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
public class AdminAuthenticationService {

    public static final String LEGACY_HEADER = "X-IAM-Admin-Token";
    public static final UUID LEGACY_SUBJECT = UUID.fromString("a1000000-0000-4000-8000-0000000000ff");
    public static final String LEGACY_USERNAME = "legacy-admin";
    public static final String LEGACY_TENANT = "legacy";

    private static final Logger log = LoggerFactory.getLogger(AdminAuthenticationService.class);

    private final IamAdminProperties properties;
    private final IamSessionService sessionService;
    private final JwtSigner jwtSigner;
    private final IamUserService userService;
    private final AdminRbacService rbacService;
    private final IamAuditService auditService;

    public AdminAuthenticationService(
            IamAdminProperties properties,
            IamSessionService sessionService,
            JwtSigner jwtSigner,
            IamUserService userService,
            AdminRbacService rbacService,
            IamAuditService auditService) {
        this.properties = properties;
        this.sessionService = sessionService;
        this.jwtSigner = jwtSigner;
        this.userService = userService;
        this.rbacService = rbacService;
        this.auditService = auditService;
    }

    public AdminPrincipal authenticate(HttpServletRequest request) {
        Optional<String> cookieSid = readCookieSid(request);
        if (cookieSid.isPresent()) {
            return authenticateCookie(request, cookieSid.get());
        }
        Optional<String> bearer = readBearer(request);
        if (bearer.isPresent()) {
            return authenticateBearer(request, bearer.get());
        }
        if (legacyEnabled()) {
            return authenticateLegacy(request);
        }
        auditFailure(request, null, null, null, "unauthenticated");
        throw new IamException(IamErrorCode.UNAUTHORIZED, "Admin authentication required");
    }

    private AdminPrincipal authenticateCookie(HttpServletRequest request, String sid) {
        IamSession session = sessionService
                .find(sid)
                .filter(s -> IamSession.STATUS_ACTIVE.equals(s.status()))
                .orElseThrow(() -> {
                    auditFailure(request, null, null, null, "invalid_session");
                    return new IamException(IamErrorCode.UNAUTHORIZED, "Admin session is invalid");
                });
        return loadUserPrincipal(request, session.subjectId(), AdminPrincipal.AuthMethod.COOKIE);
    }

    private AdminPrincipal authenticateBearer(HttpServletRequest request, String token) {
        SignedJWT jwt;
        try {
            jwt = jwtSigner.verify(token);
        } catch (IamException ex) {
            auditFailure(request, null, null, null, "invalid_jwt");
            throw new IamException(IamErrorCode.UNAUTHORIZED, "Admin bearer token is invalid");
        } catch (Exception ex) {
            auditFailure(request, null, null, null, "invalid_jwt");
            throw new IamException(IamErrorCode.UNAUTHORIZED, "Admin bearer token is invalid");
        }
        String sub;
        try {
            sub = jwt.getJWTClaimsSet().getSubject();
        } catch (java.text.ParseException ex) {
            auditFailure(request, null, null, null, "invalid_jwt");
            throw new IamException(IamErrorCode.UNAUTHORIZED, "Admin bearer token is invalid");
        }
        return loadUserPrincipal(request, sub, AdminPrincipal.AuthMethod.BEARER);
    }

    private AdminPrincipal authenticateLegacy(HttpServletRequest request) {
        String expected = properties.getAccessToken();
        if (!StringUtils.hasText(expected)) {
            auditFailure(request, LEGACY_USERNAME, LEGACY_TENANT, LEGACY_SUBJECT.toString(), "legacy_token_unconfigured");
            throw new IamException(IamErrorCode.UNAUTHORIZED, "Admin authentication required");
        }
        String provided = request.getHeader(LEGACY_HEADER);
        byte[] expectedBytes = expected.getBytes(StandardCharsets.UTF_8);
        byte[] actualBytes = provided == null ? new byte[0] : provided.getBytes(StandardCharsets.UTF_8);
        if (!MessageDigest.isEqual(expectedBytes, actualBytes)) {
            auditFailure(request, LEGACY_USERNAME, LEGACY_TENANT, null, "legacy_token_mismatch");
            throw new IamException(IamErrorCode.UNAUTHORIZED, "Admin authentication required");
        }
        log.warn("Legacy X-IAM-Admin-Token accepted for /api/admin; migrate to SSO cookie or Bearer JWT");
        AdminRbacService.AdminAccess access = rbacService.loadFullAdminAccess();
        AdminPrincipal principal = new AdminPrincipal(
                LEGACY_SUBJECT,
                LEGACY_USERNAME,
                LEGACY_TENANT,
                access.roles(),
                access.permissions(),
                AdminPrincipal.AuthMethod.LEGACY);
        auditService.recordAdmin(
                AuditEvent.ADMIN_LEGACY_AUTH,
                principal.subjectId().toString(),
                principal.username(),
                principal.tenantId(),
                "admin-api",
                request.getRequestURI(),
                clientIp(request),
                request.getHeader(HttpHeaders.USER_AGENT),
                true,
                "legacy_token_auth");
        return principal;
    }

    private AdminPrincipal loadUserPrincipal(HttpServletRequest request, String subject, AdminPrincipal.AuthMethod method) {
        UUID subjectId;
        try {
            subjectId = UUID.fromString(subject);
        } catch (RuntimeException ex) {
            auditFailure(request, null, null, subject, "invalid_subject");
            throw new IamException(IamErrorCode.UNAUTHORIZED, "Admin authentication required");
        }
        UserContext user;
        try {
            user = userService.requireActiveForToken(subjectId);
        } catch (IamException ex) {
            auditFailure(request, null, null, subjectId.toString(), "user_not_active");
            throw new IamException(IamErrorCode.UNAUTHORIZED, "Admin authentication required");
        }
        AdminRbacService.AdminAccess access = rbacService.loadBySubjectId(subjectId);
        if (access.isEmpty()) {
            auditService.recordAdmin(
                    AuditEvent.ADMIN_FORBIDDEN,
                    subjectId.toString(),
                    user.username(),
                    user.tenantId(),
                    "admin-api",
                    request.getRequestURI(),
                    clientIp(request),
                    request.getHeader(HttpHeaders.USER_AGENT),
                    false,
                    "admin_role_required");
            throw new IamException(IamErrorCode.ADMIN_ROLE_REQUIRED, "Admin role required");
        }
        return new AdminPrincipal(
                subjectId, user.username(), user.tenantId(), access.roles(), access.permissions(), method);
    }

    private boolean legacyEnabled() {
        return properties.getLegacyToken() != null && properties.getLegacyToken().isEnabled();
    }

    private Optional<String> readCookieSid(HttpServletRequest request) {
        if (request.getCookies() == null) {
            return Optional.empty();
        }
        String name = properties.getCookieName();
        if (!StringUtils.hasText(name)) {
            name = "IAM_SSO_SESSION";
        }
        for (Cookie cookie : request.getCookies()) {
            if (name.equals(cookie.getName()) && StringUtils.hasText(cookie.getValue())) {
                return Optional.of(cookie.getValue());
            }
        }
        return Optional.empty();
    }

    private static Optional<String> readBearer(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header == null || !header.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return Optional.empty();
        }
        String token = header.substring(7).trim();
        return StringUtils.hasText(token) ? Optional.of(token) : Optional.empty();
    }

    private void auditFailure(
            HttpServletRequest request, String username, String tenant, String subject, String reason) {
        auditService.recordAdmin(
                AuditEvent.ADMIN_AUTH_FAILURE,
                subject,
                username,
                tenant,
                "admin-api",
                request.getRequestURI(),
                clientIp(request),
                request.getHeader(HttpHeaders.USER_AGENT),
                false,
                reason);
    }

    public static String clientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (StringUtils.hasText(forwarded)) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
