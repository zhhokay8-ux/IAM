package com.example.iam.admin.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.iam.admin.config.IamAdminProperties;
import com.example.iam.admin.rbac.AdminPermissions;
import com.example.iam.admin.rbac.AdminRbacService;
import com.example.iam.admin.rbac.AdminRoles;
import com.example.iam.audit.AuditEvent;
import com.example.iam.audit.IamAuditService;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.session.IamSession;
import com.example.iam.session.IamSessionService;
import com.example.iam.token.signing.JwtSigner;
import com.example.iam.user.context.UserContext;
import com.example.iam.user.service.IamUserService;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.Cookie;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;

@ExtendWith(MockitoExtension.class)
class AdminAuthenticationServiceTest {

    @Mock
    private IamSessionService sessionService;

    @Mock
    private JwtSigner jwtSigner;

    @Mock
    private IamUserService userService;

    @Mock
    private AdminRbacService rbacService;

    @Mock
    private IamAuditService auditService;

    private IamAdminProperties properties;
    private AdminAuthenticationService service;

    @BeforeEach
    void setUp() {
        properties = new IamAdminProperties();
        properties.setAccessToken("legacy-secret");
        service = new AdminAuthenticationService(
                properties, sessionService, jwtSigner, userService, rbacService, auditService);
    }

    @Test
    void unauthenticatedIs401() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/admin/me");
        assertThatThrownBy(() -> service.authenticate(request))
                .isInstanceOf(IamException.class)
                .extracting(ex -> ((IamException) ex).getErrorCode())
                .isEqualTo(IamErrorCode.UNAUTHORIZED);
        verify(auditService).recordAdmin(
                eq(AuditEvent.ADMIN_AUTH_FAILURE),
                any(),
                any(),
                any(),
                anyString(),
                anyString(),
                any(),
                any(),
                eq(false),
                eq("unauthenticated"));
    }

    @Test
    void regularUserWithoutRoleIs403() {
        UUID subject = UUID.randomUUID();
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/admin/me");
        request.setCookies(new Cookie("IAM_SSO_SESSION", "sid-1"));
        when(sessionService.find("sid-1")).thenReturn(Optional.of(activeSession(subject)));
        when(userService.requireActiveForToken(subject)).thenReturn(user(subject, "alice"));
        when(rbacService.loadBySubjectId(subject)).thenReturn(AdminRbacService.AdminAccess.empty());

        assertThatThrownBy(() -> service.authenticate(request))
                .isInstanceOf(IamException.class)
                .extracting(ex -> ((IamException) ex).getErrorCode())
                .isEqualTo(IamErrorCode.ADMIN_ROLE_REQUIRED);
        verify(auditService).recordAdmin(
                eq(AuditEvent.ADMIN_FORBIDDEN),
                eq(subject.toString()),
                eq("alice"),
                eq("t1"),
                anyString(),
                anyString(),
                any(),
                any(),
                eq(false),
                eq("admin_role_required"));
    }

    @Test
    void cookieUserWithAdminRoleSucceeds() {
        UUID subject = UUID.randomUUID();
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/admin/me");
        request.setCookies(new Cookie("IAM_SSO_SESSION", "sid-1"));
        when(sessionService.find("sid-1")).thenReturn(Optional.of(activeSession(subject)));
        when(userService.requireActiveForToken(subject)).thenReturn(user(subject, "admin"));
        when(rbacService.loadBySubjectId(subject))
                .thenReturn(new AdminRbacService.AdminAccess(
                        Set.of(AdminRoles.IAM_ADMIN), Set.of(AdminPermissions.CLIENT_WRITE)));

        AdminPrincipal principal = service.authenticate(request);
        assertThat(principal.username()).isEqualTo("admin");
        assertThat(principal.authMethod()).isEqualTo(AdminPrincipal.AuthMethod.COOKIE);
        assertThat(principal.hasPermission(AdminPermissions.CLIENT_WRITE)).isTrue();
    }

    @Test
    void bearerJwtSucceeds() throws Exception {
        UUID subject = UUID.randomUUID();
        SignedJWT jwt = org.mockito.Mockito.mock(SignedJWT.class);
        when(jwt.getJWTClaimsSet())
                .thenReturn(new JWTClaimsSet.Builder()
                        .subject(subject.toString())
                        .expirationTime(Date.from(Instant.now().plusSeconds(60)))
                        .build());
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/admin/me");
        request.addHeader("Authorization", "Bearer token");
        when(jwtSigner.verify("token")).thenReturn(jwt);
        when(userService.requireActiveForToken(subject)).thenReturn(user(subject, "op"));
        when(rbacService.loadBySubjectId(subject))
                .thenReturn(new AdminRbacService.AdminAccess(
                        Set.of(AdminRoles.IAM_OPERATOR), Set.of(AdminPermissions.TOKEN_REVOKE)));

        AdminPrincipal principal = service.authenticate(request);
        assertThat(principal.authMethod()).isEqualTo(AdminPrincipal.AuthMethod.BEARER);
        assertThat(principal.hasRole(AdminRoles.IAM_OPERATOR)).isTrue();
    }

    @Test
    void legacyTokenDisabledByDefault() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/admin/me");
        request.addHeader(AdminAuthenticationService.LEGACY_HEADER, "legacy-secret");
        assertThatThrownBy(() -> service.authenticate(request))
                .extracting(ex -> ((IamException) ex).getErrorCode())
                .isEqualTo(IamErrorCode.UNAUTHORIZED);
        verify(rbacService, never()).loadFullAdminAccess();
    }

    @Test
    void legacyTokenWhenEnabledAuditsWithoutLoggingSecret() {
        properties.getLegacyToken().setEnabled(true);
        when(rbacService.loadFullAdminAccess())
                .thenReturn(new AdminRbacService.AdminAccess(
                        Set.of(AdminRoles.IAM_ADMIN), Set.of(AdminPermissions.CLIENT_WRITE)));
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/admin/me");
        request.addHeader(AdminAuthenticationService.LEGACY_HEADER, "legacy-secret");

        AdminPrincipal principal = service.authenticate(request);
        assertThat(principal.authMethod()).isEqualTo(AdminPrincipal.AuthMethod.LEGACY);
        verify(auditService).recordAdmin(
                eq(AuditEvent.ADMIN_LEGACY_AUTH),
                eq(AdminAuthenticationService.LEGACY_SUBJECT.toString()),
                eq(AdminAuthenticationService.LEGACY_USERNAME),
                eq(AdminAuthenticationService.LEGACY_TENANT),
                anyString(),
                anyString(),
                any(),
                any(),
                eq(true),
                eq("legacy_token_auth"));
    }

    private static IamSession activeSession(UUID subject) {
        Instant now = Instant.now();
        return new IamSession(
                "sid-1",
                subject.toString(),
                now,
                now,
                now.plusSeconds(3600),
                "pwd",
                "client",
                IamSession.STATUS_ACTIVE);
    }

    private static UserContext user(UUID subject, String username) {
        return new UserContext(subject.toString(), username, username, null, "t1", null, "ACTIVE");
    }
}
