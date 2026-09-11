package com.example.iam.authorizationserver.admin.token;

import com.example.iam.admin.rbac.AdminPermissions;
import com.example.iam.admin.security.AdminAuthenticationService;
import com.example.iam.admin.security.AdminPrincipal;
import com.example.iam.admin.security.AdminPrincipalHolder;
import com.example.iam.admin.security.RequireAdminPermission;
import com.example.iam.audit.AuditEvent;
import com.example.iam.audit.IamAuditService;
import com.example.iam.authorizationserver.oauth.introspect.TokenIntrospectionResponse;
import com.example.iam.authorizationserver.oauth.introspect.TokenIntrospectionService;
import com.example.iam.authorizationserver.oauth.revoke.TokenRevocationService;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin/tokens")
public class AdminTokenOpsController {

    private static final Logger log = LoggerFactory.getLogger(AdminTokenOpsController.class);

    private final TokenIntrospectionService tokenIntrospectionService;
    private final TokenRevocationService tokenRevocationService;
    private final IamAuditService auditService;

    public AdminTokenOpsController(
            TokenIntrospectionService tokenIntrospectionService,
            TokenRevocationService tokenRevocationService,
            IamAuditService auditService) {
        this.tokenIntrospectionService = tokenIntrospectionService;
        this.tokenRevocationService = tokenRevocationService;
        this.auditService = auditService;
    }

    @PostMapping("/introspect")
    @RequireAdminPermission(AdminPermissions.TOKEN_READ)
    public AdminTokenIntrospectResponse introspect(@RequestBody AdminTokenIntrospectRequest request) {
        String token = request == null ? null : request.token();
        TokenIntrospectionResponse result = tokenIntrospectionService.introspect(token);
        log.info("admin_token_introspect active={}", result.active());
        return AdminTokenIntrospectResponse.from(result);
    }

    @PostMapping("/revoke")
    @RequireAdminPermission(AdminPermissions.TOKEN_REVOKE)
    public void revoke(@RequestBody AdminTokenRevokeRequest request, HttpServletRequest http) {
        String token = request == null ? null : request.token();
        String hint = request == null ? null : request.tokenTypeHint();
        boolean revoked = tokenRevocationService.revoke(token, hint);
        log.info("admin_token_revoke revoked={} hint={}", revoked, hint);
        if (revoked) {
            audit(http, AuditEvent.TOKEN_REVOKED, hint, "admin_revoke_presented_token; token_type_hint=" + hint);
        }
    }

    private void audit(HttpServletRequest request, AuditEvent event, String resourceId, String detail) {
        AdminPrincipal principal = AdminPrincipalHolder.get(request);
        auditService.recordAdmin(
                event,
                principal == null || principal.subjectId() == null ? null : principal.subjectId().toString(),
                principal == null ? null : principal.username(),
                principal == null ? null : principal.tenantId(),
                "token",
                resourceId,
                AdminAuthenticationService.clientIp(request),
                request.getHeader(HttpHeaders.USER_AGENT),
                true,
                detail);
    }
}
