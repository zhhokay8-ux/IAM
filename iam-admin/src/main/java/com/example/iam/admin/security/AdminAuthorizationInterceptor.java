package com.example.iam.admin.security;

import com.example.iam.audit.AuditEvent;
import com.example.iam.audit.IamAuditService;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

public class AdminAuthorizationInterceptor implements HandlerInterceptor {

    private final IamAuditService auditService;

    public AdminAuthorizationInterceptor(IamAuditService auditService) {
        this.auditService = auditService;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        if (!(handler instanceof HandlerMethod handlerMethod)) {
            return true;
        }
        RequireAdminPermission required = handlerMethod.getMethodAnnotation(RequireAdminPermission.class);
        if (required == null) {
            required = handlerMethod.getBeanType().getAnnotation(RequireAdminPermission.class);
        }
        if (required == null) {
            return true;
        }
        AdminPrincipal principal = AdminPrincipalHolder.get(request);
        if (principal == null) {
            throw new IamException(IamErrorCode.UNAUTHORIZED, "Admin authentication required");
        }
        if (!principal.hasPermission(required.value())) {
            auditService.recordAdmin(
                    AuditEvent.ADMIN_FORBIDDEN,
                    principal.subjectId() == null ? null : principal.subjectId().toString(),
                    principal.username(),
                    principal.tenantId(),
                    "admin-api",
                    request.getRequestURI(),
                    AdminAuthenticationService.clientIp(request),
                    request.getHeader(HttpHeaders.USER_AGENT),
                    false,
                    "missing_permission=" + required.value());
            throw new IamException(IamErrorCode.ADMIN_PERMISSION_DENIED, "Admin permission denied");
        }
        return true;
    }
}
