package com.example.iam.resourceserver.security;

import com.example.iam.resourceserver.jwt.RoleValidator;
import com.example.iam.resourceserver.jwt.ScopeValidator;
import com.example.iam.resourceserver.jwt.ValidatedAccessToken;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

public class RequireScopeRoleInterceptor implements HandlerInterceptor {

    private final ScopeValidator scopeValidator;
    private final RoleValidator roleValidator;

    public RequireScopeRoleInterceptor(ScopeValidator scopeValidator, RoleValidator roleValidator) {
        this.scopeValidator = scopeValidator;
        this.roleValidator = roleValidator;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        if (!(handler instanceof HandlerMethod method)) {
            return true;
        }
        RequireScope requireScope = method.getMethodAnnotation(RequireScope.class);
        if (requireScope == null) {
            requireScope = method.getBeanType().getAnnotation(RequireScope.class);
        }
        RequireRole requireRole = method.getMethodAnnotation(RequireRole.class);
        if (requireRole == null) {
            requireRole = method.getBeanType().getAnnotation(RequireRole.class);
        }
        if (requireScope == null && requireRole == null) {
            return true;
        }
        ValidatedAccessToken token = currentToken();
        if (requireScope != null) {
            scopeValidator.validate(token.scopes(), requireScope.value());
        }
        if (requireRole != null) {
            roleValidator.validate(token.roles(), requireRole.value());
        }
        return true;
    }

    private static ValidatedAccessToken currentToken() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof IamJwtAuthenticationToken jwtAuth) {
            return jwtAuth.accessToken();
        }
        throw new com.example.iam.common.error.IamException(
                com.example.iam.common.error.IamErrorCode.UNAUTHORIZED, "authentication is required");
    }
}
