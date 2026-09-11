package com.example.iam.admin.security;

import jakarta.servlet.http.HttpServletRequest;

public final class AdminPrincipalHolder {

    public static final String REQUEST_ATTRIBUTE = "IAM_ADMIN_PRINCIPAL";

    private AdminPrincipalHolder() {}

    public static void set(HttpServletRequest request, AdminPrincipal principal) {
        request.setAttribute(REQUEST_ATTRIBUTE, principal);
    }

    public static AdminPrincipal get(HttpServletRequest request) {
        Object value = request.getAttribute(REQUEST_ATTRIBUTE);
        return value instanceof AdminPrincipal principal ? principal : null;
    }
}
