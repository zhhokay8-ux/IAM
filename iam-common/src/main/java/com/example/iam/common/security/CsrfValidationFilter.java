package com.example.iam.common.security;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Locale;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.web.filter.OncePerRequestFilter;

public class CsrfValidationFilter extends OncePerRequestFilter implements Ordered {

    private final CsrfTokenService csrfTokenService;
    private final CorsOriginValidator originValidator;
    private final CorsProperties corsProperties;
    private final String sessionCookieName;

    public CsrfValidationFilter(
            CsrfTokenService csrfTokenService,
            CorsOriginValidator originValidator,
            CorsProperties corsProperties,
            String sessionCookieName) {
        this.csrfTokenService = csrfTokenService;
        this.originValidator = originValidator;
        this.corsProperties = corsProperties;
        this.sessionCookieName = sessionCookieName;
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 20;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        csrfTokenService.ensure(request, response);
        if (requiresCsrf(request)) {
            try {
                validate(request);
            } catch (IamException ex) {
                response.setStatus(ex.getErrorCode().getHttpStatus());
                response.setContentType("application/json");
                response.getWriter()
                        .write("{\"code\":\"" + ex.getErrorCode().getCode() + "\",\"message\":\"" + ex.getMessage() + "\"}");
                return;
            }
        }
        filterChain.doFilter(request, response);
    }

    private void validate(HttpServletRequest request) {
        if (!csrfTokenService.matches(request)) {
            throw new IamException(IamErrorCode.CSRF_INVALID, "CSRF token is required");
        }
        String origin = request.getHeader(HttpHeaders.ORIGIN);
        String referer = request.getHeader(HttpHeaders.REFERER);
        if (origin != null && !origin.isBlank()) {
            originValidator.requireAllowed(origin, corsProperties.getAllowedOrigins());
        } else if (referer != null && !referer.isBlank()) {
            String refererOrigin = refererOrigin(referer);
            originValidator.requireAllowed(refererOrigin, corsProperties.getAllowedOrigins());
        } else {
            throw new IamException(IamErrorCode.CSRF_INVALID, "Origin or Referer is required for cookie authentication");
        }
    }

    private boolean requiresCsrf(HttpServletRequest request) {
        if (HttpMethod.GET.matches(request.getMethod())
                || HttpMethod.HEAD.matches(request.getMethod())
                || HttpMethod.OPTIONS.matches(request.getMethod())) {
            return false;
        }
        String path = request.getRequestURI();
        if (path != null
                && (path.startsWith("/oauth2/")
                        || path.startsWith("/.well-known/")
                        || path.equals("/oidc/backchannel-logout"))) {
            return false;
        }
        return hasSessionCookie(request);
    }

    private boolean hasSessionCookie(HttpServletRequest request) {
        if (request.getCookies() == null) {
            return false;
        }
        for (Cookie cookie : request.getCookies()) {
            if (sessionCookieName.equals(cookie.getName()) && cookie.getValue() != null && !cookie.getValue().isBlank()) {
                return true;
            }
        }
        return false;
    }

    private static String refererOrigin(String referer) {
        try {
            java.net.URI uri = java.net.URI.create(referer);
            if (uri.getScheme() == null || uri.getHost() == null) {
                return referer;
            }
            int port = uri.getPort();
            if (port > 0 && port != 80 && port != 443) {
                return uri.getScheme() + "://" + uri.getHost() + ":" + port;
            }
            return uri.getScheme() + "://" + uri.getHost();
        } catch (IllegalArgumentException ex) {
            return referer.toLowerCase(Locale.ROOT);
        }
    }
}
