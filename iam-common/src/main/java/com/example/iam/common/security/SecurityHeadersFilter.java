package com.example.iam.common.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import org.springframework.core.Ordered;
import org.springframework.web.filter.OncePerRequestFilter;

public class SecurityHeadersFilter extends OncePerRequestFilter implements Ordered {

    public static final String CSP_NONE = "default-src 'self'; frame-ancestors 'none'";

    private final List<String> embedParentOrigins;

    public SecurityHeadersFilter(List<String> embedParentOrigins) {
        this.embedParentOrigins = embedParentOrigins == null ? List.of() : List.copyOf(embedParentOrigins);
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 5;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
        if (isEmbed(request) && !embedParentOrigins.isEmpty()) {
            response.setHeader("Content-Security-Policy", "frame-ancestors " + String.join(" ", embedParentOrigins));
        } else {
            response.setHeader("X-Frame-Options", "DENY");
            response.setHeader("Content-Security-Policy", CSP_NONE);
        }
        filterChain.doFilter(request, response);
    }

    private static boolean isEmbed(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path != null && (path.contains("/embed") || path.endsWith("iam-embed.js"));
    }
}
