package com.example.iam.resourceserver.security;

import com.example.iam.resourceserver.jwt.ValidatedAccessToken;
import com.example.iam.user.context.UserContext;
import com.example.iam.user.context.UserContextHolder;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

public class UserContextAuthenticationFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication instanceof IamJwtAuthenticationToken jwtAuth) {
                ValidatedAccessToken token = jwtAuth.accessToken();
                UserContextHolder.set(new UserContext(
                        token.subject(),
                        null,
                        null,
                        null,
                        token.tenantId(),
                        token.orgId(),
                        "ACTIVE"));
            }
            filterChain.doFilter(request, response);
        } finally {
            UserContextHolder.clear();
        }
    }
}
