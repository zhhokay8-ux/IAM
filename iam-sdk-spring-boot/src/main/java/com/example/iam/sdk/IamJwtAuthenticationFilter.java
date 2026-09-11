package com.example.iam.sdk;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.resourceserver.jwt.JwtTokenValidator;
import com.example.iam.resourceserver.jwt.ValidatedAccessToken;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

public class IamJwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenValidator jwtTokenValidator;
    private final String[] permitAll;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    public IamJwtAuthenticationFilter(JwtTokenValidator jwtTokenValidator, String[] permitAll) {
        this.jwtTokenValidator = jwtTokenValidator;
        this.permitAll = permitAll == null ? new String[0] : permitAll;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (HttpMethod.OPTIONS.matches(request.getMethod()) || permitted(request)) {
            filterChain.doFilter(request, response);
            return;
        }
        try {
            String header = request.getHeader(HttpHeaders.AUTHORIZATION);
            if (header == null || header.isBlank()) {
                throw new IamException(IamErrorCode.UNAUTHORIZED, "access token is required");
            }
            if (!header.regionMatches(true, 0, "Bearer ", 0, 7)) {
                throw new IamException(IamErrorCode.UNAUTHORIZED, "Authorization scheme must be Bearer");
            }
            ValidatedAccessToken token = jwtTokenValidator.validate(header.substring(7).trim());
            IamUserContextHolder.set(toContext(token));
            filterChain.doFilter(request, response);
        } catch (IamException ex) {
            int status = ex.getErrorCode().getHttpStatus();
            response.setStatus(status);
            response.setContentType("application/json");
            response.getWriter()
                    .write("{\"code\":\"" + ex.getErrorCode().getCode() + "\",\"message\":\"" + ex.getMessage() + "\"}");
        } finally {
            IamUserContextHolder.clear();
        }
    }

    private boolean permitted(HttpServletRequest request) {
        String path = request.getRequestURI();
        for (String pattern : permitAll) {
            if (pattern != null && !pattern.isBlank() && pathMatcher.match(pattern, path)) {
                return true;
            }
        }
        return false;
    }

    static IamUserContext toContext(ValidatedAccessToken token) {
        return new IamUserContext(
                token.subject(),
                null,
                token.tenantId(),
                token.orgId(),
                token.roles(),
                token.scopes(),
                token.clientId());
    }
}
