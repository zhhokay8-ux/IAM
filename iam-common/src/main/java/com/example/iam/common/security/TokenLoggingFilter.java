package com.example.iam.common.security;

import com.example.iam.common.error.IamErrorCode;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.web.filter.OncePerRequestFilter;

public class TokenLoggingFilter extends OncePerRequestFilter implements Ordered {

    private static final Logger log = LoggerFactory.getLogger(TokenLoggingFilter.class);

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 40;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authorization != null) {
            MDC.put("authorization", SensitiveDataMasker.mask(authorization));
        }
        if (log.isDebugEnabled()) {
            log.debug(
                    "request method={} path={} query={}",
                    request.getMethod(),
                    request.getRequestURI(),
                    SensitiveDataMasker.mask(request.getQueryString()));
        }
        if (request.getQueryString() != null && request.getQueryString().toLowerCase().contains("access_token")) {
            log.warn("rejected request with access_token in query string path={}", request.getRequestURI());
            response.setStatus(IamErrorCode.TOKEN_IN_URL.getHttpStatus());
            response.setContentType("application/json");
            response.getWriter()
                    .write("{\"code\":\""
                            + IamErrorCode.TOKEN_IN_URL.getCode()
                            + "\",\"message\":\""
                            + IamErrorCode.TOKEN_IN_URL.getMessage()
                            + "\"}");
            return;
        }
        try {
            filterChain.doFilter(request, response);
        } finally {
            MDC.remove("authorization");
        }
    }
}
