package com.example.iam.admin.security;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.common.trace.TraceId;
import com.example.iam.common.web.ApiErrorResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.core.Ordered;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

public class AdminAuthenticationFilter extends OncePerRequestFilter implements Ordered {

    private final AdminAuthenticationService authenticationService;
    private final ObjectMapper objectMapper;

    public AdminAuthenticationFilter(AdminAuthenticationService authenticationService, ObjectMapper objectMapper) {
        this.authenticationService = authenticationService;
        this.objectMapper = objectMapper;
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 25;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path == null || !path.startsWith("/api/admin/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            AdminPrincipal principal = authenticationService.authenticate(request);
            AdminPrincipalHolder.set(request, principal);
        } catch (IamException ex) {
            writeError(response, ex);
            return;
        }
        filterChain.doFilter(request, response);
    }

    private void writeError(HttpServletResponse response, IamException ex) throws IOException {
        IamErrorCode code = ex.getErrorCode();
        response.setStatus(code.getHttpStatus());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(
                response.getWriter(), ApiErrorResponse.of(TraceId.currentOrNew(), code.getCode(), ex.getMessage()));
    }
}
