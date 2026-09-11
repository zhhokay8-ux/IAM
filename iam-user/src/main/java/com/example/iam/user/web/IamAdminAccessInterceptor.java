package com.example.iam.user.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.springframework.http.HttpStatus;
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.HandlerInterceptor;

public class IamAdminAccessInterceptor implements HandlerInterceptor {

    public static final String HEADER = "X-IAM-Admin-Token";

    private final byte[] expectedToken;

    public IamAdminAccessInterceptor(String expectedToken) {
        this.expectedToken = StringUtils.hasText(expectedToken)
                ? expectedToken.getBytes(StandardCharsets.UTF_8)
                : new byte[0];
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        if (expectedToken.length == 0) {
            response.sendError(HttpStatus.FORBIDDEN.value(), "Admin API is disabled");
            return false;
        }
        String provided = request.getHeader(HEADER);
        byte[] actual = provided == null ? new byte[0] : provided.getBytes(StandardCharsets.UTF_8);
        if (!MessageDigest.isEqual(expectedToken, actual)) {
            response.sendError(HttpStatus.UNAUTHORIZED.value(), "Invalid admin token");
            return false;
        }
        return true;
    }
}
