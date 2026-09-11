package com.example.iam.common.security;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import java.util.Collection;

public class CorsOriginValidator {

    public String requireAllowed(String origin, Collection<String> allowedOrigins) {
        if (origin == null || origin.isBlank()) {
            throw new IamException(IamErrorCode.INVALID_ORIGIN, "origin is required");
        }
        if ("*".equals(origin.trim()) || origin.contains("*")) {
            throw new IamException(IamErrorCode.INVALID_ORIGIN, "wildcard origin is not allowed");
        }
        if (allowedOrigins == null || allowedOrigins.stream().noneMatch(origin::equals)) {
            throw new IamException(IamErrorCode.INVALID_ORIGIN, "origin is not in the allowlist");
        }
        return origin;
    }

    public boolean allowed(String origin, Collection<String> allowedOrigins) {
        if (origin == null || origin.isBlank() || origin.contains("*")) {
            return false;
        }
        return allowedOrigins != null && allowedOrigins.contains(origin);
    }

    public void rejectWildcardAllowOrigin(String allowOrigin, boolean allowCredentials) {
        if ("*".equals(allowOrigin) && allowCredentials) {
            throw new IamException(
                    IamErrorCode.INVALID_ORIGIN, "Access-Control-Allow-Origin * cannot be combined with credentials");
        }
        if ("*".equals(allowOrigin)) {
            throw new IamException(IamErrorCode.INVALID_ORIGIN, "Access-Control-Allow-Origin * is not allowed");
        }
    }
}
