package com.example.iam.clientregistry.validation;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import java.net.URI;
import java.util.Collection;
import java.util.Locale;
import org.springframework.stereotype.Component;

@Component
public class IamOriginValidator {

    public void validateOrigin(String requested, Collection<String> allowedOrigins) {
        validateSyntax(requested);
        if (allowedOrigins == null || allowedOrigins.stream().noneMatch(requested::equals)) {
            throw new IamException(IamErrorCode.INVALID_ORIGIN, "origin is not in the allowlist");
        }
    }

    public void validateSyntax(String origin) {
        if (origin == null || origin.isBlank()) {
            throw new IamException(IamErrorCode.INVALID_ORIGIN, "origin is required");
        }
        if ("*".equals(origin.trim()) || origin.contains("*")) {
            throw new IamException(IamErrorCode.INVALID_ORIGIN, "wildcard origin is not allowed");
        }
        URI uri;
        try {
            uri = URI.create(origin);
        } catch (IllegalArgumentException ex) {
            throw new IamException(IamErrorCode.INVALID_ORIGIN, "origin is not a valid URI");
        }
        if (uri.getScheme() == null || uri.getHost() == null || !uri.isAbsolute()) {
            throw new IamException(IamErrorCode.INVALID_ORIGIN, "origin must be an absolute URI");
        }
        String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
        if (!"https".equals(scheme) && !"http".equals(scheme)) {
            throw new IamException(IamErrorCode.INVALID_ORIGIN, "origin scheme is not allowed");
        }
        if (uri.getRawUserInfo() != null || origin.contains("@")) {
            throw new IamException(IamErrorCode.INVALID_ORIGIN, "origin must not contain userinfo");
        }
        if (uri.getPath() != null && !uri.getPath().isEmpty() && !"/".equals(uri.getPath())) {
            throw new IamException(IamErrorCode.INVALID_ORIGIN, "origin must not contain a path");
        }
        if (uri.getQuery() != null || uri.getFragment() != null) {
            throw new IamException(IamErrorCode.INVALID_ORIGIN, "origin must not contain query or fragment");
        }
    }
}
