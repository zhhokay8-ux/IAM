package com.example.iam.clientregistry.domain;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import java.util.Locale;

public final class RedirectUriType {

    public static final String LOGIN_CALLBACK = "LOGIN_CALLBACK";
    public static final String LOGOUT_CALLBACK = "LOGOUT_CALLBACK";

    private RedirectUriType() {
    }

    public static String normalize(String raw) {
        if (raw == null || raw.isBlank()) {
            return LOGIN_CALLBACK;
        }
        String normalized = raw.trim().toUpperCase(Locale.ROOT);
        if (!LOGIN_CALLBACK.equals(normalized) && !LOGOUT_CALLBACK.equals(normalized)) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "uri_type must be LOGIN_CALLBACK or LOGOUT_CALLBACK");
        }
        return normalized;
    }
}
