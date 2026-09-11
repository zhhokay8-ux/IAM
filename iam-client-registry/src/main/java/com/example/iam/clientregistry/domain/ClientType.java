package com.example.iam.clientregistry.domain;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import java.util.Locale;

public final class ClientType {

    public static final String CONFIDENTIAL = "confidential";
    public static final String PUBLIC = "public";

    private ClientType() {
    }

    public static String normalize(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new IamException(IamErrorCode.INVALID_CLIENT_TYPE, "client_type is required");
        }
        String normalized = raw.trim().toLowerCase(Locale.ROOT);
        if (!CONFIDENTIAL.equals(normalized) && !PUBLIC.equals(normalized)) {
            throw new IamException(IamErrorCode.INVALID_CLIENT_TYPE, "client_type must be confidential or public");
        }
        return normalized;
    }
}
