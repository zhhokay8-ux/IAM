package com.example.iam.clientregistry.domain;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import java.util.Locale;

public enum GrantType {
    AUTHORIZATION_CODE,
    TOKEN_EXCHANGE,
    CLIENT_CREDENTIALS;

    public static GrantType from(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new IamException(IamErrorCode.INVALID_GRANT_TYPE, "grant_type is required");
        }
        String value = raw.trim();
        String compact = value.toUpperCase(Locale.ROOT).replace('-', '_');
        if ("AUTHORIZATION_CODE".equals(compact) || "AUTHORIZATION_CODE".equals(value.toUpperCase(Locale.ROOT))) {
            return AUTHORIZATION_CODE;
        }
        if ("CLIENT_CREDENTIALS".equals(compact)) {
            return CLIENT_CREDENTIALS;
        }
        if ("TOKEN_EXCHANGE".equals(compact)
                || "URN:IETF:PARAMS:OAUTH:GRANT-TYPE:TOKEN-EXCHANGE".equals(value.toUpperCase(Locale.ROOT))) {
            return TOKEN_EXCHANGE;
        }
        throw new IamException(IamErrorCode.INVALID_GRANT_TYPE, "unsupported grant_type: " + raw);
    }
}
