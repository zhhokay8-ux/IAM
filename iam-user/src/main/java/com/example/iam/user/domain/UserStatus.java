package com.example.iam.user.domain;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import java.util.Locale;

public final class UserStatus {

    public static final String ACTIVE = "ACTIVE";
    public static final String INACTIVE = "INACTIVE";

    private UserStatus() {
    }

    public static String normalize(String raw) {
        if (raw == null || raw.isBlank()) {
            return ACTIVE;
        }
        String normalized = raw.trim().toUpperCase(Locale.ROOT);
        if (!ACTIVE.equals(normalized) && !INACTIVE.equals(normalized)) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "status must be ACTIVE or INACTIVE");
        }
        return normalized;
    }

    public static boolean isActive(String status) {
        return ACTIVE.equalsIgnoreCase(status);
    }
}
