package com.example.iam.migration;

import java.util.Locale;

public enum MigrationMode {
    LEGACY,
    IAM,
    DUAL;

    public static MigrationMode from(String raw) {
        if (raw == null || raw.isBlank()) {
            return DUAL;
        }
        return MigrationMode.valueOf(raw.trim().toUpperCase(Locale.ROOT));
    }
}
