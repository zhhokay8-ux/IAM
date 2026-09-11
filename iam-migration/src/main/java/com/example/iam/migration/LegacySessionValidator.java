package com.example.iam.migration;

public interface LegacySessionValidator {

    LegacyPrincipal requireValid(String legacySessionCookie);
}
