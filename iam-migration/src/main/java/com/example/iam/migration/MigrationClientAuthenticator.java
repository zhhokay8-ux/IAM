package com.example.iam.migration;

public interface MigrationClientAuthenticator {

    void authenticateConfidential(String clientId, String clientSecret);
}
