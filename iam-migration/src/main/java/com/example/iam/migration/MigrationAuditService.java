package com.example.iam.migration;

public interface MigrationAuditService {

    void record(String eventType, String subjectId, String clientId, String result, String failureReason);
}
