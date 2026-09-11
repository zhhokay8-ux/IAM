package com.example.iam.audit;

import java.time.Instant;
import java.util.UUID;

public record IamAuditLogView(
        UUID id,
        String traceId,
        String eventType,
        UUID subjectId,
        UUID clientId,
        UUID resourceId,
        String resourceType,
        String sourceIp,
        String userAgent,
        String result,
        boolean success,
        String failureReason,
        String detail,
        String operatorName,
        String tenantId,
        Instant createdAt) {}
