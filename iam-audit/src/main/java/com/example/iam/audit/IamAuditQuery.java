package com.example.iam.audit;

import java.time.Instant;
import java.util.UUID;

public record IamAuditQuery(
        Instant from,
        Instant to,
        String operator,
        UUID subjectId,
        String tenantId,
        String eventType,
        String resourceType,
        UUID resourceId,
        Boolean success,
        String traceId,
        String sourceIp) {}
