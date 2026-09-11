package com.example.iam.migration;

import com.example.iam.audit.entity.IamAuditLogEntity;
import com.example.iam.audit.repository.IamAuditLogRepository;
import com.example.iam.common.trace.TraceId;
import java.time.Instant;
import java.util.UUID;
import org.springframework.stereotype.Service;

@Service
public class MigrationAuditServiceImpl implements MigrationAuditService {

    private final IamAuditLogRepository repository;

    public MigrationAuditServiceImpl(IamAuditLogRepository repository) {
        this.repository = repository;
    }

    @Override
    public void record(String eventType, String subjectId, String clientId, String result, String failureReason) {
        repository.save(IamAuditLogEntity.builder()
                .traceId(TraceId.currentOrNew())
                .eventType(eventType)
                .subjectId(parseUuid(subjectId))
                .clientId(null)
                .result(result == null ? "UNKNOWN" : result)
                .failureReason(trim(clientId, failureReason))
                .createdAt(Instant.now())
                .build());
    }

    private static UUID parseUuid(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException ex) {
            return null;
        }
    }

    private static String trim(String clientId, String failureReason) {
        String prefix = clientId == null || clientId.isBlank() ? "" : "client_id=" + clientId + "; ";
        String reason = failureReason == null ? "" : failureReason;
        String combined = prefix + reason;
        return combined.isBlank() ? null : combined.substring(0, Math.min(1024, combined.length()));
    }
}
