package com.example.iam.audit;

import com.example.iam.audit.entity.IamAuditLogEntity;
import com.example.iam.audit.repository.IamAuditLogRepository;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.common.trace.TraceId;
import jakarta.persistence.criteria.Predicate;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
public class IamAuditService {

    private final IamAuditLogRepository repository;

    public IamAuditService(IamAuditLogRepository repository) {
        this.repository = repository;
    }

    public void record(
            AuditEvent event,
            String subjectId,
            String clientId,
            String resourceId,
            String result,
            String failureReason,
            String detail) {
        String mergedDetail = detail;
        if (clientId != null && !clientId.isBlank() && parseUuid(clientId) == null) {
            mergedDetail = mergedDetail == null || mergedDetail.isBlank()
                    ? "client_id=" + clientId
                    : mergedDetail + "; client_id=" + clientId;
        }
        repository.save(IamAuditLogEntity.builder()
                .traceId(TraceId.currentOrNew())
                .eventType(event.name())
                .subjectId(parseUuid(subjectId))
                .clientId(parseUuid(clientId))
                .resourceId(parseUuid(resourceId))
                .result(result == null ? "UNKNOWN" : result)
                .failureReason(trim(sanitize(failureReason), 1024))
                .detail(trim(sanitize(mergedDetail), 4000))
                .createdAt(Instant.now())
                .build());
    }

    public void success(AuditEvent event, String subjectId, String clientId, String detail) {
        record(event, subjectId, clientId, null, "SUCCESS", null, detail);
    }

    public void failure(AuditEvent event, String subjectId, String clientId, String reason) {
        record(event, subjectId, clientId, null, "FAILURE", reason, null);
    }

    public void recordAdmin(
            AuditEvent event,
            String operatorSubject,
            String operatorUsername,
            String tenantId,
            String resourceType,
            String resourceId,
            String sourceIp,
            String userAgent,
            boolean success,
            String detail) {
        String safeDetail = sanitize(detail);
        IamAuditLogEntity entity = IamAuditLogEntity.builder()
                .traceId(TraceId.currentOrNew())
                .eventType(event.name())
                .subjectId(parseUuid(operatorSubject))
                .resourceId(parseUuid(resourceId))
                .sourceIp(trim(sourceIp, 64))
                .userAgent(trim(userAgent, 512))
                .result(success ? "SUCCESS" : "FAILURE")
                .failureReason(success ? null : trim(safeDetail, 1024))
                .detail(trim(safeDetail, 4000))
                .operatorName(trim(operatorUsername, 128))
                .tenantId(trim(tenantId, 128))
                .resourceType(trim(resourceType, 64))
                .createdAt(Instant.now())
                .build();
        repository.save(entity);
    }

    public Page<IamAuditLogView> search(IamAuditQuery query, Pageable pageable) {
        IamAuditQuery safe = query == null
                ? new IamAuditQuery(null, null, null, null, null, null, null, null, null, null, null)
                : query;
        if (safe.from() != null && safe.to() != null && safe.from().isAfter(safe.to())) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "from must be before to");
        }
        return repository.findAll(specification(safe), pageable).map(this::toView);
    }

    public List<IamAuditTrendRow> trend(Instant from, Instant to) {
        if (from == null || to == null || from.isAfter(to)) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "from must be before to");
        }
        List<Object[]> raw = repository.aggregateByDay(from, to);
        if (raw == null || raw.isEmpty()) {
            return groupByDayUtc(repository.findByCreatedAtBetween(from, to));
        }
        return mapNative(raw);
    }

    public Page<IamAuditLogView> recentAdminOperations(Pageable pageable) {
        return repository.findByOperatorNameIsNotNull(pageable).map(this::toView);
    }

    static List<IamAuditTrendRow> groupByDayUtc(List<IamAuditLogEntity> rows) {
        if (rows == null || rows.isEmpty()) {
            return List.of();
        }
        Map<String, Long> counts = new LinkedHashMap<>();
        for (IamAuditLogEntity row : rows) {
            if (row.getCreatedAt() == null || row.getEventType() == null) {
                continue;
            }
            String day = LocalDate.ofInstant(row.getCreatedAt(), ZoneOffset.UTC).toString();
            String result = row.getResult() == null ? "UNKNOWN" : row.getResult();
            String key = day + "\0" + row.getEventType() + "\0" + result;
            counts.merge(key, 1L, Long::sum);
        }
        List<IamAuditTrendRow> out = new ArrayList<>();
        for (Map.Entry<String, Long> entry : counts.entrySet()) {
            String[] parts = entry.getKey().split("\0", 3);
            out.add(new IamAuditTrendRow(parts[0], parts[1], parts[2], entry.getValue()));
        }
        out.sort(Comparator.comparing(IamAuditTrendRow::day)
                .thenComparing(IamAuditTrendRow::eventType)
                .thenComparing(IamAuditTrendRow::result));
        return out;
    }

    static List<IamAuditTrendRow> mapNative(List<Object[]> raw) {
        List<IamAuditTrendRow> out = new ArrayList<>();
        for (Object[] row : raw) {
            if (row == null || row.length < 4) {
                continue;
            }
            out.add(new IamAuditTrendRow(toDay(row[0]), String.valueOf(row[1]), String.valueOf(row[2]), toCount(row[3])));
        }
        out.sort(Comparator.comparing(IamAuditTrendRow::day)
                .thenComparing(IamAuditTrendRow::eventType)
                .thenComparing(IamAuditTrendRow::result));
        return out;
    }

    private static String toDay(Object value) {
        if (value == null) {
            return "";
        }
        if (value instanceof Timestamp timestamp) {
            return LocalDate.ofInstant(timestamp.toInstant(), ZoneOffset.UTC).toString();
        }
        if (value instanceof java.sql.Date date) {
            return date.toLocalDate().toString();
        }
        String text = String.valueOf(value);
        return text.length() >= 10 ? text.substring(0, 10) : text;
    }

    private static long toCount(Object value) {
        if (value instanceof Number number) {
            return number.longValue();
        }
        return Long.parseLong(String.valueOf(value));
    }

    public IamAuditLogView get(UUID id) {
        if (id == null) {
            throw new IamException(IamErrorCode.NOT_FOUND, "audit log not found");
        }
        return repository
                .findById(id)
                .map(this::toView)
                .orElseThrow(() -> new IamException(IamErrorCode.NOT_FOUND, "audit log not found"));
    }

    private IamAuditLogView toView(IamAuditLogEntity entity) {
        String result = entity.getResult();
        return new IamAuditLogView(
                entity.getId(),
                entity.getTraceId(),
                entity.getEventType(),
                entity.getSubjectId(),
                entity.getClientId(),
                entity.getResourceId(),
                entity.getResourceType(),
                entity.getSourceIp(),
                entity.getUserAgent(),
                result,
                "SUCCESS".equals(result),
                sanitize(entity.getFailureReason()),
                sanitize(entity.getDetail()),
                entity.getOperatorName(),
                entity.getTenantId(),
                entity.getCreatedAt());
    }

    private static Specification<IamAuditLogEntity> specification(IamAuditQuery query) {
        return (root, criteriaQuery, cb) -> {
            List<Predicate> predicates = new ArrayList<>();
            if (query.from() != null) {
                predicates.add(cb.greaterThanOrEqualTo(root.get("createdAt"), query.from()));
            }
            if (query.to() != null) {
                predicates.add(cb.lessThanOrEqualTo(root.get("createdAt"), query.to()));
            }
            if (StringUtils.hasText(query.operator())) {
                predicates.add(cb.equal(root.get("operatorName"), query.operator()));
            }
            if (query.subjectId() != null) {
                predicates.add(cb.equal(root.get("subjectId"), query.subjectId()));
            }
            if (StringUtils.hasText(query.tenantId())) {
                predicates.add(cb.equal(root.get("tenantId"), query.tenantId()));
            }
            if (StringUtils.hasText(query.eventType())) {
                predicates.add(cb.equal(root.get("eventType"), query.eventType()));
            }
            if (StringUtils.hasText(query.resourceType())) {
                predicates.add(cb.equal(root.get("resourceType"), query.resourceType()));
            }
            if (query.resourceId() != null) {
                predicates.add(cb.equal(root.get("resourceId"), query.resourceId()));
            }
            if (query.success() != null) {
                predicates.add(cb.equal(root.get("result"), query.success() ? "SUCCESS" : "FAILURE"));
            }
            if (StringUtils.hasText(query.traceId())) {
                predicates.add(cb.equal(root.get("traceId"), query.traceId()));
            }
            if (StringUtils.hasText(query.sourceIp())) {
                predicates.add(cb.equal(root.get("sourceIp"), query.sourceIp()));
            }
            return cb.and(predicates.toArray(Predicate[]::new));
        };
    }

    static String sanitize(String detail) {
        if (detail == null || detail.isBlank()) {
            return null;
        }
        String redacted = detail;
        String[] secrets = {
            "client_secret",
            "access_token",
            "refresh_token",
            "private_key",
            "authorization_code",
            "code_verifier",
            "cookie",
            "token"
        };
        for (String secret : secrets) {
            redacted = redacted.replaceAll("(?i)" + secret + "\\s*[=:]\\s*[^\\s;]+", secret + "=***");
        }
        return redacted;
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

    private static String trim(String value, int max) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.length() <= max ? value : value.substring(0, max);
    }
}
