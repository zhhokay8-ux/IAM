package com.example.iam.audit.repository;

import com.example.iam.audit.entity.IamAuditLogEntity;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface IamAuditLogRepository
        extends JpaRepository<IamAuditLogEntity, UUID>, JpaSpecificationExecutor<IamAuditLogEntity> {
    List<IamAuditLogEntity> findByTraceId(String traceId);
    List<IamAuditLogEntity> findBySubjectId(UUID subjectId);
    List<IamAuditLogEntity> findByClientId(UUID clientId);
    List<IamAuditLogEntity> findByCreatedAtBetween(Instant start, Instant end);
    Page<IamAuditLogEntity> findByOperatorNameIsNotNull(Pageable pageable);

    @Query(
            value =
                    "SELECT TO_CHAR(TRUNC(created_at), 'YYYY-MM-DD') AS d, event_type, result, COUNT(*) AS cnt "
                            + "FROM iam_audit_log WHERE created_at >= :fromTime AND created_at < :toTime "
                            + "GROUP BY TRUNC(created_at), event_type, result",
            nativeQuery = true)
    List<Object[]> aggregateByDay(@Param("fromTime") Instant fromTime, @Param("toTime") Instant toTime);
}
