package com.example.iam.audit.entity;

import java.time.Instant;
import java.util.UUID;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * 认证与授权审计日志实体。
 */
@Entity
@Table(
        name = "iam_audit_log",
        indexes = {
                @Index(name = "idx_iam_audit_trace", columnList = "trace_id"),
                @Index(name = "idx_iam_audit_event", columnList = "event_type"),
                @Index(name = "idx_iam_audit_subject", columnList = "subject_id"),
                @Index(name = "idx_iam_audit_client", columnList = "client_id"),
                @Index(name = "idx_iam_audit_resource", columnList = "resource_id"),
                @Index(name = "idx_iam_audit_result", columnList = "result"),
                @Index(name = "idx_iam_audit_created_at", columnList = "created_at")
        }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class IamAuditLogEntity {
    /**
     * 审计日志主键。
     */
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /**
     * 链路追踪 ID。
     */
    @Column(name = "trace_id", nullable = false, length = 64)
    private String traceId;

    /**
     * 审计事件类型。
     */
    @Column(name = "event_type", nullable = false, length = 128)
    private String eventType;

    /**
     * 统一用户 ID。
     */
    @Column(name = "subject_id")
    private UUID subjectId;

    /**
     * 客户端 ID。
     */
    @Column(name = "client_id")
    private UUID clientId;

    /**
     * 资源服务器 ID。
     */
    @Column(name = "resource_id")
    private UUID resourceId;

    /**
     * 来源 IP。
     */
    @Column(name = "source_ip", length = 64)
    private String sourceIp;

    /**
     * 客户端 User-Agent。
     */
    @Column(name = "user_agent", length = 512)
    private String userAgent;

    /**
     * 处理结果。
     */
    @Column(name = "result", nullable = false, length = 32)
    private String result;

    /**
     * 失败原因。
     */
    @Column(name = "failure_reason", length = 1024)
    private String failureReason;

    /**
     * Extra structured audit fields (for example token-exchange original_sub).
     */
    @Column(name = "detail", length = 4000)
    private String detail;

    @Column(name = "operator_name", length = 128)
    private String operatorName;

    @Column(name = "tenant_id", length = 128)
    private String tenantId;

    @Column(name = "res_type", length = 64)
    private String resourceType;

    /**
     * 创建时间。
     */
    @Column(name = "created_at", nullable = false)
    private Instant createdAt;
}
