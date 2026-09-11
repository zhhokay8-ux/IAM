package com.example.iam.clientregistry.entity;

import java.time.Instant;
import java.util.UUID;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * 客户端资源授权关系实体。
 */
@Entity
@Table(
        name = "iam_cli_res_perm",
        uniqueConstraints = @UniqueConstraint(
                name = "uk_cli_res_perm",
                columnNames = {"client_id", "resource_id", "scope_id", "grant_type"}
        ),
        indexes = {
                @Index(name = "idx_perm_client", columnList = "client_id"),
                @Index(name = "idx_perm_resource", columnList = "resource_id"),
                @Index(name = "idx_perm_scope", columnList = "scope_id")
        }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class IamClientResourcePermissionEntity {
    /**
     * 授权关系主键。
     */
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /**
     * 客户端 ID。
     */
    @Column(name = "client_id", nullable = false)
    private UUID clientId;

    /**
     * 资源服务器 ID。
     */
    @Column(name = "resource_id", nullable = false)
    private UUID resourceId;

    /**
     * 作用域 ID。
     */
    @Column(name = "scope_id", nullable = false)
    private UUID scopeId;

    /**
     * 授权类型。
     */
    @Column(name = "grant_type", nullable = false, length = 64)
    private String grantType;

    /**
     * 授权状态。
     */
    @Column(name = "status", nullable = false, length = 32)
    private String status;

    /**
     * 创建时间。
     */
    @Column(name = "created_at", nullable = false)
    private Instant createdAt;
}
