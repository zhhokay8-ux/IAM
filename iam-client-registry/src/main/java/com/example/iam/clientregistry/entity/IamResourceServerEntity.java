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
 * 资源服务器注册实体。
 */
@Entity
@Table(
        name = "iam_resource_server",
        uniqueConstraints = {
                @UniqueConstraint(name = "uk_iam_rs_code", columnNames = "resource_code"),
                @UniqueConstraint(name = "uk_iam_rs_audience", columnNames = "audience")
        },
        indexes = {
                @Index(name = "idx_iam_rs_status", columnList = "status"),
                @Index(name = "idx_iam_rs_owner", columnList = "owner")
        }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class IamResourceServerEntity {
    /**
     * 资源服务器主键。
     */
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /**
     * 资源服务器编码。
     */
    @Column(name = "resource_code", nullable = false, length = 128, unique = true)
    private String resourceCode;

    /**
     * 资源服务器名称。
     */
    @Column(name = "resource_name", nullable = false, length = 256)
    private String resourceName;

    /**
     * Token 受众标识。
     */
    @Column(name = "audience", nullable = false, length = 256, unique = true)
    private String audience;

    /**
     * 资源服务器状态。
     */
    @Column(name = "status", nullable = false, length = 32)
    private String status;

    /**
     * 资源服务器归属负责人或团队。
     */
    @Column(name = "owner", length = 256)
    private String owner;

    /**
     * 创建时间。
     */
    @Column(name = "created_at", nullable = false)
    private Instant createdAt;
}
