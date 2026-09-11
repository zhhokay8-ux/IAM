package com.example.iam.clientregistry.entity;

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
 * 资源作用域实体。
 */
@Entity
@Table(
        name = "iam_scope",
        uniqueConstraints = @UniqueConstraint(
                name = "uk_iam_scope_res_code",
                columnNames = {"resource_id", "scope_code"}
        ),
        indexes = {
                @Index(name = "idx_iam_scope_resource", columnList = "resource_id"),
                @Index(name = "idx_iam_scope_status", columnList = "status")
        }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class IamScopeEntity {
    /**
     * 作用域主键。
     */
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /**
     * 所属资源服务器 ID。
     */
    @Column(name = "resource_id", nullable = false)
    private UUID resourceId;

    /**
     * 作用域编码。
     */
    @Column(name = "scope_code", nullable = false, length = 128)
    private String scopeCode;

    /**
     * 作用域名称。
     */
    @Column(name = "scope_name", nullable = false, length = 256)
    private String scopeName;

    /**
     * 作用域说明。
     */
    @Column(name = "description", length = 1024)
    private String description;

    /**
     * 作用域状态。
     */
    @Column(name = "status", nullable = false, length = 32)
    private String status;
}
