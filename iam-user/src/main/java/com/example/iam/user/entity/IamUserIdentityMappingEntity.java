package com.example.iam.user.entity;

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
 * 外部系统用户身份映射实体。
 */
@Entity
@Table(
        name = "iam_user_identity_mapping",
        uniqueConstraints = @UniqueConstraint(
                name = "uk_idmap_sys_ext",
                columnNames = {"system_code", "external_user_id"}
        ),
        indexes = {
                @Index(name = "idx_iam_identity_subject", columnList = "subject_id"),
                @Index(name = "idx_iam_identity_system", columnList = "system_code"),
                @Index(name = "idx_iam_identity_external_id", columnList = "external_user_id"),
                @Index(name = "idx_iam_identity_status", columnList = "mapping_status")
        }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class IamUserIdentityMappingEntity {
    /**
     * 身份映射主键。
     */
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /**
     * 统一用户主体 ID。
     */
    @Column(name = "subject_id", nullable = false)
    private UUID subjectId;

    /**
     * 外部系统编码。
     */
    @Column(name = "system_code", nullable = false, length = 128)
    private String systemCode;

    /**
     * 外部系统用户 ID。
     */
    @Column(name = "external_user_id", nullable = false, length = 256)
    private String externalUserId;

    /**
     * 外部系统用户名。
     */
    @Column(name = "external_username", length = 256)
    private String externalUsername;

    /**
     * 映射状态。
     */
    @Column(name = "mapping_status", nullable = false, length = 32)
    private String mappingStatus;

    /**
     * 创建时间。
     */
    @Column(name = "created_at", nullable = false)
    private Instant createdAt;
}
