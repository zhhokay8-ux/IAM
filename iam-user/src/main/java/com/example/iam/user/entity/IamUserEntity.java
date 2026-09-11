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
 * 统一用户实体。
 */
@Entity
@Table(
        name = "iam_user",
        uniqueConstraints = {
                @UniqueConstraint(name = "uk_iam_user_subject", columnNames = "subject_id"),
                @UniqueConstraint(name = "uk_iam_user_tenant_username", columnNames = {"tenant_id", "username"})
        },
        indexes = {
                @Index(name = "idx_iam_user_username", columnList = "username"),
                @Index(name = "idx_iam_user_status", columnList = "status"),
                @Index(name = "idx_iam_user_tenant", columnList = "tenant_id"),
                @Index(name = "idx_iam_user_org", columnList = "org_id"),
                @Index(name = "idx_iam_user_email", columnList = "email")
        }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class IamUserEntity {
    /**
     * 用户主键。
     */
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /**
     * 统一用户主体标识。
     */
    @Column(name = "subject_id", nullable = false, unique = true)
    private UUID subjectId;

    /**
     * 登录用户名。
     */
    @Column(name = "username", nullable = false, length = 128)
    private String username;

    /**
     * 用户显示名称。
     */
    @Column(name = "display_name", length = 256)
    private String displayName;

    /**
     * 用户邮箱，可变更，禁止作为 JWT sub。
     */
    @Column(name = "email", length = 256)
    private String email;

    /**
     * BCrypt 口令哈希，禁止明文。
     */
    @Column(name = "password_hash", length = 100)
    private String passwordHash;

    /**
     * 用户状态。
     */
    @Column(name = "status", nullable = false, length = 32)
    private String status;

    /**
     * 租户 ID。
     */
    @Column(name = "tenant_id", nullable = false, length = 128)
    private String tenantId;

    /**
     * 组织机构 ID。
     */
    @Column(name = "org_id", length = 128)
    private String orgId;

    /**
     * 创建时间。
     */
    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    /**
     * 更新时间。
     */
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;
}
