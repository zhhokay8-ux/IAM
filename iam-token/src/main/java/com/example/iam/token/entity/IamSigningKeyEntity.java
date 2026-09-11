package com.example.iam.token.entity;

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
 * 签名密钥元数据实体。
 */
@Entity
@Table(
        name = "iam_signing_key",
        uniqueConstraints = @UniqueConstraint(name = "uk_iam_signing_key_kid", columnNames = "kid"),
        indexes = {
                @Index(name = "idx_iam_signing_key_status", columnList = "status"),
                @Index(name = "idx_iam_signing_key_algorithm", columnList = "algorithm")
        }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class IamSigningKeyEntity {
    /**
     * 签名密钥主键。
     */
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /**
     * 密钥 ID。
     */
    @Column(name = "kid", nullable = false, length = 128, unique = true)
    private String kid;

    /**
     * 签名算法。
     */
    @Column(name = "algorithm", nullable = false, length = 32)
    private String algorithm;

    /**
     * KMS/HSM 密钥标识，禁止保存 RSA 私钥。
     */
    @Column(name = "kms_key_id", nullable = false, length = 512)
    private String kmsKeyId;

    /**
     * 密钥状态。
     */
    @Column(name = "status", nullable = false, length = 32)
    private String status;

    /**
     * 启用时间。
     */
    @Column(name = "activated_at")
    private Instant activatedAt;

    /**
     * 停用时间。
     */
    @Column(name = "retired_at")
    private Instant retiredAt;

    /**
     * 创建时间。
     */
    @Column(name = "created_at", nullable = false)
    private Instant createdAt;
}
