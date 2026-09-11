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
 * OAuth/OIDC 客户端注册实体。
 */
@Entity
@Table(
        name = "iam_client",
        uniqueConstraints = @UniqueConstraint(name = "uk_iam_client_client_id", columnNames = "client_id"),
        indexes = {
                @Index(name = "idx_iam_client_status", columnList = "status"),
                @Index(name = "idx_iam_client_owner", columnList = "owner")
        }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class IamClientEntity {
    /**
     * 客户端主键。
     */
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /**
     * 客户端唯一标识。
     */
    @Column(name = "client_id", nullable = false, length = 128, unique = true)
    private String clientId;

    /**
     * 客户端显示名称。
     */
    @Column(name = "client_name", nullable = false, length = 256)
    private String clientName;

    /**
     * 客户端类型，例如 CONFIDENTIAL 或 PUBLIC。
     */
    @Column(name = "client_type", nullable = false, length = 32)
    private String clientType;

    /**
     * 客户端状态。
     */
    @Column(name = "status", nullable = false, length = 32)
    private String status;

    /**
     * Token Endpoint 认证方式。
     */
    @Column(name = "token_endpoint_auth_method", nullable = false, length = 64)
    private String tokenEndpointAuthMethod;

    /**
     * Access Token 有效期，单位秒。
     */
    @Column(name = "access_token_ttl", nullable = false)
    private Integer accessTokenTtl;

    /**
     * Refresh Token 有效期，单位秒。
     */
    @Column(name = "refresh_token_ttl", nullable = false)
    private Integer refreshTokenTtl;

    /**
     * 是否强制要求 PKCE。
     */
    @Column(name = "pkce_required", nullable = false)
    private Boolean pkceRequired;

    /**
     * 客户端密钥 SHA-256 哈希，禁止保存明文。
     */
    @Column(name = "client_secret_hash", length = 128)
    private String clientSecretHash;

    /**
     * 客户端归属负责人或团队。
     */
    @Column(name = "owner", length = 256)
    private String owner;

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
