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
 * Refresh Token 持久化实体。
 */
@Entity
@Table(
        name = "iam_refresh_token",
        uniqueConstraints = @UniqueConstraint(name = "uk_iam_refresh_token_hash", columnNames = "token_hash"),
        indexes = {
                @Index(name = "idx_iam_refresh_subject", columnList = "subject_id"),
                @Index(name = "idx_iam_refresh_client", columnList = "client_id"),
                @Index(name = "idx_iam_refresh_session", columnList = "session_id"),
                @Index(name = "idx_iam_refresh_status", columnList = "status"),
                @Index(name = "idx_iam_refresh_expires", columnList = "expires_at")
        }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class IamRefreshTokenEntity {
    /**
     * Refresh Token 主键。
     */
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /**
     * Refresh Token 的 SHA-256 哈希值，禁止保存明文。
     */
    @Column(name = "token_hash", nullable = false, length = 128, unique = true)
    private String tokenHash;

    /**
     * 统一用户 ID。
     */
    @Column(name = "subject_id", nullable = false)
    private UUID subjectId;

    /**
     * 客户端 ID。
     */
    @Column(name = "client_id", nullable = false)
    private UUID clientId;

    /**
     * 会话 ID。
     */
    @Column(name = "session_id", nullable = false)
    private UUID sessionId;

    /**
     * 签发时间。
     */
    @Column(name = "issued_at", nullable = false)
    private Instant issuedAt;

    /**
     * 过期时间。
     */
    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    /**
     * 撤销时间。
     */
    @Column(name = "revoked_at")
    private Instant revokedAt;

    /**
     * 轮换前的父 Refresh Token ID。
     */
    @Column(name = "rotation_parent_id")
    private UUID rotationParentId;

    /**
     * Refresh Token 状态。
     */
    @Column(name = "status", nullable = false, length = 32)
    private String status;

    /**
     * 授权时批准的 scope，空格分隔。
     */
    @Column(name = "scope", length = 1024)
    private String scope;

    /**
     * Access Token 受众，空格分隔。
     */
    @Column(name = "audience", length = 1024)
    private String audience;
}
