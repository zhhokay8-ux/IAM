package com.example.iam.embed.entity;

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
 * iframe 嵌入策略实体。
 */
@Entity
@Table(
        name = "iam_embed_policy",
        uniqueConstraints = @UniqueConstraint(
                name = "uk_iam_embed_policy",
                columnNames = {"child_client_id", "parent_client_id", "parent_origin", "allowed_path"}
        ),
        indexes = {
                @Index(name = "idx_iam_embed_child", columnList = "child_client_id"),
                @Index(name = "idx_iam_embed_parent", columnList = "parent_client_id"),
                @Index(name = "idx_iam_embed_status", columnList = "status")
        }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class IamEmbedPolicyEntity {
    /**
     * 嵌入策略主键。
     */
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /**
     * 子应用客户端 ID。
     */
    @Column(name = "child_client_id", nullable = false)
    private UUID childClientId;

    /**
     * 父应用客户端 ID。
     */
    @Column(name = "parent_client_id", nullable = false)
    private UUID parentClientId;

    /**
     * 允许的父应用 Origin。
     */
    @Column(name = "parent_origin", nullable = false, length = 512)
    private String parentOrigin;

    /**
     * 允许嵌入的路径。
     */
    @Column(name = "allowed_path", nullable = false, length = 512)
    private String allowedPath;

    /**
     * 策略状态。
     */
    @Column(name = "status", nullable = false, length = 32)
    private String status;

    /**
     * 创建时间。
     */
    @Column(name = "created_at", nullable = false)
    private Instant createdAt;
}
