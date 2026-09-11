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
 * OAuth/OIDC 客户端回调地址实体。
 */
@Entity
@Table(
        name = "iam_client_redirect_uri",
        uniqueConstraints = @UniqueConstraint(
                name = "uk_iam_cli_redir_uri",
                columnNames = {"client_id", "redirect_uri", "uri_type"}
        ),
        indexes = {
                @Index(name = "idx_iam_cli_redir_client", columnList = "client_id"),
                @Index(name = "idx_iam_cli_redir_status", columnList = "status")
        }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class IamClientRedirectUriEntity {
    /**
     * 回调地址主键。
     */
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /**
     * 所属客户端 ID。
     */
    @Column(name = "client_id", nullable = false)
    private UUID clientId;

    /**
     * 注册的回调 URI。
     */
    @Column(name = "redirect_uri", nullable = false, length = 1024)
    private String redirectUri;

    /**
     * 回调 URI 类型。
     */
    @Column(name = "uri_type", nullable = false, length = 32)
    private String uriType;

    /**
     * 回调地址状态。
     */
    @Column(name = "status", nullable = false, length = 32)
    private String status;
}
