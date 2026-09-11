package com.example.iam.embed.repository;

import com.example.iam.embed.entity.IamEmbedPolicyEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface IamEmbedPolicyRepository extends JpaRepository<IamEmbedPolicyEntity, UUID> {
    List<IamEmbedPolicyEntity> findByChildClientIdAndParentClientId(UUID childClientId, UUID parentClientId);

    List<IamEmbedPolicyEntity> findByParentClientId(UUID parentClientId);

    List<IamEmbedPolicyEntity> findByChildClientId(UUID childClientId);

    boolean existsByChildClientIdAndParentClientIdAndParentOriginAndAllowedPath(
            UUID childClientId, UUID parentClientId, String parentOrigin, String allowedPath);
}
