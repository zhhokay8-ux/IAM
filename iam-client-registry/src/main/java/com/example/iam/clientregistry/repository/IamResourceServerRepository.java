package com.example.iam.clientregistry.repository;

import com.example.iam.clientregistry.entity.IamResourceServerEntity;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

public interface IamResourceServerRepository
        extends JpaRepository<IamResourceServerEntity, UUID>, JpaSpecificationExecutor<IamResourceServerEntity> {
    Optional<IamResourceServerEntity> findByResourceCode(String resourceCode);
    Optional<IamResourceServerEntity> findByAudience(String audience);
    boolean existsByResourceCode(String resourceCode);
    boolean existsByAudience(String audience);
    long countByStatus(String status);
}
