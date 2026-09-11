package com.example.iam.clientregistry.repository;

import com.example.iam.clientregistry.entity.IamScopeEntity;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

public interface IamScopeRepository
        extends JpaRepository<IamScopeEntity, UUID>, JpaSpecificationExecutor<IamScopeEntity> {
    Optional<IamScopeEntity> findByResourceIdAndScopeCode(UUID resourceId, String scopeCode);
    List<IamScopeEntity> findByResourceId(UUID resourceId);
    List<IamScopeEntity> findByScopeCode(String scopeCode);
    boolean existsByResourceIdAndScopeCode(UUID resourceId, String scopeCode);
    long countByStatus(String status);
}
