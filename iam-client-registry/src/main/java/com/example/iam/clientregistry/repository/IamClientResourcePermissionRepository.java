package com.example.iam.clientregistry.repository;

import com.example.iam.clientregistry.entity.IamClientResourcePermissionEntity;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

public interface IamClientResourcePermissionRepository
        extends JpaRepository<IamClientResourcePermissionEntity, UUID>,
                JpaSpecificationExecutor<IamClientResourcePermissionEntity> {
    Optional<IamClientResourcePermissionEntity> findByClientIdAndResourceIdAndScopeIdAndGrantType(
            UUID clientId, UUID resourceId, UUID scopeId, String grantType);
    List<IamClientResourcePermissionEntity> findByClientId(UUID clientId);
    List<IamClientResourcePermissionEntity> findByClientIdAndResourceId(UUID clientId, UUID resourceId);
}
