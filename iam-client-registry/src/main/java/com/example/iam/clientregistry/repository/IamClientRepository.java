package com.example.iam.clientregistry.repository;

import com.example.iam.clientregistry.entity.IamClientEntity;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

public interface IamClientRepository
        extends JpaRepository<IamClientEntity, UUID>, JpaSpecificationExecutor<IamClientEntity> {
    Optional<IamClientEntity> findByClientId(String clientId);
    boolean existsByClientId(String clientId);
    long countByStatus(String status);
}
