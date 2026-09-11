package com.example.iam.user.repository;

import com.example.iam.user.entity.IamUserEntity;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

public interface IamUserRepository extends JpaRepository<IamUserEntity, UUID>, JpaSpecificationExecutor<IamUserEntity> {
    Optional<IamUserEntity> findBySubjectId(UUID subjectId);
    Optional<IamUserEntity> findByUsernameAndTenantId(String username, String tenantId);
    boolean existsByUsernameAndTenantId(String username, String tenantId);
    long countByStatus(String status);
}
