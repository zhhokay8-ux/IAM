package com.example.iam.user.repository;

import com.example.iam.user.entity.IamUserIdentityMappingEntity;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

public interface IamUserIdentityMappingRepository
        extends JpaRepository<IamUserIdentityMappingEntity, UUID>,
                JpaSpecificationExecutor<IamUserIdentityMappingEntity> {
    Optional<IamUserIdentityMappingEntity> findBySubjectIdAndSystemCodeAndExternalUserId(
            UUID subjectId, String systemCode, String externalUserId);
    Optional<IamUserIdentityMappingEntity> findBySystemCodeAndExternalUserId(String systemCode, String externalUserId);
    boolean existsBySystemCodeAndExternalUserId(String systemCode, String externalUserId);
    List<IamUserIdentityMappingEntity> findBySubjectId(UUID subjectId);
}
