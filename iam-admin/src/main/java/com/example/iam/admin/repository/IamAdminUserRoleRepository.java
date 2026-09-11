package com.example.iam.admin.repository;

import com.example.iam.admin.entity.IamAdminUserRoleEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface IamAdminUserRoleRepository extends JpaRepository<IamAdminUserRoleEntity, UUID> {
    List<IamAdminUserRoleEntity> findBySubjectId(UUID subjectId);

    boolean existsBySubjectIdAndRoleId(UUID subjectId, UUID roleId);
}
