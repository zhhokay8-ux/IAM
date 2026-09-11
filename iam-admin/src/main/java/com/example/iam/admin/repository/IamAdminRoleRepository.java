package com.example.iam.admin.repository;

import com.example.iam.admin.entity.IamAdminRoleEntity;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface IamAdminRoleRepository extends JpaRepository<IamAdminRoleEntity, UUID> {
    Optional<IamAdminRoleEntity> findByRoleCode(String roleCode);
}
