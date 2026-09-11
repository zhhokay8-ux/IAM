package com.example.iam.admin.repository;

import com.example.iam.admin.entity.IamAdminRolePermissionEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface IamAdminRolePermissionRepository extends JpaRepository<IamAdminRolePermissionEntity, UUID> {
    List<IamAdminRolePermissionEntity> findByRoleIdIn(List<UUID> roleIds);
}
