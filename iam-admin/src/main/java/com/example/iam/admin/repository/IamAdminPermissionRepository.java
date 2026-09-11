package com.example.iam.admin.repository;

import com.example.iam.admin.entity.IamAdminPermissionEntity;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface IamAdminPermissionRepository extends JpaRepository<IamAdminPermissionEntity, UUID> {
    Optional<IamAdminPermissionEntity> findByPermCode(String permCode);
}
