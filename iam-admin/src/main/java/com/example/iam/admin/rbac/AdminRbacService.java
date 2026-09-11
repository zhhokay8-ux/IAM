package com.example.iam.admin.rbac;

import com.example.iam.admin.entity.IamAdminPermissionEntity;
import com.example.iam.admin.entity.IamAdminRoleEntity;
import com.example.iam.admin.entity.IamAdminRolePermissionEntity;
import com.example.iam.admin.entity.IamAdminUserRoleEntity;
import com.example.iam.admin.repository.IamAdminPermissionRepository;
import com.example.iam.admin.repository.IamAdminRolePermissionRepository;
import com.example.iam.admin.repository.IamAdminRoleRepository;
import com.example.iam.admin.repository.IamAdminUserRoleRepository;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AdminRbacService {

    public static final String ROLE_STATUS_ACTIVE = "ACTIVE";

    private final IamAdminUserRoleRepository userRoleRepository;
    private final IamAdminRoleRepository roleRepository;
    private final IamAdminRolePermissionRepository rolePermissionRepository;
    private final IamAdminPermissionRepository permissionRepository;

    public AdminRbacService(
            IamAdminUserRoleRepository userRoleRepository,
            IamAdminRoleRepository roleRepository,
            IamAdminRolePermissionRepository rolePermissionRepository,
            IamAdminPermissionRepository permissionRepository) {
        this.userRoleRepository = userRoleRepository;
        this.roleRepository = roleRepository;
        this.rolePermissionRepository = rolePermissionRepository;
        this.permissionRepository = permissionRepository;
    }

    @Transactional(readOnly = true)
    public AdminAccess loadBySubjectId(UUID subjectId) {
        if (subjectId == null) {
            return AdminAccess.empty();
        }
        List<IamAdminUserRoleEntity> bindings = userRoleRepository.findBySubjectId(subjectId);
        if (bindings.isEmpty()) {
            return AdminAccess.empty();
        }
        List<UUID> roleIds = bindings.stream().map(IamAdminUserRoleEntity::getRoleId).toList();
        List<IamAdminRoleEntity> activeRoles = roleRepository.findAllById(roleIds).stream()
                .filter(role -> ROLE_STATUS_ACTIVE.equals(role.getStatus()))
                .toList();
        if (activeRoles.isEmpty()) {
            return AdminAccess.empty();
        }
        Set<String> roleCodes = activeRoles.stream()
                .map(IamAdminRoleEntity::getRoleCode)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        List<UUID> activeRoleIds = activeRoles.stream().map(IamAdminRoleEntity::getId).toList();
        List<IamAdminRolePermissionEntity> mappings = rolePermissionRepository.findByRoleIdIn(activeRoleIds);
        if (mappings.isEmpty()) {
            return new AdminAccess(roleCodes, Set.of());
        }
        List<UUID> permIds = mappings.stream().map(IamAdminRolePermissionEntity::getPermId).distinct().toList();
        Set<String> permissions = permissionRepository.findAllById(permIds).stream()
                .map(IamAdminPermissionEntity::getPermCode)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        return new AdminAccess(roleCodes, permissions);
    }

    @Transactional(readOnly = true)
    public AdminAccess loadFullAdminAccess() {
        Set<String> permissions = permissionRepository.findAll().stream()
                .map(IamAdminPermissionEntity::getPermCode)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        return new AdminAccess(Set.of(AdminRoles.IAM_ADMIN), permissions);
    }

    public record AdminAccess(Set<String> roles, Set<String> permissions) {
        public static AdminAccess empty() {
            return new AdminAccess(Set.of(), Set.of());
        }

        public boolean isEmpty() {
            return roles == null || roles.isEmpty();
        }
    }
}
