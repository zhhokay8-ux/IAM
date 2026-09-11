package com.example.iam.admin.rbac;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import com.example.iam.admin.entity.IamAdminPermissionEntity;
import com.example.iam.admin.entity.IamAdminRoleEntity;
import com.example.iam.admin.entity.IamAdminRolePermissionEntity;
import com.example.iam.admin.entity.IamAdminUserRoleEntity;
import com.example.iam.admin.repository.IamAdminPermissionRepository;
import com.example.iam.admin.repository.IamAdminRolePermissionRepository;
import com.example.iam.admin.repository.IamAdminRoleRepository;
import com.example.iam.admin.repository.IamAdminUserRoleRepository;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class AdminRbacServiceTest {

    @Mock
    private IamAdminUserRoleRepository userRoleRepository;

    @Mock
    private IamAdminRoleRepository roleRepository;

    @Mock
    private IamAdminRolePermissionRepository rolePermissionRepository;

    @Mock
    private IamAdminPermissionRepository permissionRepository;

    private AdminRbacService service;

    @BeforeEach
    void setUp() {
        service = new AdminRbacService(
                userRoleRepository, roleRepository, rolePermissionRepository, permissionRepository);
    }

    @Test
    void returnsEmptyWhenUserHasNoAdminRole() {
        UUID subject = UUID.randomUUID();
        when(userRoleRepository.findBySubjectId(subject)).thenReturn(List.of());
        assertThat(service.loadBySubjectId(subject).isEmpty()).isTrue();
    }

    @Test
    void loadsActiveRolePermissions() {
        UUID subject = UUID.randomUUID();
        UUID roleId = UUID.randomUUID();
        UUID permId = UUID.randomUUID();
        when(userRoleRepository.findBySubjectId(subject))
                .thenReturn(List.of(IamAdminUserRoleEntity.builder()
                        .id(UUID.randomUUID())
                        .subjectId(subject)
                        .roleId(roleId)
                        .createdAt(Instant.now())
                        .build()));
        when(roleRepository.findAllById(List.of(roleId)))
                .thenReturn(List.of(IamAdminRoleEntity.builder()
                        .id(roleId)
                        .roleCode(AdminRoles.IAM_AUDITOR)
                        .roleName("Auditor")
                        .status("ACTIVE")
                        .createdAt(Instant.now())
                        .build()));
        when(rolePermissionRepository.findByRoleIdIn(List.of(roleId)))
                .thenReturn(List.of(IamAdminRolePermissionEntity.builder()
                        .id(UUID.randomUUID())
                        .roleId(roleId)
                        .permId(permId)
                        .build()));
        when(permissionRepository.findAllById(List.of(permId)))
                .thenReturn(List.of(IamAdminPermissionEntity.builder()
                        .id(permId)
                        .permCode(AdminPermissions.AUDIT_READ)
                        .permName("Audit read")
                        .createdAt(Instant.now())
                        .build()));

        AdminRbacService.AdminAccess access = service.loadBySubjectId(subject);
        assertThat(access.roles()).containsExactly(AdminRoles.IAM_AUDITOR);
        assertThat(access.permissions()).containsExactly(AdminPermissions.AUDIT_READ);
    }
}
