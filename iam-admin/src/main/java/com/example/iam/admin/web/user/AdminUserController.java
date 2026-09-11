package com.example.iam.admin.web.user;

import com.example.iam.admin.rbac.AdminPermissions;
import com.example.iam.admin.security.AdminAuthenticationService;
import com.example.iam.admin.security.AdminPrincipal;
import com.example.iam.admin.security.AdminPrincipalHolder;
import com.example.iam.admin.security.RequireAdminPermission;
import com.example.iam.admin.web.client.AdminPageResponse;
import com.example.iam.audit.AuditEvent;
import com.example.iam.audit.IamAuditService;
import com.example.iam.user.domain.UserStatus;
import com.example.iam.user.dto.CreateUserRequest;
import com.example.iam.user.dto.IdentityMappingRequest;
import com.example.iam.user.dto.IdentityMappingResponse;
import com.example.iam.user.dto.UpdateUserRequest;
import com.example.iam.user.dto.UserResponse;
import com.example.iam.user.service.IamIdentityMappingService;
import com.example.iam.user.service.IamUserService;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin/users")
public class AdminUserController {

    private final IamUserService userService;
    private final AdminUserLifecycleService lifecycleService;
    private final IamIdentityMappingService mappingService;
    private final IamAuditService auditService;

    public AdminUserController(
            IamUserService userService,
            AdminUserLifecycleService lifecycleService,
            IamIdentityMappingService mappingService,
            IamAuditService auditService) {
        this.userService = userService;
        this.lifecycleService = lifecycleService;
        this.mappingService = mappingService;
        this.auditService = auditService;
    }

    @GetMapping
    @RequireAdminPermission(AdminPermissions.USER_READ)
    public AdminPageResponse<UserResponse> list(
            @RequestParam(name = "q", required = false) String query,
            @RequestParam(name = "status", required = false) String status,
            @RequestParam(name = "tenant_id", required = false) String tenantId,
            @RequestParam(name = "page", defaultValue = "0") int page,
            @RequestParam(name = "size", defaultValue = "20") int size) {
        Page<UserResponse> result = userService.search(
                query, status, tenantId, PageRequest.of(Math.max(page, 0), Math.min(Math.max(size, 1), 100)));
        return new AdminPageResponse<>(result.getContent(), result.getNumber(), result.getSize(), result.getTotalElements());
    }

    @GetMapping("/{subjectId}")
    @RequireAdminPermission(AdminPermissions.USER_READ)
    public UserResponse get(@PathVariable UUID subjectId) {
        return userService.get(subjectId);
    }

    @PostMapping
    @RequireAdminPermission(AdminPermissions.USER_WRITE)
    public UserResponse create(@RequestBody AdminCreateUserRequest request, HttpServletRequest http) {
        UserResponse created = userService.create(new CreateUserRequest(
                request.username(),
                request.displayName(),
                request.email(),
                request.tenantId(),
                request.orgId(),
                UserStatus.INACTIVE));
        audit(http, AuditEvent.USER_CREATED, created.subjectId(), "admin_create_user");
        return created;
    }

    @PutMapping("/{subjectId}")
    @RequireAdminPermission(AdminPermissions.USER_WRITE)
    public UserResponse update(
            @PathVariable UUID subjectId, @RequestBody AdminUpdateUserRequest request, HttpServletRequest http) {
        UserResponse updated = userService.update(
                subjectId,
                new UpdateUserRequest(request.username(), request.displayName(), request.email(), request.orgId(), null));
        audit(http, AuditEvent.USER_UPDATED, subjectId.toString(), "admin_update_user");
        return updated;
    }

    @PostMapping("/{subjectId}/disable")
    @RequireAdminPermission(AdminPermissions.USER_WRITE)
    public UserResponse disable(@PathVariable("subjectId") UUID subjectId, HttpServletRequest http) {
        UserResponse response = lifecycleService.disable(subjectId);
        audit(
                http,
                AuditEvent.USER_DISABLED,
                subjectId.toString(),
                "admin_disable_user; subject_id=" + subjectId);
        audit(
                http,
                AuditEvent.SESSION_REVOKED,
                subjectId.toString(),
                "admin_disable_user_sessions; subject_id=" + subjectId);
        return response;
    }

    @PostMapping("/{subjectId}/enable")
    @RequireAdminPermission(AdminPermissions.USER_WRITE)
    public UserResponse enable(@PathVariable UUID subjectId, HttpServletRequest http) {
        UserResponse response = lifecycleService.enable(subjectId);
        audit(http, AuditEvent.USER_ENABLED, subjectId.toString(), "admin_enable_user; subject_id=" + subjectId);
        return response;
    }

    @GetMapping("/{subjectId}/identity-mappings")
    @RequireAdminPermission(AdminPermissions.USER_READ)
    public List<IdentityMappingResponse> mappings(@PathVariable UUID subjectId) {
        return mappingService.list(subjectId);
    }

    @PostMapping("/{subjectId}/identity-mappings")
    @RequireAdminPermission(AdminPermissions.USER_WRITE)
    public IdentityMappingResponse createMapping(
            @PathVariable UUID subjectId, @RequestBody AdminIdentityMappingRequest request, HttpServletRequest http) {
        IdentityMappingResponse created = mappingService.create(
                subjectId,
                new IdentityMappingRequest(
                        request.systemCode(),
                        request.externalUserId(),
                        request.externalUsername(),
                        request.mappingStatus()));
        audit(http, AuditEvent.USER_UPDATED, subjectId.toString(), "admin_create_identity_mapping");
        return created;
    }

    private void audit(HttpServletRequest request, AuditEvent event, String subjectId, String detail) {
        AdminPrincipal principal = AdminPrincipalHolder.get(request);
        auditService.recordAdmin(
                event,
                principal == null || principal.subjectId() == null ? null : principal.subjectId().toString(),
                principal == null ? null : principal.username(),
                principal == null ? null : principal.tenantId(),
                "user",
                subjectId,
                AdminAuthenticationService.clientIp(request),
                request.getHeader(HttpHeaders.USER_AGENT),
                true,
                detail);
    }
}
