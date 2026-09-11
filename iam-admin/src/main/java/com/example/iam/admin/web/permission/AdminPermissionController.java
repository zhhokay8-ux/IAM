package com.example.iam.admin.web.permission;

import com.example.iam.admin.rbac.AdminPermissions;
import com.example.iam.admin.security.AdminAuthenticationService;
import com.example.iam.admin.security.AdminPrincipal;
import com.example.iam.admin.security.AdminPrincipalHolder;
import com.example.iam.admin.security.RequireAdminPermission;
import com.example.iam.admin.web.client.AdminPageResponse;
import com.example.iam.audit.AuditEvent;
import com.example.iam.audit.IamAuditService;
import com.example.iam.clientregistry.domain.RegistryStatus;
import com.example.iam.clientregistry.dto.CreatePermissionRequest;
import com.example.iam.clientregistry.dto.PermissionResponse;
import com.example.iam.clientregistry.service.IamPermissionService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin/permissions")
public class AdminPermissionController {

    private final IamPermissionService permissionService;
    private final IamAuditService auditService;

    public AdminPermissionController(IamPermissionService permissionService, IamAuditService auditService) {
        this.permissionService = permissionService;
        this.auditService = auditService;
    }

    @GetMapping
    @RequireAdminPermission(AdminPermissions.POLICY_READ)
    public AdminPageResponse<PermissionResponse> list(
            @RequestParam(name = "client_id", required = false) String clientId,
            @RequestParam(name = "resource_code", required = false) String resourceCode,
            @RequestParam(name = "grant_type", required = false) String grantType,
            @RequestParam(name = "status", required = false) String status,
            @RequestParam(name = "page", defaultValue = "0") int page,
            @RequestParam(name = "size", defaultValue = "20") int size) {
        Page<PermissionResponse> result = permissionService.search(
                clientId,
                resourceCode,
                grantType,
                status,
                PageRequest.of(Math.max(page, 0), Math.min(Math.max(size, 1), 100)));
        return new AdminPageResponse<>(result.getContent(), result.getNumber(), result.getSize(), result.getTotalElements());
    }

    @GetMapping("/item")
    @RequireAdminPermission(AdminPermissions.POLICY_READ)
    public PermissionResponse get(
            @RequestParam("client_id") String clientId,
            @RequestParam("resource_code") String resourceCode,
            @RequestParam("scope_code") String scopeCode,
            @RequestParam("grant_type") String grantType) {
        return permissionService.get(clientId, resourceCode, scopeCode, grantType);
    }

    @PostMapping
    @RequireAdminPermission(AdminPermissions.POLICY_WRITE)
    public PermissionResponse create(@RequestBody AdminCreatePermissionRequest request, HttpServletRequest http) {
        PermissionResponse created = permissionService.create(new CreatePermissionRequest(
                request.clientId(),
                request.resourceCode(),
                request.scopeCode(),
                request.grantType(),
                RegistryStatus.INACTIVE));
        audit(http, created, "admin_create_permission");
        return created;
    }

    @PostMapping("/disable")
    @RequireAdminPermission(AdminPermissions.POLICY_WRITE)
    public PermissionResponse disable(@RequestBody AdminPermissionKeyRequest request, HttpServletRequest http) {
        PermissionResponse response = permissionService.disable(
                request.clientId(), request.resourceCode(), request.scopeCode(), request.grantType());
        audit(http, response, "admin_disable_permission");
        return response;
    }

    @PostMapping("/enable")
    @RequireAdminPermission(AdminPermissions.POLICY_WRITE)
    public PermissionResponse enable(@RequestBody AdminPermissionKeyRequest request, HttpServletRequest http) {
        PermissionResponse response = permissionService.enable(
                request.clientId(), request.resourceCode(), request.scopeCode(), request.grantType());
        audit(http, response, "admin_enable_permission");
        return response;
    }

    private void audit(HttpServletRequest request, PermissionResponse permission, String action) {
        AdminPrincipal principal = AdminPrincipalHolder.get(request);
        auditService.recordAdmin(
                AuditEvent.POLICY_CHANGED,
                principal == null || principal.subjectId() == null ? null : principal.subjectId().toString(),
                principal == null ? null : principal.username(),
                principal == null ? null : principal.tenantId(),
                "permission",
                permission.clientId(),
                AdminAuthenticationService.clientIp(request),
                request.getHeader(HttpHeaders.USER_AGENT),
                true,
                action + "; client_id=" + permission.clientId()
                        + "; resource_code=" + permission.resourceCode()
                        + "; scope_code=" + permission.scopeCode()
                        + "; grant_type=" + permission.grantType()
                        + "; status=" + permission.status());
    }
}
