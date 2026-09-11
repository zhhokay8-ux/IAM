package com.example.iam.admin.web.resource;

import com.example.iam.admin.rbac.AdminPermissions;
import com.example.iam.admin.security.AdminAuthenticationService;
import com.example.iam.admin.security.AdminPrincipal;
import com.example.iam.admin.security.AdminPrincipalHolder;
import com.example.iam.admin.security.RequireAdminPermission;
import com.example.iam.admin.web.client.AdminPageResponse;
import com.example.iam.audit.AuditEvent;
import com.example.iam.audit.IamAuditService;
import com.example.iam.clientregistry.domain.RegistryStatus;
import com.example.iam.clientregistry.dto.CreateResourceRequest;
import com.example.iam.clientregistry.dto.ResourceResponse;
import com.example.iam.clientregistry.dto.UpdateResourceRequest;
import com.example.iam.clientregistry.service.IamResourceService;
import jakarta.servlet.http.HttpServletRequest;
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
@RequestMapping("/api/admin/resources")
public class AdminResourceController {

    private final IamResourceService resourceService;
    private final IamAuditService auditService;

    public AdminResourceController(IamResourceService resourceService, IamAuditService auditService) {
        this.resourceService = resourceService;
        this.auditService = auditService;
    }

    @GetMapping
    @RequireAdminPermission(AdminPermissions.RESOURCE_READ)
    public AdminPageResponse<ResourceResponse> list(
            @RequestParam(name = "q", required = false) String query,
            @RequestParam(name = "status", required = false) String status,
            @RequestParam(name = "page", defaultValue = "0") int page,
            @RequestParam(name = "size", defaultValue = "20") int size) {
        Page<ResourceResponse> result =
                resourceService.search(query, status, PageRequest.of(Math.max(page, 0), Math.min(Math.max(size, 1), 100)));
        return new AdminPageResponse<>(result.getContent(), result.getNumber(), result.getSize(), result.getTotalElements());
    }

    @GetMapping("/{resourceCode}")
    @RequireAdminPermission(AdminPermissions.RESOURCE_READ)
    public ResourceResponse get(@PathVariable String resourceCode) {
        return resourceService.get(resourceCode);
    }

    @PostMapping
    @RequireAdminPermission(AdminPermissions.RESOURCE_WRITE)
    public ResourceResponse create(@RequestBody AdminCreateResourceRequest request, HttpServletRequest http) {
        ResourceResponse created = resourceService.create(new CreateResourceRequest(
                request.resourceCode(),
                request.resourceName(),
                request.audience(),
                RegistryStatus.INACTIVE,
                request.owner()));
        audit(http, AuditEvent.RESOURCE_CREATED, created.resourceCode(), "admin_create_resource");
        return created;
    }

    @PutMapping("/{resourceCode}")
    @RequireAdminPermission(AdminPermissions.RESOURCE_WRITE)
    public ResourceResponse update(
            @PathVariable String resourceCode,
            @RequestBody AdminUpdateResourceRequest request,
            HttpServletRequest http) {
        ResourceResponse updated = resourceService.update(
                resourceCode, new UpdateResourceRequest(request.resourceName(), request.audience(), null, request.owner()));
        audit(http, AuditEvent.RESOURCE_UPDATED, resourceCode, "admin_update_resource");
        return updated;
    }

    @PostMapping("/{resourceCode}/disable")
    @RequireAdminPermission(AdminPermissions.RESOURCE_WRITE)
    public ResourceResponse disable(@PathVariable("resourceCode") String resourceCode, HttpServletRequest http) {
        ResourceResponse response = resourceService.disable(resourceCode);
        audit(http, AuditEvent.RESOURCE_DISABLED, resourceCode, "admin_disable_resource; resource_code=" + resourceCode);
        return response;
    }

    @PostMapping("/{resourceCode}/enable")
    @RequireAdminPermission(AdminPermissions.RESOURCE_WRITE)
    public ResourceResponse enable(@PathVariable String resourceCode, HttpServletRequest http) {
        ResourceResponse response = resourceService.enable(resourceCode);
        audit(http, AuditEvent.RESOURCE_ENABLED, resourceCode, "admin_enable_resource; resource_code=" + resourceCode);
        return response;
    }

    private void audit(HttpServletRequest request, AuditEvent event, String resourceCode, String detail) {
        AdminPrincipal principal = AdminPrincipalHolder.get(request);
        auditService.recordAdmin(
                event,
                principal == null || principal.subjectId() == null ? null : principal.subjectId().toString(),
                principal == null ? null : principal.username(),
                principal == null ? null : principal.tenantId(),
                "resource",
                resourceCode,
                AdminAuthenticationService.clientIp(request),
                request.getHeader(HttpHeaders.USER_AGENT),
                true,
                detail);
    }
}
