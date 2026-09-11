package com.example.iam.admin.web.scope;

import com.example.iam.admin.rbac.AdminPermissions;
import com.example.iam.admin.security.AdminAuthenticationService;
import com.example.iam.admin.security.AdminPrincipal;
import com.example.iam.admin.security.AdminPrincipalHolder;
import com.example.iam.admin.security.RequireAdminPermission;
import com.example.iam.admin.web.client.AdminPageResponse;
import com.example.iam.audit.AuditEvent;
import com.example.iam.audit.IamAuditService;
import com.example.iam.clientregistry.domain.RegistryStatus;
import com.example.iam.clientregistry.dto.CreateScopeRequest;
import com.example.iam.clientregistry.dto.ScopeResponse;
import com.example.iam.clientregistry.dto.UpdateScopeRequest;
import com.example.iam.clientregistry.service.IamScopeService;
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
@RequestMapping("/api/admin/scopes")
public class AdminScopeController {

    private final IamScopeService scopeService;
    private final IamAuditService auditService;

    public AdminScopeController(IamScopeService scopeService, IamAuditService auditService) {
        this.scopeService = scopeService;
        this.auditService = auditService;
    }

    @GetMapping
    @RequireAdminPermission(AdminPermissions.SCOPE_READ)
    public AdminPageResponse<ScopeResponse> list(
            @RequestParam(name = "resource_code", required = false) String resourceCode,
            @RequestParam(name = "q", required = false) String query,
            @RequestParam(name = "status", required = false) String status,
            @RequestParam(name = "page", defaultValue = "0") int page,
            @RequestParam(name = "size", defaultValue = "20") int size) {
        Page<ScopeResponse> result = scopeService.search(
                resourceCode, query, status, PageRequest.of(Math.max(page, 0), Math.min(Math.max(size, 1), 100)));
        return new AdminPageResponse<>(result.getContent(), result.getNumber(), result.getSize(), result.getTotalElements());
    }

    @GetMapping("/{resourceCode}/{scopeCode}")
    @RequireAdminPermission(AdminPermissions.SCOPE_READ)
    public ScopeResponse get(@PathVariable String resourceCode, @PathVariable String scopeCode) {
        return scopeService.get(resourceCode, scopeCode);
    }

    @PostMapping
    @RequireAdminPermission(AdminPermissions.SCOPE_WRITE)
    public ScopeResponse create(@RequestBody AdminCreateScopeRequest request, HttpServletRequest http) {
        ScopeResponse created = scopeService.create(new CreateScopeRequest(
                request.resourceCode(),
                request.scopeCode(),
                request.scopeName(),
                request.description(),
                RegistryStatus.INACTIVE));
        audit(http, AuditEvent.SCOPE_CREATED, request.resourceCode(), created.scopeCode(), "admin_create_scope");
        return created;
    }

    @PutMapping("/{resourceCode}/{scopeCode}")
    @RequireAdminPermission(AdminPermissions.SCOPE_WRITE)
    public ScopeResponse update(
            @PathVariable String resourceCode,
            @PathVariable String scopeCode,
            @RequestBody AdminUpdateScopeRequest request,
            HttpServletRequest http) {
        ScopeResponse updated =
                scopeService.update(resourceCode, scopeCode, new UpdateScopeRequest(request.scopeName(), request.description()));
        audit(http, AuditEvent.SCOPE_UPDATED, resourceCode, scopeCode, "admin_update_scope");
        return updated;
    }

    @PostMapping("/{resourceCode}/{scopeCode}/disable")
    @RequireAdminPermission(AdminPermissions.SCOPE_WRITE)
    public ScopeResponse disable(
            @PathVariable("resourceCode") String resourceCode,
            @PathVariable("scopeCode") String scopeCode,
            HttpServletRequest http) {
        ScopeResponse response = scopeService.disable(resourceCode, scopeCode);
        audit(
                http,
                AuditEvent.SCOPE_DISABLED,
                resourceCode,
                scopeCode,
                "admin_disable_scope; resource_code=" + resourceCode + "; scope_code=" + scopeCode);
        return response;
    }

    @PostMapping("/{resourceCode}/{scopeCode}/enable")
    @RequireAdminPermission(AdminPermissions.SCOPE_WRITE)
    public ScopeResponse enable(
            @PathVariable String resourceCode, @PathVariable String scopeCode, HttpServletRequest http) {
        ScopeResponse response = scopeService.enable(resourceCode, scopeCode);
        audit(http, AuditEvent.SCOPE_ENABLED, resourceCode, scopeCode, "admin_enable_scope; scope_code=" + scopeCode);
        return response;
    }

    private void audit(
            HttpServletRequest request, AuditEvent event, String resourceCode, String scopeCode, String detail) {
        AdminPrincipal principal = AdminPrincipalHolder.get(request);
        auditService.recordAdmin(
                event,
                principal == null || principal.subjectId() == null ? null : principal.subjectId().toString(),
                principal == null ? null : principal.username(),
                principal == null ? null : principal.tenantId(),
                "scope",
                resourceCode + "/" + scopeCode,
                AdminAuthenticationService.clientIp(request),
                request.getHeader(HttpHeaders.USER_AGENT),
                true,
                detail);
    }
}
