package com.example.iam.admin.web.user;

import com.example.iam.admin.rbac.AdminPermissions;
import com.example.iam.admin.security.AdminAuthenticationService;
import com.example.iam.admin.security.AdminPrincipal;
import com.example.iam.admin.security.AdminPrincipalHolder;
import com.example.iam.admin.security.RequireAdminPermission;
import com.example.iam.admin.web.client.AdminPageResponse;
import com.example.iam.audit.AuditEvent;
import com.example.iam.audit.IamAuditService;
import com.example.iam.user.dto.IdentityMappingRequest;
import com.example.iam.user.dto.IdentityMappingResponse;
import com.example.iam.user.service.IamIdentityMappingService;
import jakarta.servlet.http.HttpServletRequest;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin/identity-mappings")
public class AdminIdentityMappingController {

    private final IamIdentityMappingService mappingService;
    private final IamAuditService auditService;

    public AdminIdentityMappingController(IamIdentityMappingService mappingService, IamAuditService auditService) {
        this.mappingService = mappingService;
        this.auditService = auditService;
    }

    @GetMapping
    @RequireAdminPermission(AdminPermissions.USER_READ)
    public AdminPageResponse<IdentityMappingResponse> list(
            @RequestParam(name = "system_code", required = false) String systemCode,
            @RequestParam(name = "external_user_id", required = false) String externalUserId,
            @RequestParam(name = "subject_id", required = false) UUID subjectId,
            @RequestParam(name = "page", defaultValue = "0") int page,
            @RequestParam(name = "size", defaultValue = "20") int size) {
        Page<IdentityMappingResponse> result = mappingService.search(
                systemCode,
                externalUserId,
                subjectId,
                PageRequest.of(Math.max(page, 0), Math.min(Math.max(size, 1), 100)));
        return new AdminPageResponse<>(result.getContent(), result.getNumber(), result.getSize(), result.getTotalElements());
    }

    @GetMapping("/{mappingId}")
    @RequireAdminPermission(AdminPermissions.USER_READ)
    public IdentityMappingResponse get(@PathVariable UUID mappingId) {
        return mappingService.get(mappingId);
    }

    @PostMapping
    @RequireAdminPermission(AdminPermissions.USER_WRITE)
    public IdentityMappingResponse create(@RequestBody AdminIdentityMappingRequest request, HttpServletRequest http) {
        UUID subjectId = UUID.fromString(request.subjectId());
        IdentityMappingResponse created = mappingService.create(
                subjectId,
                new IdentityMappingRequest(
                        request.systemCode(),
                        request.externalUserId(),
                        request.externalUsername(),
                        request.mappingStatus()));
        audit(http, created.subjectId(), "admin_create_identity_mapping");
        return created;
    }

    @PutMapping("/{mappingId}")
    @RequireAdminPermission(AdminPermissions.USER_WRITE)
    public IdentityMappingResponse update(
            @PathVariable UUID mappingId, @RequestBody AdminIdentityMappingRequest request, HttpServletRequest http) {
        IdentityMappingResponse updated = mappingService.update(
                mappingId,
                new IdentityMappingRequest(
                        request.systemCode(),
                        request.externalUserId(),
                        request.externalUsername(),
                        request.mappingStatus()));
        audit(http, updated.subjectId(), "admin_update_identity_mapping");
        return updated;
    }

    @DeleteMapping("/{mappingId}")
    @RequireAdminPermission(AdminPermissions.USER_WRITE)
    public void delete(@PathVariable UUID mappingId, HttpServletRequest http) {
        IdentityMappingResponse existing = mappingService.get(mappingId);
        mappingService.delete(mappingId);
        audit(http, existing.subjectId(), "admin_delete_identity_mapping");
    }

    private void audit(HttpServletRequest request, String subjectId, String detail) {
        AdminPrincipal principal = AdminPrincipalHolder.get(request);
        auditService.recordAdmin(
                AuditEvent.USER_UPDATED,
                principal == null || principal.subjectId() == null ? null : principal.subjectId().toString(),
                principal == null ? null : principal.username(),
                principal == null ? null : principal.tenantId(),
                "identity-mapping",
                subjectId,
                AdminAuthenticationService.clientIp(request),
                request.getHeader(HttpHeaders.USER_AGENT),
                true,
                detail);
    }
}
