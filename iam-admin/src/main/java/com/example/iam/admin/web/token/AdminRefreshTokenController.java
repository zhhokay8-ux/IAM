package com.example.iam.admin.web.token;

import com.example.iam.admin.rbac.AdminPermissions;
import com.example.iam.admin.security.AdminAuthenticationService;
import com.example.iam.admin.security.AdminPrincipal;
import com.example.iam.admin.security.AdminPrincipalHolder;
import com.example.iam.admin.security.RequireAdminPermission;
import com.example.iam.admin.web.client.AdminPageResponse;
import com.example.iam.audit.AuditEvent;
import com.example.iam.audit.IamAuditService;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin/refresh-tokens")
public class AdminRefreshTokenController {

    private final AdminRefreshTokenService refreshTokenService;
    private final IamAuditService auditService;

    public AdminRefreshTokenController(AdminRefreshTokenService refreshTokenService, IamAuditService auditService) {
        this.refreshTokenService = refreshTokenService;
        this.auditService = auditService;
    }

    @GetMapping
    @RequireAdminPermission(AdminPermissions.TOKEN_READ)
    public AdminPageResponse<AdminRefreshTokenResponse> list(
            @RequestParam(name = "subject_id", required = false) UUID subjectId,
            @RequestParam(name = "family_id", required = false) UUID familyId,
            @RequestParam(name = "page", defaultValue = "0") int page,
            @RequestParam(name = "size", defaultValue = "20") int size) {
        List<AdminRefreshTokenResponse> all;
        if (subjectId != null) {
            all = refreshTokenService.listByJwtSubject(subjectId);
        } else if (familyId != null) {
            all = refreshTokenService.listByFamily(familyId);
        } else {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "subject_id or family_id is required");
        }
        return pageOf(all, page, size);
    }

    @GetMapping("/{id}")
    @RequireAdminPermission(AdminPermissions.TOKEN_READ)
    public AdminRefreshTokenResponse get(@PathVariable("id") UUID id) {
        return refreshTokenService.get(id);
    }

    @PostMapping("/{id}/revoke")
    @RequireAdminPermission(AdminPermissions.TOKEN_REVOKE)
    public AdminRefreshTokenResponse revoke(@PathVariable("id") UUID id, HttpServletRequest http) {
        AdminRefreshTokenResponse response = refreshTokenService.revokeById(id);
        audit(http, id.toString(), "admin_revoke_refresh_family; id=" + id + "; family_id=" + response.familyId());
        return response;
    }

    @PostMapping("/families/{familyId}/revoke")
    @RequireAdminPermission(AdminPermissions.TOKEN_REVOKE)
    public void revokeFamily(@PathVariable("familyId") UUID familyId, HttpServletRequest http) {
        refreshTokenService.revokeFamily(familyId);
        audit(http, familyId.toString(), "admin_revoke_refresh_family; family_id=" + familyId);
    }

    @PostMapping("/by-subject/{subjectId}/revoke")
    @RequireAdminPermission(AdminPermissions.TOKEN_REVOKE)
    public void revokeBySubject(@PathVariable("subjectId") UUID subjectId, HttpServletRequest http) {
        refreshTokenService.revokeByJwtSubject(subjectId);
        audit(http, subjectId.toString(), "admin_revoke_refresh_by_subject; subject_id=" + subjectId);
    }

    private void audit(HttpServletRequest request, String resourceId, String detail) {
        AdminPrincipal principal = AdminPrincipalHolder.get(request);
        auditService.recordAdmin(
                AuditEvent.TOKEN_REVOKED,
                principal == null || principal.subjectId() == null ? null : principal.subjectId().toString(),
                principal == null ? null : principal.username(),
                principal == null ? null : principal.tenantId(),
                "refresh_token",
                resourceId,
                AdminAuthenticationService.clientIp(request),
                request.getHeader(HttpHeaders.USER_AGENT),
                true,
                detail);
    }

    private static <T> AdminPageResponse<T> pageOf(List<T> all, int page, int size) {
        int safePage = Math.max(page, 0);
        int safeSize = Math.min(Math.max(size, 1), 100);
        int from = Math.min(safePage * safeSize, all.size());
        int to = Math.min(from + safeSize, all.size());
        return new AdminPageResponse<>(all.subList(from, to), safePage, safeSize, all.size());
    }
}
