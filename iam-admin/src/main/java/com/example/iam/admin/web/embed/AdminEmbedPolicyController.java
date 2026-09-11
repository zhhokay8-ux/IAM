package com.example.iam.admin.web.embed;

import com.example.iam.admin.rbac.AdminPermissions;
import com.example.iam.admin.security.AdminAuthenticationService;
import com.example.iam.admin.security.AdminPrincipal;
import com.example.iam.admin.security.AdminPrincipalHolder;
import com.example.iam.admin.security.RequireAdminPermission;
import com.example.iam.admin.web.client.AdminPageResponse;
import com.example.iam.audit.AuditEvent;
import com.example.iam.audit.IamAuditService;
import com.example.iam.embed.EmbedPolicyService;
import com.example.iam.embed.EmbedPolicyView;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.UUID;
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
@RequestMapping("/api/admin/embed-policies")
public class AdminEmbedPolicyController {

    private final EmbedPolicyService embedPolicyService;
    private final IamAuditService auditService;

    public AdminEmbedPolicyController(EmbedPolicyService embedPolicyService, IamAuditService auditService) {
        this.embedPolicyService = embedPolicyService;
        this.auditService = auditService;
    }

    @GetMapping
    @RequireAdminPermission(AdminPermissions.EMBED_READ)
    public AdminPageResponse<EmbedPolicyView> list(
            @RequestParam(name = "parent_client_id", required = false) String parentClientId,
            @RequestParam(name = "child_client_id", required = false) String childClientId,
            @RequestParam(name = "page", defaultValue = "0") int page,
            @RequestParam(name = "size", defaultValue = "20") int size) {
        List<EmbedPolicyView> all = embedPolicyService.list(parentClientId, childClientId);
        int safePage = Math.max(page, 0);
        int safeSize = Math.min(Math.max(size, 1), 100);
        int from = Math.min(safePage * safeSize, all.size());
        int to = Math.min(from + safeSize, all.size());
        return new AdminPageResponse<>(all.subList(from, to), safePage, safeSize, all.size());
    }

    @GetMapping("/{id}")
    @RequireAdminPermission(AdminPermissions.EMBED_READ)
    public EmbedPolicyView get(@PathVariable("id") UUID id) {
        return embedPolicyService.get(id);
    }

    @PostMapping
    @RequireAdminPermission(AdminPermissions.EMBED_WRITE)
    public EmbedPolicyView create(@RequestBody AdminEmbedPolicyRequest request, HttpServletRequest http) {
        EmbedPolicyView created = embedPolicyService.create(
                request.parentClientId(), request.childClientId(), request.parentOrigin(), request.allowedPath());
        audit(http, created.id().toString(), "admin_create_embed_policy; parent=" + created.parentClientId()
                + "; child=" + created.childClientId());
        return created;
    }

    @PutMapping("/{id}")
    @RequireAdminPermission(AdminPermissions.EMBED_WRITE)
    public EmbedPolicyView update(
            @PathVariable("id") UUID id, @RequestBody AdminEmbedPolicyRequest request, HttpServletRequest http) {
        EmbedPolicyView updated = embedPolicyService.update(id, request.parentOrigin(), request.allowedPath());
        audit(http, id.toString(), "admin_update_embed_policy");
        return updated;
    }

    @PostMapping("/{id}/enable")
    @RequireAdminPermission(AdminPermissions.EMBED_WRITE)
    public EmbedPolicyView enable(@PathVariable("id") UUID id, HttpServletRequest http) {
        EmbedPolicyView response = embedPolicyService.enable(id);
        audit(http, id.toString(), "admin_enable_embed_policy");
        return response;
    }

    @PostMapping("/{id}/disable")
    @RequireAdminPermission(AdminPermissions.EMBED_WRITE)
    public EmbedPolicyView disable(@PathVariable("id") UUID id, HttpServletRequest http) {
        EmbedPolicyView response = embedPolicyService.disable(id);
        audit(http, id.toString(), "admin_disable_embed_policy");
        return response;
    }

    private void audit(HttpServletRequest request, String resourceId, String detail) {
        AdminPrincipal principal = AdminPrincipalHolder.get(request);
        auditService.recordAdmin(
                AuditEvent.EMBED_POLICY_CHANGED,
                principal == null || principal.subjectId() == null ? null : principal.subjectId().toString(),
                principal == null ? null : principal.username(),
                principal == null ? null : principal.tenantId(),
                "embed_policy",
                resourceId,
                AdminAuthenticationService.clientIp(request),
                request.getHeader(HttpHeaders.USER_AGENT),
                true,
                detail);
    }
}
