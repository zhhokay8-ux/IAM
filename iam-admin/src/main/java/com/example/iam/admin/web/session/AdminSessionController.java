package com.example.iam.admin.web.session;

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
import com.example.iam.session.IamSession;
import com.example.iam.session.IamSessionService;
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
@RequestMapping("/api/admin/sessions")
public class AdminSessionController {

    private final IamSessionService sessionService;
    private final IamAuditService auditService;

    public AdminSessionController(IamSessionService sessionService, IamAuditService auditService) {
        this.sessionService = sessionService;
        this.auditService = auditService;
    }

    @GetMapping
    @RequireAdminPermission(AdminPermissions.SESSION_READ)
    public AdminPageResponse<AdminSessionResponse> listBySubject(
            @RequestParam(name = "subject_id") String subjectId,
            @RequestParam(name = "page", defaultValue = "0") int page,
            @RequestParam(name = "size", defaultValue = "20") int size) {
        if (subjectId == null || subjectId.isBlank()) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "subject_id is required");
        }
        List<AdminSessionResponse> all = sessionService.listBySubject(subjectId).stream()
                .map(AdminSessionResponse::from)
                .toList();
        return pageOf(all, page, size);
    }

    @GetMapping("/{sid}")
    @RequireAdminPermission(AdminPermissions.SESSION_READ)
    public AdminSessionResponse get(@PathVariable("sid") String sid) {
        IamSession session = sessionService
                .inspect(sid)
                .orElseThrow(() -> new IamException(IamErrorCode.NOT_FOUND, "SSO session not found"));
        return AdminSessionResponse.from(session);
    }

    @PostMapping("/{sid}/revoke")
    @RequireAdminPermission(AdminPermissions.SESSION_REVOKE)
    public AdminSessionResponse revoke(@PathVariable("sid") String sid, HttpServletRequest http) {
        sessionService.revoke(sid);
        IamSession session = sessionService
                .inspect(sid)
                .orElseThrow(() -> new IamException(IamErrorCode.NOT_FOUND, "SSO session not found"));
        audit(http, AuditEvent.SESSION_REVOKED, session.subjectId(), sid, "admin_revoke_session; sid=" + sid);
        return AdminSessionResponse.from(session);
    }

    @PostMapping("/{sid}/expire")
    @RequireAdminPermission(AdminPermissions.SESSION_REVOKE)
    public AdminSessionResponse expire(@PathVariable("sid") String sid, HttpServletRequest http) {
        sessionService.expire(sid);
        IamSession session = sessionService
                .inspect(sid)
                .orElseThrow(() -> new IamException(IamErrorCode.NOT_FOUND, "SSO session not found"));
        audit(http, AuditEvent.SESSION_EXPIRED, session.subjectId(), sid, "admin_expire_session; sid=" + sid);
        return AdminSessionResponse.from(session);
    }

    @PostMapping("/by-subject/{subjectId}/revoke")
    @RequireAdminPermission(AdminPermissions.SESSION_REVOKE)
    public void revokeBySubject(@PathVariable("subjectId") UUID subjectId, HttpServletRequest http) {
        sessionService.revokeAllForSubject(subjectId.toString());
        audit(
                http,
                AuditEvent.SESSION_REVOKED,
                subjectId.toString(),
                subjectId.toString(),
                "admin_revoke_sessions_by_subject; subject_id=" + subjectId);
    }

    private void audit(HttpServletRequest request, AuditEvent event, String subjectId, String resourceId, String detail) {
        AdminPrincipal principal = AdminPrincipalHolder.get(request);
        auditService.recordAdmin(
                event,
                principal == null || principal.subjectId() == null ? null : principal.subjectId().toString(),
                principal == null ? null : principal.username(),
                principal == null ? null : principal.tenantId(),
                "session",
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
