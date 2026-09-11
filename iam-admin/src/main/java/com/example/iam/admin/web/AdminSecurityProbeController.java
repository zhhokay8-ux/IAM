package com.example.iam.admin.web;

import com.example.iam.admin.rbac.AdminPermissions;
import com.example.iam.admin.security.AdminPrincipal;
import com.example.iam.admin.security.AdminPrincipalHolder;
import com.example.iam.admin.security.RequireAdminPermission;
import com.example.iam.audit.AuditEvent;
import com.example.iam.audit.IamAuditService;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin/security")
public class AdminSecurityProbeController {

    private final IamAuditService auditService;

    public AdminSecurityProbeController(IamAuditService auditService) {
        this.auditService = auditService;
    }

    @GetMapping("/read-probe")
    @RequireAdminPermission(AdminPermissions.AUDIT_READ)
    public Map<String, String> readProbe() {
        return Map.of("status", "ok", "permission", AdminPermissions.AUDIT_READ);
    }

    @PostMapping("/write-probe")
    @RequireAdminPermission(AdminPermissions.CLIENT_WRITE)
    public Map<String, String> writeProbe(HttpServletRequest request) {
        AdminPrincipal principal = AdminPrincipalHolder.get(request);
        auditService.recordAdmin(
                AuditEvent.ADMIN_WRITE,
                principal.subjectId().toString(),
                principal.username(),
                principal.tenantId(),
                "client",
                "write-probe",
                request.getRemoteAddr(),
                request.getHeader(HttpHeaders.USER_AGENT),
                true,
                "phase1_security_probe");
        return Map.of("status", "ok", "permission", AdminPermissions.CLIENT_WRITE);
    }

    @PostMapping("/token-revoke-probe")
    @RequireAdminPermission(AdminPermissions.TOKEN_REVOKE)
    public Map<String, String> tokenRevokeProbe(HttpServletRequest request) {
        AdminPrincipal principal = AdminPrincipalHolder.get(request);
        auditService.recordAdmin(
                AuditEvent.ADMIN_WRITE,
                principal.subjectId().toString(),
                principal.username(),
                principal.tenantId(),
                "token",
                "token-revoke-probe",
                request.getRemoteAddr(),
                request.getHeader(HttpHeaders.USER_AGENT),
                true,
                "phase1_operator_probe");
        return Map.of("status", "ok", "permission", AdminPermissions.TOKEN_REVOKE);
    }
}
