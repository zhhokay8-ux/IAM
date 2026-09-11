package com.example.iam.admin.web.key;

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
import com.example.iam.token.signing.KeyMetadata;
import com.example.iam.token.signing.SigningKeyRotationService;
import com.example.iam.token.signing.SigningKeyService;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin/signing-keys")
public class AdminSigningKeyController {

    private final SigningKeyService signingKeyService;
    private final SigningKeyRotationService rotationService;
    private final IamAuditService auditService;

    public AdminSigningKeyController(
            SigningKeyService signingKeyService,
            SigningKeyRotationService rotationService,
            IamAuditService auditService) {
        this.signingKeyService = signingKeyService;
        this.rotationService = rotationService;
        this.auditService = auditService;
    }

    @GetMapping
    @RequireAdminPermission(AdminPermissions.KEY_READ)
    public AdminPageResponse<AdminSigningKeyResponse> list(
            @RequestParam(name = "page", defaultValue = "0") int page,
            @RequestParam(name = "size", defaultValue = "20") int size) {
        List<AdminSigningKeyResponse> all =
                signingKeyService.listAll().stream().map(AdminSigningKeyResponse::from).toList();
        int safePage = Math.max(page, 0);
        int safeSize = Math.min(Math.max(size, 1), 100);
        int from = Math.min(safePage * safeSize, all.size());
        int to = Math.min(from + safeSize, all.size());
        return new AdminPageResponse<>(all.subList(from, to), safePage, safeSize, all.size());
    }

    @GetMapping("/active")
    @RequireAdminPermission(AdminPermissions.KEY_READ)
    public AdminSigningKeyResponse active() {
        return AdminSigningKeyResponse.from(signingKeyService.getActiveKey());
    }

    @GetMapping("/{kid}")
    @RequireAdminPermission(AdminPermissions.KEY_READ)
    public AdminSigningKeyResponse get(@PathVariable("kid") String kid) {
        return AdminSigningKeyResponse.from(signingKeyService.getByKid(kid));
    }

    @PostMapping("/rotate")
    @RequireAdminPermission(AdminPermissions.KEY_ROTATE)
    public AdminSigningKeyResponse rotate(@RequestBody(required = false) AdminConfirmRotateRequest request, HttpServletRequest http) {
        if (request == null || !Boolean.TRUE.equals(request.confirm())) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "confirm=true is required to rotate signing keys");
        }
        KeyMetadata rotated = rotationService.rotate();
        AdminPrincipal principal = AdminPrincipalHolder.get(http);
        auditService.recordAdmin(
                AuditEvent.SIGNING_KEY_ROTATED,
                principal == null || principal.subjectId() == null ? null : principal.subjectId().toString(),
                principal == null ? null : principal.username(),
                principal == null ? null : principal.tenantId(),
                "signing_key",
                rotated.kid(),
                AdminAuthenticationService.clientIp(http),
                http.getHeader(HttpHeaders.USER_AGENT),
                true,
                "admin_rotate_signing_key; kid=" + rotated.kid());
        return AdminSigningKeyResponse.from(rotated);
    }
}
