package com.example.iam.admin.web.exchange;

import com.example.iam.admin.rbac.AdminPermissions;
import com.example.iam.admin.security.AdminAuthenticationService;
import com.example.iam.admin.security.AdminPrincipal;
import com.example.iam.admin.security.AdminPrincipalHolder;
import com.example.iam.admin.security.RequireAdminPermission;
import com.example.iam.admin.web.client.AdminPageResponse;
import com.example.iam.admin.web.permission.AdminCreatePermissionRequest;
import com.example.iam.admin.web.permission.AdminPermissionKeyRequest;
import com.example.iam.audit.AuditEvent;
import com.example.iam.audit.IamAuditService;
import com.example.iam.clientregistry.domain.GrantType;
import com.example.iam.clientregistry.domain.RegistryStatus;
import com.example.iam.clientregistry.dto.CreatePermissionRequest;
import com.example.iam.clientregistry.dto.PermissionResponse;
import com.example.iam.clientregistry.service.IamPermissionService;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
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
@RequestMapping("/api/admin/token-exchange/permissions")
public class AdminTokenExchangeController {

    private final IamPermissionService permissionService;
    private final IamAuditService auditService;

    public AdminTokenExchangeController(IamPermissionService permissionService, IamAuditService auditService) {
        this.permissionService = permissionService;
        this.auditService = auditService;
    }

    @GetMapping
    @RequireAdminPermission(AdminPermissions.POLICY_READ)
    public AdminPageResponse<PermissionResponse> list(
            @RequestParam(name = "client_id", required = false) String clientId,
            @RequestParam(name = "resource_code", required = false) String resourceCode,
            @RequestParam(name = "status", required = false) String status,
            @RequestParam(name = "page", defaultValue = "0") int page,
            @RequestParam(name = "size", defaultValue = "20") int size) {
        Page<PermissionResponse> result = permissionService.search(
                clientId,
                resourceCode,
                GrantType.TOKEN_EXCHANGE.name(),
                status,
                PageRequest.of(Math.max(page, 0), Math.min(Math.max(size, 1), 100)));
        return new AdminPageResponse<>(result.getContent(), result.getNumber(), result.getSize(), result.getTotalElements());
    }

    @PostMapping
    @RequireAdminPermission(AdminPermissions.POLICY_WRITE)
    public PermissionResponse create(@RequestBody AdminCreatePermissionRequest request, HttpServletRequest http) {
        requireTokenExchange(request.grantType());
        PermissionResponse created = permissionService.create(new CreatePermissionRequest(
                request.clientId(),
                request.resourceCode(),
                request.scopeCode(),
                GrantType.TOKEN_EXCHANGE.name(),
                RegistryStatus.INACTIVE));
        audit(http, created, "admin_create_token_exchange_permission");
        return created;
    }

    @PostMapping("/disable")
    @RequireAdminPermission(AdminPermissions.POLICY_WRITE)
    public PermissionResponse disable(@RequestBody AdminPermissionKeyRequest request, HttpServletRequest http) {
        requireTokenExchange(request.grantType());
        PermissionResponse response = permissionService.disable(
                request.clientId(),
                request.resourceCode(),
                request.scopeCode(),
                GrantType.TOKEN_EXCHANGE.name());
        audit(http, response, "admin_disable_token_exchange_permission");
        return response;
    }

    @PostMapping("/enable")
    @RequireAdminPermission(AdminPermissions.POLICY_WRITE)
    public PermissionResponse enable(@RequestBody AdminPermissionKeyRequest request, HttpServletRequest http) {
        requireTokenExchange(request.grantType());
        PermissionResponse response = permissionService.enable(
                request.clientId(),
                request.resourceCode(),
                request.scopeCode(),
                GrantType.TOKEN_EXCHANGE.name());
        audit(http, response, "admin_enable_token_exchange_permission");
        return response;
    }

    private static void requireTokenExchange(String grantType) {
        if (grantType != null && !grantType.isBlank() && GrantType.from(grantType) != GrantType.TOKEN_EXCHANGE) {
            throw new IamException(IamErrorCode.INVALID_GRANT_TYPE, "this API only manages TOKEN_EXCHANGE");
        }
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
