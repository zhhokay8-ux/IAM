package com.example.iam.admin.web.client;

import com.example.iam.admin.rbac.AdminPermissions;
import com.example.iam.admin.security.AdminPrincipal;
import com.example.iam.admin.security.AdminPrincipalHolder;
import com.example.iam.admin.security.AdminAuthenticationService;
import com.example.iam.admin.security.RequireAdminPermission;
import com.example.iam.audit.AuditEvent;
import com.example.iam.audit.IamAuditService;
import com.example.iam.clientregistry.domain.ClientType;
import com.example.iam.clientregistry.domain.RegistryStatus;
import com.example.iam.clientregistry.dto.ClientResponse;
import com.example.iam.clientregistry.dto.CreateClientRequest;
import com.example.iam.clientregistry.dto.PermissionResponse;
import com.example.iam.clientregistry.dto.RedirectUriInput;
import com.example.iam.clientregistry.dto.RotatedSecretResponse;
import com.example.iam.clientregistry.dto.UpdateClientRequest;
import com.example.iam.clientregistry.service.IamClientService;
import com.example.iam.clientregistry.service.IamPermissionService;
import com.example.iam.clientregistry.service.impl.IamClientServiceImpl;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
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
@RequestMapping("/api/admin/clients")
public class AdminClientController {

    private final IamClientService clientService;
    private final IamPermissionService permissionService;
    private final IamAuditService auditService;

    public AdminClientController(
            IamClientService clientService, IamPermissionService permissionService, IamAuditService auditService) {
        this.clientService = clientService;
        this.permissionService = permissionService;
        this.auditService = auditService;
    }

    @GetMapping
    @RequireAdminPermission(AdminPermissions.CLIENT_READ)
    public AdminPageResponse<ClientResponse> list(
            @RequestParam(name = "q", required = false) String query,
            @RequestParam(name = "status", required = false) String status,
            @RequestParam(name = "page", defaultValue = "0") int page,
            @RequestParam(name = "size", defaultValue = "20") int size) {
        int safeSize = Math.min(Math.max(size, 1), 100);
        int safePage = Math.max(page, 0);
        Page<ClientResponse> result = clientService.search(query, status, PageRequest.of(safePage, safeSize));
        return new AdminPageResponse<>(result.getContent(), result.getNumber(), result.getSize(), result.getTotalElements());
    }

    @GetMapping("/{clientId}")
    @RequireAdminPermission(AdminPermissions.CLIENT_READ)
    public ClientResponse get(@PathVariable String clientId) {
        return clientService.get(clientId);
    }

    @PostMapping
    @RequireAdminPermission(AdminPermissions.CLIENT_WRITE)
    public RotatedSecretResponse create(@RequestBody AdminCreateClientRequest request, HttpServletRequest http) {
        String status = RegistryStatus.INACTIVE;
        String type = request.clientType() == null ? ClientType.CONFIDENTIAL : request.clientType();
        String secret = ClientType.PUBLIC.equalsIgnoreCase(type) ? null : IamClientServiceImpl.generateSecret();
        ClientResponse created = clientService.create(new CreateClientRequest(
                request.clientId(),
                request.clientName(),
                type,
                status,
                request.tokenEndpointAuthMethod(),
                request.accessTokenTtl() == null ? 600 : request.accessTokenTtl(),
                request.refreshTokenTtl() == null ? 86400 : request.refreshTokenTtl(),
                request.pkceRequired() == null || request.pkceRequired(),
                request.owner(),
                request.redirectUris(),
                secret));
        audit(http, AuditEvent.CLIENT_CREATED, created.clientId(), true, "admin_create_client");
        return new RotatedSecretResponse(created, secret);
    }

    @PutMapping("/{clientId}")
    @RequireAdminPermission(AdminPermissions.CLIENT_WRITE)
    public ClientResponse update(
            @PathVariable String clientId, @RequestBody AdminUpdateClientRequest request, HttpServletRequest http) {
        ClientResponse updated = clientService.update(
                clientId,
                new UpdateClientRequest(
                        request.clientName(),
                        null,
                        request.tokenEndpointAuthMethod(),
                        request.accessTokenTtl(),
                        request.refreshTokenTtl(),
                        request.pkceRequired(),
                        request.owner(),
                        request.redirectUris()));
        audit(http, AuditEvent.CLIENT_UPDATED, clientId, true, "admin_update_client");
        return updated;
    }

    @PostMapping("/{clientId}/disable")
    @RequireAdminPermission(AdminPermissions.CLIENT_WRITE)
    public ClientResponse disable(@PathVariable("clientId") String clientId, HttpServletRequest http) {
        ClientResponse response = clientService.disable(clientId);
        audit(http, AuditEvent.CLIENT_DISABLED, clientId, true, "admin_disable_client; client_id=" + clientId);
        return response;
    }

    @PostMapping("/{clientId}/enable")
    @RequireAdminPermission(AdminPermissions.CLIENT_WRITE)
    public ClientResponse enable(@PathVariable String clientId, HttpServletRequest http) {
        ClientResponse response = clientService.enable(clientId);
        audit(http, AuditEvent.CLIENT_ENABLED, clientId, true, "admin_enable_client");
        return response;
    }

    @PostMapping("/{clientId}/rotate-secret")
    @RequireAdminPermission(AdminPermissions.CLIENT_WRITE)
    public RotatedSecretResponse rotateSecret(@PathVariable String clientId, HttpServletRequest http) {
        RotatedSecretResponse rotated = clientService.rotateSecret(clientId);
        audit(http, AuditEvent.SECRET_ROTATED, clientId, true, "admin_rotate_secret");
        return rotated;
    }

    @PutMapping("/{clientId}/redirect-uris")
    @RequireAdminPermission(AdminPermissions.CLIENT_WRITE)
    public ClientResponse replaceRedirectUris(
            @PathVariable String clientId, @RequestBody List<RedirectUriInput> redirectUris, HttpServletRequest http) {
        ClientResponse response = clientService.replaceRedirectUris(clientId, redirectUris);
        audit(http, AuditEvent.CLIENT_UPDATED, clientId, true, "admin_replace_redirect_uris");
        return response;
    }

    @GetMapping("/{clientId}/permissions")
    @RequireAdminPermission(AdminPermissions.CLIENT_READ)
    public List<PermissionResponse> permissions(@PathVariable String clientId) {
        return permissionService.listByClientId(clientId);
    }

    private void audit(HttpServletRequest request, AuditEvent event, String clientId, boolean success, String detail) {
        AdminPrincipal principal = AdminPrincipalHolder.get(request);
        auditService.recordAdmin(
                event,
                principal == null || principal.subjectId() == null ? null : principal.subjectId().toString(),
                principal == null ? null : principal.username(),
                principal == null ? null : principal.tenantId(),
                "client",
                clientId,
                AdminAuthenticationService.clientIp(request),
                request.getHeader(HttpHeaders.USER_AGENT),
                success,
                detail);
    }
}
