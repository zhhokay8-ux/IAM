package com.example.iam.authorizationserver.admin.auth;

import com.example.iam.admin.config.IamAdminProperties;
import com.example.iam.clientregistry.domain.RegistryStatus;
import com.example.iam.clientregistry.dto.CreateClientRequest;
import com.example.iam.clientregistry.dto.CreatePermissionRequest;
import com.example.iam.clientregistry.dto.CreateResourceRequest;
import com.example.iam.clientregistry.dto.CreateScopeRequest;
import com.example.iam.clientregistry.dto.RedirectUriInput;
import com.example.iam.clientregistry.service.IamClientService;
import com.example.iam.clientregistry.service.IamPermissionService;
import com.example.iam.clientregistry.service.IamResourceService;
import com.example.iam.clientregistry.service.IamScopeService;
import com.example.iam.clientregistry.validation.IamRedirectUriValidator;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
@Order(200)
public class AdminClientBootstrap implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(AdminClientBootstrap.class);

    private final IamAdminProperties properties;
    private final IamRedirectUriValidator redirectUriValidator;
    private final IamClientService clientService;
    private final IamResourceService resourceService;
    private final IamScopeService scopeService;
    private final IamPermissionService permissionService;

    public AdminClientBootstrap(
            IamAdminProperties properties,
            IamRedirectUriValidator redirectUriValidator,
            IamClientService clientService,
            IamResourceService resourceService,
            IamScopeService scopeService,
            IamPermissionService permissionService) {
        this.properties = properties;
        this.redirectUriValidator = redirectUriValidator;
        this.clientService = clientService;
        this.resourceService = resourceService;
        this.scopeService = scopeService;
        this.permissionService = permissionService;
    }

    @Override
    public void run(ApplicationArguments args) {
        IamAdminProperties.OAuth oauth = properties.getOauth();
        if (!StringUtils.hasText(oauth.getClientSecret())) {
            log.warn(
                    "iam.admin.oauth.client-secret is empty; confidential Admin BFF client will not be bootstrapped. DEVELOPMENT ONLY SSO remains at POST /sso/login (no password).");
            return;
        }
        redirectUriValidator.validateSyntax(oauth.getRedirectUri());
        ensureClient(oauth);
        ensureResource(oauth);
        ensureScope(oauth);
        ensurePermission(oauth);
        log.warn(
                "Admin client '{}' bootstrapped as confidential + PKCE BFF. Browser must not receive client_secret or tokens. POST /sso/login is DEVELOPMENT ONLY and is not production-grade admin authentication.",
                oauth.getClientId());
    }

    private void ensureClient(IamAdminProperties.OAuth oauth) {
        try {
            var existing = clientService.get(oauth.getClientId());
            boolean registered = existing.redirectUris() != null
                    && existing.redirectUris().stream()
                            .anyMatch(uri -> oauth.getRedirectUri().equals(uri.redirectUri()));
            if (!registered) {
                ArrayList<RedirectUriInput> uris = new ArrayList<>();
                if (existing.redirectUris() != null) {
                    uris.addAll(existing.redirectUris());
                }
                uris.add(new RedirectUriInput(oauth.getRedirectUri(), "LOGIN_CALLBACK"));
                clientService.replaceRedirectUris(oauth.getClientId(), uris);
            }
        } catch (IamException ex) {
            if (ex.getErrorCode() != IamErrorCode.CLIENT_NOT_FOUND) {
                throw ex;
            }
            clientService.create(new CreateClientRequest(
                    oauth.getClientId(),
                    "IAM Admin Console",
                    "confidential",
                    RegistryStatus.ACTIVE,
                    "client_secret_basic",
                    600,
                    86400,
                    true,
                    "iam",
                    List.of(new RedirectUriInput(oauth.getRedirectUri(), "LOGIN_CALLBACK")),
                    oauth.getClientSecret()));
        }
    }

    private void ensureResource(IamAdminProperties.OAuth oauth) {
        try {
            resourceService.get(oauth.getResourceCode());
        } catch (IamException ex) {
            if (ex.getErrorCode() != IamErrorCode.RESOURCE_NOT_FOUND) {
                throw ex;
            }
            resourceService.create(new CreateResourceRequest(
                    oauth.getResourceCode(),
                    "IAM Admin",
                    oauth.getAudience(),
                    RegistryStatus.ACTIVE,
                    "iam"));
        }
    }

    private void ensureScope(IamAdminProperties.OAuth oauth) {
        try {
            scopeService.get(oauth.getResourceCode(), oauth.getScope());
        } catch (IamException ex) {
            if (ex.getErrorCode() != IamErrorCode.SCOPE_NOT_FOUND && ex.getErrorCode() != IamErrorCode.SCOPE_NOT_BOUND) {
                throw ex;
            }
            scopeService.create(new CreateScopeRequest(
                    oauth.getResourceCode(), oauth.getScope(), "OpenID", "openid", RegistryStatus.ACTIVE));
        }
    }

    private void ensurePermission(IamAdminProperties.OAuth oauth) {
        try {
            permissionService.get(oauth.getClientId(), oauth.getResourceCode(), oauth.getScope(), "authorization_code");
        } catch (IamException ex) {
            if (ex.getErrorCode() != IamErrorCode.PERMISSION_DENIED) {
                throw ex;
            }
            permissionService.create(new CreatePermissionRequest(
                    oauth.getClientId(),
                    oauth.getResourceCode(),
                    oauth.getScope(),
                    "authorization_code",
                    RegistryStatus.ACTIVE));
        }
    }
}
