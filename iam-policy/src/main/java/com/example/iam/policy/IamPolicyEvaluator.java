package com.example.iam.policy;

import com.example.iam.clientregistry.domain.GrantType;
import com.example.iam.clientregistry.domain.RedirectUriType;
import com.example.iam.clientregistry.domain.RegistryStatus;
import com.example.iam.clientregistry.entity.IamClientEntity;
import com.example.iam.clientregistry.entity.IamClientRedirectUriEntity;
import com.example.iam.clientregistry.entity.IamClientResourcePermissionEntity;
import com.example.iam.clientregistry.entity.IamResourceServerEntity;
import com.example.iam.clientregistry.entity.IamScopeEntity;
import com.example.iam.clientregistry.repository.IamClientRedirectUriRepository;
import com.example.iam.clientregistry.repository.IamClientRepository;
import com.example.iam.clientregistry.repository.IamClientResourcePermissionRepository;
import com.example.iam.clientregistry.repository.IamResourceServerRepository;
import com.example.iam.clientregistry.repository.IamScopeRepository;
import com.example.iam.clientregistry.validation.IamClientValidator;
import com.example.iam.clientregistry.validation.IamOriginValidator;
import com.example.iam.clientregistry.validation.IamRedirectUriValidator;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import java.util.List;
import org.springframework.stereotype.Component;

@Component
public class IamPolicyEvaluator {

    private final IamClientRepository clientRepository;
    private final IamClientRedirectUriRepository redirectUriRepository;
    private final IamResourceServerRepository resourceRepository;
    private final IamScopeRepository scopeRepository;
    private final IamClientResourcePermissionRepository permissionRepository;
    private final IamClientValidator clientValidator;
    private final IamRedirectUriValidator redirectUriValidator;
    private final IamOriginValidator originValidator;

    public IamPolicyEvaluator(
            IamClientRepository clientRepository,
            IamClientRedirectUriRepository redirectUriRepository,
            IamResourceServerRepository resourceRepository,
            IamScopeRepository scopeRepository,
            IamClientResourcePermissionRepository permissionRepository,
            IamClientValidator clientValidator,
            IamRedirectUriValidator redirectUriValidator,
            IamOriginValidator originValidator) {
        this.clientRepository = clientRepository;
        this.redirectUriRepository = redirectUriRepository;
        this.resourceRepository = resourceRepository;
        this.scopeRepository = scopeRepository;
        this.permissionRepository = permissionRepository;
        this.clientValidator = clientValidator;
        this.redirectUriValidator = redirectUriValidator;
        this.originValidator = originValidator;
    }

    public IamClientEntity validateClient(String clientId) {
        return clientValidator.validateClient(clientRepository.findByClientId(clientId), clientId);
    }

    public void validateRedirectUri(String clientId, String redirectUri) {
        IamClientEntity client = validateClient(clientId);
        List<String> registered = redirectUriRepository.findByClientId(client.getId()).stream()
                .filter(uri -> RegistryStatus.isActive(uri.getStatus()))
                .filter(uri -> RedirectUriType.LOGIN_CALLBACK.equalsIgnoreCase(uri.getUriType()))
                .map(IamClientRedirectUriEntity::getRedirectUri)
                .toList();
        redirectUriValidator.validateRedirectUri(redirectUri, registered);
    }

    public void validateOrigin(String origin, List<String> allowedOrigins) {
        originValidator.validateOrigin(origin, allowedOrigins);
    }

    public IamResourceServerEntity validateAudience(String audience) {
        if (audience == null || audience.isBlank()) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "audience is required");
        }
        IamResourceServerEntity resource = resourceRepository.findByAudience(audience)
                .orElseThrow(() -> new IamException(IamErrorCode.AUDIENCE_NOT_FOUND, "audience not found: " + audience));
        if (!RegistryStatus.isActive(resource.getStatus())) {
            throw new IamException(IamErrorCode.FORBIDDEN, "resource is disabled: " + resource.getResourceCode());
        }
        return resource;
    }

    public IamScopeEntity validateScope(String audience, String scopeCode) {
        IamResourceServerEntity resource = validateAudience(audience);
        if (scopeCode == null || scopeCode.isBlank()) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "scope is required");
        }
        IamScopeEntity scope = scopeRepository.findByResourceIdAndScopeCode(resource.getId(), scopeCode)
                .orElseGet(() -> {
                    if (scopeRepository.findByScopeCode(scopeCode).isEmpty()) {
                        throw new IamException(IamErrorCode.SCOPE_NOT_FOUND, "scope not found: " + scopeCode);
                    }
                    throw new IamException(
                            IamErrorCode.SCOPE_NOT_BOUND, "scope is not bound to audience " + audience);
                });
        if (!RegistryStatus.isActive(scope.getStatus())) {
            throw new IamException(IamErrorCode.SCOPE_INACTIVE, "scope is disabled: " + scopeCode);
        }
        return scope;
    }

    public void validateTokenExchangePermission(String clientId, String audience, String scopeCode) {
        validateGrantPermission(clientId, audience, scopeCode, GrantType.TOKEN_EXCHANGE);
    }

    public void validateClientCredentialsPermission(String clientId, String audience, String scopeCode) {
        validateGrantPermission(clientId, audience, scopeCode, GrantType.CLIENT_CREDENTIALS);
    }

    public void validateAuthorizationCodePermission(String clientId, String audience, String scopeCode) {
        validateGrantPermission(clientId, audience, scopeCode, GrantType.AUTHORIZATION_CODE);
    }

    public List<String> resolveAudiences(String clientId, List<String> scopes, GrantType grantType) {
        IamClientEntity client = validateClient(clientId);
        if (scopes == null || scopes.isEmpty()) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "scope is required");
        }
        java.util.LinkedHashSet<String> audiences = new java.util.LinkedHashSet<>();
        for (String scopeCode : scopes) {
            List<IamScopeEntity> matches = scopeRepository.findByScopeCode(scopeCode);
            for (IamScopeEntity scope : matches) {
                if (!RegistryStatus.isActive(scope.getStatus())) {
                    continue;
                }
                IamResourceServerEntity resource = resourceRepository.findById(scope.getResourceId()).orElse(null);
                if (resource == null || !RegistryStatus.isActive(resource.getStatus())) {
                    continue;
                }
                boolean grantAllowed = permissionRepository
                        .findByClientIdAndResourceId(client.getId(), resource.getId())
                        .stream()
                        .filter(permission -> RegistryStatus.isActive(permission.getStatus()))
                        .filter(permission -> permission.getScopeId().equals(scope.getId()))
                        .anyMatch(permission -> grantType.name().equals(permission.getGrantType()));
                if (grantAllowed) {
                    audiences.add(resource.getAudience());
                }
            }
        }
        if (audiences.isEmpty()) {
            throw new IamException(IamErrorCode.PERMISSION_DENIED, "no audience is allowed for the requested scopes");
        }
        return List.copyOf(audiences);
    }

    public void validateAuthorizationCodeScopes(String clientId, List<String> scopes) {
        IamClientEntity client = validateClient(clientId);
        if (scopes == null || scopes.isEmpty()) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "scope is required");
        }
        for (String scopeCode : scopes) {
            if (scopeCode == null || scopeCode.isBlank()) {
                throw new IamException(IamErrorCode.INVALID_ARGUMENT, "scope is required");
            }
            List<IamScopeEntity> matches = scopeRepository.findByScopeCode(scopeCode);
            if (matches.isEmpty()) {
                throw new IamException(IamErrorCode.SCOPE_NOT_FOUND, "scope not found: " + scopeCode);
            }
            boolean anyActive = false;
            boolean permitted = false;
            for (IamScopeEntity scope : matches) {
                if (!RegistryStatus.isActive(scope.getStatus())) {
                    continue;
                }
                anyActive = true;
                IamResourceServerEntity resource = resourceRepository.findById(scope.getResourceId()).orElse(null);
                if (resource == null || !RegistryStatus.isActive(resource.getStatus())) {
                    continue;
                }
                boolean grantAllowed = permissionRepository
                        .findByClientIdAndResourceId(client.getId(), resource.getId())
                        .stream()
                        .filter(permission -> RegistryStatus.isActive(permission.getStatus()))
                        .filter(permission -> permission.getScopeId().equals(scope.getId()))
                        .anyMatch(permission -> GrantType.AUTHORIZATION_CODE.name().equals(permission.getGrantType()));
                if (grantAllowed) {
                    permitted = true;
                    break;
                }
            }
            if (!anyActive) {
                throw new IamException(IamErrorCode.SCOPE_INACTIVE, "scope is disabled: " + scopeCode);
            }
            if (!permitted) {
                throw new IamException(IamErrorCode.PERMISSION_DENIED, "client is not allowed to request scope " + scopeCode);
            }
        }
    }

    private void validateGrantPermission(String clientId, String audience, String scopeCode, GrantType grantType) {
        IamClientEntity client = validateClient(clientId);
        IamResourceServerEntity resource = validateAudience(audience);
        IamScopeEntity scope = validateScope(audience, scopeCode);
        List<IamClientResourcePermissionEntity> resourcePerms = permissionRepository
                .findByClientIdAndResourceId(client.getId(), resource.getId())
                .stream()
                .filter(permission -> RegistryStatus.isActive(permission.getStatus()))
                .toList();
        if (resourcePerms.isEmpty()) {
            throw new IamException(IamErrorCode.PERMISSION_DENIED, "client has no access to resource");
        }
        boolean grantAllowed = resourcePerms.stream()
                .filter(permission -> permission.getScopeId().equals(scope.getId()))
                .anyMatch(permission -> grantType.name().equals(permission.getGrantType()));
        if (!grantAllowed) {
            if (grantType == GrantType.TOKEN_EXCHANGE) {
                throw new IamException(IamErrorCode.TOKEN_EXCHANGE_NOT_ALLOWED, "token exchange is not allowed");
            }
            if (grantType == GrantType.CLIENT_CREDENTIALS) {
                throw new IamException(
                        IamErrorCode.CLIENT_CREDENTIALS_NOT_ALLOWED, "client_credentials is not allowed");
            }
            throw new IamException(IamErrorCode.PERMISSION_DENIED, "grant is not allowed");
        }
    }
}
