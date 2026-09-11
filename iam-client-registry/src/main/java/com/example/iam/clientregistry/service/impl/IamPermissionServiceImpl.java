package com.example.iam.clientregistry.service.impl;

import com.example.iam.audit.AuditEvent;
import com.example.iam.audit.IamAuditService;
import com.example.iam.clientregistry.domain.GrantType;
import com.example.iam.clientregistry.domain.RegistryStatus;
import com.example.iam.clientregistry.dto.ClientResponse;
import com.example.iam.clientregistry.dto.CreatePermissionRequest;
import com.example.iam.clientregistry.dto.PermissionResponse;
import com.example.iam.clientregistry.entity.IamClientEntity;
import com.example.iam.clientregistry.entity.IamClientResourcePermissionEntity;
import com.example.iam.clientregistry.entity.IamResourceServerEntity;
import com.example.iam.clientregistry.entity.IamScopeEntity;
import com.example.iam.clientregistry.repository.IamClientRepository;
import com.example.iam.clientregistry.repository.IamClientResourcePermissionRepository;
import com.example.iam.clientregistry.repository.IamResourceServerRepository;
import com.example.iam.clientregistry.repository.IamScopeRepository;
import com.example.iam.clientregistry.service.IamClientService;
import com.example.iam.clientregistry.service.IamPermissionService;
import com.example.iam.clientregistry.service.IamResourceService;
import com.example.iam.clientregistry.service.IamScopeService;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

@Service
public class IamPermissionServiceImpl implements IamPermissionService {

    private final IamClientResourcePermissionRepository permissionRepository;
    private final IamClientService clientService;
    private final IamResourceService resourceService;
    private final IamScopeService scopeService;
    private final IamResourceServerRepository resourceRepository;
    private final IamScopeRepository scopeRepository;
    private final IamClientRepository clientRepository;
    private final IamAuditService auditService;

    public IamPermissionServiceImpl(
            IamClientResourcePermissionRepository permissionRepository,
            IamClientService clientService,
            IamResourceService resourceService,
            IamScopeService scopeService) {
        this(permissionRepository, clientService, resourceService, scopeService, null, null, null, null);
    }

    @Autowired
    public IamPermissionServiceImpl(
            IamClientResourcePermissionRepository permissionRepository,
            IamClientService clientService,
            IamResourceService resourceService,
            IamScopeService scopeService,
            IamResourceServerRepository resourceRepository,
            IamScopeRepository scopeRepository,
            IamClientRepository clientRepository,
            IamAuditService auditService) {
        this.permissionRepository = permissionRepository;
        this.clientService = clientService;
        this.resourceService = resourceService;
        this.scopeService = scopeService;
        this.resourceRepository = resourceRepository;
        this.scopeRepository = scopeRepository;
        this.clientRepository = clientRepository;
        this.auditService = auditService;
    }

    @Override
    @Transactional
    public PermissionResponse create(CreatePermissionRequest request) {
        IamClientEntity client = clientService.requireActiveClient(request.clientId());
        IamResourceServerEntity resource = resourceService.requireActiveByCode(request.resourceCode());
        IamScopeEntity scope = scopeService.requireBoundScope(request.resourceCode(), request.scopeCode());
        GrantType grantType = GrantType.from(request.grantType());
        permissionRepository
                .findByClientIdAndResourceIdAndScopeIdAndGrantType(
                        client.getId(), resource.getId(), scope.getId(), grantType.name())
                .ifPresent(existing -> {
                    throw new IamException(IamErrorCode.DUPLICATE_PERMISSION, "permission already exists");
                });
        IamClientResourcePermissionEntity saved = permissionRepository.save(IamClientResourcePermissionEntity.builder()
                .clientId(client.getId())
                .resourceId(resource.getId())
                .scopeId(scope.getId())
                .grantType(grantType.name())
                .status(RegistryStatus.normalize(request.status()))
                .createdAt(Instant.now())
                .build());
        audit(saved, client.getClientId(), resource.getResourceCode(), scope.getScopeCode());
        return toResponse(saved, client.getClientId(), resource, scope.getScopeCode());
    }

    @Override
    @Transactional(readOnly = true)
    public PermissionResponse get(String clientId, String resourceCode, String scopeCode, String grantType) {
        Loaded loaded = load(clientId, resourceCode, scopeCode, grantType);
        return toResponse(loaded.permission(), loaded.clientId(), loaded.resource(), loaded.scopeCode());
    }

    @Override
    @Transactional(readOnly = true)
    public List<PermissionResponse> listByClientId(String clientId) {
        ClientResponse client = clientService.get(clientId);
        if (resourceRepository == null || scopeRepository == null) {
            return List.of();
        }
        List<PermissionResponse> result = new ArrayList<>();
        for (IamClientResourcePermissionEntity permission : permissionRepository.findByClientId(client.id())) {
            IamResourceServerEntity resource = resourceRepository.findById(permission.getResourceId()).orElse(null);
            IamScopeEntity scope = scopeRepository.findById(permission.getScopeId()).orElse(null);
            if (resource == null || scope == null) {
                continue;
            }
            result.add(toResponse(permission, client.clientId(), resource, scope.getScopeCode()));
        }
        return result;
    }

    @Override
    @Transactional(readOnly = true)
    public Page<PermissionResponse> search(
            String clientId, String resourceCode, String grantType, String status, Pageable pageable) {
        UUID clientPk = StringUtils.hasText(clientId) ? clientService.get(clientId).id() : null;
        UUID resourcePk = StringUtils.hasText(resourceCode) ? resourceService.get(resourceCode).id() : null;
        String grant = StringUtils.hasText(grantType) ? GrantType.from(grantType).name() : null;
        Specification<IamClientResourcePermissionEntity> spec = (root, q, cb) -> {
            List<jakarta.persistence.criteria.Predicate> predicates = new ArrayList<>();
            if (clientPk != null) {
                predicates.add(cb.equal(root.get("clientId"), clientPk));
            }
            if (resourcePk != null) {
                predicates.add(cb.equal(root.get("resourceId"), resourcePk));
            }
            if (grant != null) {
                predicates.add(cb.equal(root.get("grantType"), grant));
            }
            if (StringUtils.hasText(status)) {
                predicates.add(cb.equal(root.get("status"), RegistryStatus.normalize(status)));
            }
            return cb.and(predicates.toArray(jakarta.persistence.criteria.Predicate[]::new));
        };
        return permissionRepository.findAll(spec, pageable).map(this::toSearchResponse);
    }

    @Override
    @Transactional
    public PermissionResponse disable(String clientId, String resourceCode, String scopeCode, String grantType) {
        Loaded loaded = load(clientId, resourceCode, scopeCode, grantType);
        loaded.permission().setStatus(RegistryStatus.INACTIVE);
        IamClientResourcePermissionEntity saved = permissionRepository.save(loaded.permission());
        audit(saved, loaded.clientId(), loaded.resource().getResourceCode(), loaded.scopeCode());
        return toResponse(saved, loaded.clientId(), loaded.resource(), loaded.scopeCode());
    }

    @Override
    @Transactional
    public PermissionResponse enable(String clientId, String resourceCode, String scopeCode, String grantType) {
        Loaded loaded = load(clientId, resourceCode, scopeCode, grantType);
        loaded.permission().setStatus(RegistryStatus.ACTIVE);
        IamClientResourcePermissionEntity saved = permissionRepository.save(loaded.permission());
        audit(saved, loaded.clientId(), loaded.resource().getResourceCode(), loaded.scopeCode());
        return toResponse(saved, loaded.clientId(), loaded.resource(), loaded.scopeCode());
    }

    private PermissionResponse toSearchResponse(IamClientResourcePermissionEntity permission) {
        if (resourceRepository == null || scopeRepository == null) {
            return new PermissionResponse(
                    permission.getId(),
                    null,
                    null,
                    null,
                    null,
                    permission.getGrantType(),
                    permission.getStatus(),
                    permission.getCreatedAt());
        }
        IamResourceServerEntity resource = resourceRepository.findById(permission.getResourceId()).orElse(null);
        IamScopeEntity scope = scopeRepository.findById(permission.getScopeId()).orElse(null);
        if (resource == null || scope == null) {
            return new PermissionResponse(
                    permission.getId(),
                    null,
                    null,
                    null,
                    null,
                    permission.getGrantType(),
                    permission.getStatus(),
                    permission.getCreatedAt());
        }
        String clientId = clientRepository == null
                ? null
                : clientRepository.findById(permission.getClientId()).map(IamClientEntity::getClientId).orElse(null);
        return toResponse(permission, clientId, resource, scope.getScopeCode());
    }

    private Loaded load(String clientId, String resourceCode, String scopeCode, String grantType) {
        IamClientEntity client = clientService.requireActiveClient(clientId);
        IamResourceServerEntity resource = resourceService.requireActiveByCode(resourceCode);
        IamScopeEntity scope = scopeService.requireBoundScope(resourceCode, scopeCode);
        GrantType type = GrantType.from(grantType);
        IamClientResourcePermissionEntity permission = permissionRepository
                .findByClientIdAndResourceIdAndScopeIdAndGrantType(
                        client.getId(), resource.getId(), scope.getId(), type.name())
                .orElseThrow(() -> new IamException(IamErrorCode.PERMISSION_DENIED, "permission not found"));
        return new Loaded(permission, client.getClientId(), resource, scope.getScopeCode());
    }

    private void audit(
            IamClientResourcePermissionEntity entity,
            String clientId,
            String resourceCode,
            String scopeCode) {
        if (auditService == null) {
            return;
        }
        auditService.success(
                AuditEvent.POLICY_CHANGED,
                null,
                clientId,
                "resource_code=" + resourceCode + "; scope_code=" + scopeCode + "; grant_type=" + entity.getGrantType()
                        + "; status=" + entity.getStatus());
    }

    private static PermissionResponse toResponse(
            IamClientResourcePermissionEntity entity,
            String clientId,
            IamResourceServerEntity resource,
            String scopeCode) {
        return new PermissionResponse(
                entity.getId(),
                clientId,
                resource.getResourceCode(),
                resource.getAudience(),
                scopeCode,
                entity.getGrantType(),
                entity.getStatus(),
                entity.getCreatedAt());
    }

    private record Loaded(
            IamClientResourcePermissionEntity permission,
            String clientId,
            IamResourceServerEntity resource,
            String scopeCode) {}
}
