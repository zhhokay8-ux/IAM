package com.example.iam.clientregistry.service.impl;

import com.example.iam.audit.AuditEvent;
import com.example.iam.audit.IamAuditService;
import com.example.iam.clientregistry.domain.RegistryStatus;
import com.example.iam.clientregistry.dto.CreateScopeRequest;
import com.example.iam.clientregistry.dto.ResourceResponse;
import com.example.iam.clientregistry.dto.ScopeResponse;
import com.example.iam.clientregistry.dto.UpdateScopeRequest;
import com.example.iam.clientregistry.entity.IamResourceServerEntity;
import com.example.iam.clientregistry.entity.IamScopeEntity;
import com.example.iam.clientregistry.repository.IamScopeRepository;
import com.example.iam.clientregistry.service.IamResourceService;
import com.example.iam.clientregistry.service.IamScopeService;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

@Service
public class IamScopeServiceImpl implements IamScopeService {

    private final IamScopeRepository scopeRepository;
    private final IamResourceService resourceService;
    private final IamAuditService auditService;

    public IamScopeServiceImpl(IamScopeRepository scopeRepository, IamResourceService resourceService) {
        this(scopeRepository, resourceService, null);
    }

    @Autowired
    public IamScopeServiceImpl(
            IamScopeRepository scopeRepository, IamResourceService resourceService, IamAuditService auditService) {
        this.scopeRepository = scopeRepository;
        this.resourceService = resourceService;
        this.auditService = auditService;
    }

    @Override
    @Transactional
    public ScopeResponse create(CreateScopeRequest request) {
        IamResourceServerEntity resource = resourceService.requireActiveByCode(request.resourceCode());
        if (request.scopeCode() == null || request.scopeCode().isBlank()) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "scope_code is required");
        }
        if (scopeRepository.existsByResourceIdAndScopeCode(resource.getId(), request.scopeCode())) {
            throw new IamException(IamErrorCode.DUPLICATE_SCOPE, "scope_code already exists for resource");
        }
        IamScopeEntity saved = scopeRepository.save(IamScopeEntity.builder()
                .resourceId(resource.getId())
                .scopeCode(request.scopeCode())
                .scopeName(requireName(request.scopeName()))
                .description(request.description())
                .status(RegistryStatus.normalize(request.status()))
                .build());
        audit(AuditEvent.SCOPE_CREATED, resource.getResourceCode(), saved.getScopeCode());
        return toResponse(saved, resource.getResourceCode());
    }

    @Override
    @Transactional
    public ScopeResponse update(String resourceCode, String scopeCode, UpdateScopeRequest request) {
        ResourceResponse resource = resourceService.get(resourceCode);
        IamScopeEntity entity = requireExisting(resource.id(), resourceCode, scopeCode);
        if (request.scopeName() != null) {
            entity.setScopeName(requireName(request.scopeName()));
        }
        if (request.description() != null) {
            entity.setDescription(request.description());
        }
        IamScopeEntity saved = scopeRepository.save(entity);
        audit(AuditEvent.SCOPE_UPDATED, resourceCode, saved.getScopeCode());
        return toResponse(saved, resourceCode);
    }

    @Override
    @Transactional(readOnly = true)
    public ScopeResponse get(String resourceCode, String scopeCode) {
        ResourceResponse resource = resourceService.get(resourceCode);
        return toResponse(requireExisting(resource.id(), resourceCode, scopeCode), resourceCode);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<ScopeResponse> search(String resourceCode, String query, String status, Pageable pageable) {
        ResourceResponse resource =
                StringUtils.hasText(resourceCode) ? resourceService.get(resourceCode) : null;
        Specification<IamScopeEntity> spec = (root, q, cb) -> {
            List<jakarta.persistence.criteria.Predicate> predicates = new ArrayList<>();
            if (resource != null) {
                predicates.add(cb.equal(root.get("resourceId"), resource.id()));
            }
            if (StringUtils.hasText(status)) {
                predicates.add(cb.equal(root.get("status"), RegistryStatus.normalize(status)));
            }
            if (StringUtils.hasText(query)) {
                String like = "%" + query.trim().toLowerCase(Locale.ROOT) + "%";
                predicates.add(cb.or(
                        cb.like(cb.lower(root.get("scopeCode")), like),
                        cb.like(cb.lower(root.get("scopeName")), like)));
            }
            return cb.and(predicates.toArray(jakarta.persistence.criteria.Predicate[]::new));
        };
        return scopeRepository.findAll(spec, pageable).map(entity -> {
            String code = resource != null
                    ? resource.resourceCode()
                    : resourceService.getById(entity.getResourceId()).resourceCode();
            return toResponse(entity, code);
        });
    }

    @Override
    @Transactional
    public ScopeResponse disable(String resourceCode, String scopeCode) {
        ResourceResponse resource = resourceService.get(resourceCode);
        IamScopeEntity entity = requireExisting(resource.id(), resourceCode, scopeCode);
        entity.setStatus(RegistryStatus.INACTIVE);
        IamScopeEntity saved = scopeRepository.save(entity);
        audit(AuditEvent.SCOPE_DISABLED, resourceCode, saved.getScopeCode());
        return toResponse(saved, resourceCode);
    }

    @Override
    @Transactional
    public ScopeResponse enable(String resourceCode, String scopeCode) {
        ResourceResponse resource = resourceService.get(resourceCode);
        IamScopeEntity entity = requireExisting(resource.id(), resourceCode, scopeCode);
        entity.setStatus(RegistryStatus.ACTIVE);
        IamScopeEntity saved = scopeRepository.save(entity);
        audit(AuditEvent.SCOPE_ENABLED, resourceCode, saved.getScopeCode());
        return toResponse(saved, resourceCode);
    }

    @Override
    @Transactional(readOnly = true)
    public IamScopeEntity requireBoundScope(String resourceCode, String scopeCode) {
        if (scopeCode == null || scopeCode.isBlank()) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "scope is required");
        }
        IamResourceServerEntity resource = resourceService.requireActiveByCode(resourceCode);
        IamScopeEntity scope = scopeRepository.findByResourceIdAndScopeCode(resource.getId(), scopeCode)
                .orElseGet(() -> {
                    if (scopeRepository.findByScopeCode(scopeCode).isEmpty()) {
                        throw new IamException(IamErrorCode.SCOPE_NOT_FOUND, "scope not found: " + scopeCode);
                    }
                    throw new IamException(
                            IamErrorCode.SCOPE_NOT_BOUND, "scope is not bound to resource " + resourceCode);
                });
        if (!RegistryStatus.isActive(scope.getStatus())) {
            throw new IamException(IamErrorCode.SCOPE_INACTIVE, "scope is disabled: " + scopeCode);
        }
        return scope;
    }

    private IamScopeEntity requireExisting(java.util.UUID resourceId, String resourceCode, String scopeCode) {
        if (scopeCode == null || scopeCode.isBlank()) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "scope is required");
        }
        return scopeRepository.findByResourceIdAndScopeCode(resourceId, scopeCode)
                .orElseGet(() -> {
                    if (scopeRepository.findByScopeCode(scopeCode).isEmpty()) {
                        throw new IamException(IamErrorCode.SCOPE_NOT_FOUND, "scope not found: " + scopeCode);
                    }
                    throw new IamException(
                            IamErrorCode.SCOPE_NOT_BOUND, "scope is not bound to resource " + resourceCode);
                });
    }

    private void audit(AuditEvent event, String resourceCode, String scopeCode) {
        if (auditService == null) {
            return;
        }
        auditService.success(event, null, null, "resource_code=" + resourceCode + "; scope_code=" + scopeCode);
    }

    private static String requireName(String name) {
        if (name == null || name.isBlank()) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "scope_name is required");
        }
        return name;
    }

    private static ScopeResponse toResponse(IamScopeEntity entity, String resourceCode) {
        return new ScopeResponse(
                entity.getId(),
                entity.getResourceId(),
                resourceCode,
                entity.getScopeCode(),
                entity.getScopeName(),
                entity.getDescription(),
                entity.getStatus());
    }
}
