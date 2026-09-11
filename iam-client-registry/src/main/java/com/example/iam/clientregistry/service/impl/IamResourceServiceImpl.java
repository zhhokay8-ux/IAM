package com.example.iam.clientregistry.service.impl;

import com.example.iam.audit.AuditEvent;
import com.example.iam.audit.IamAuditService;
import com.example.iam.clientregistry.domain.RegistryStatus;
import com.example.iam.clientregistry.dto.CreateResourceRequest;
import com.example.iam.clientregistry.dto.ResourceResponse;
import com.example.iam.clientregistry.dto.UpdateResourceRequest;
import com.example.iam.clientregistry.entity.IamResourceServerEntity;
import com.example.iam.clientregistry.repository.IamResourceServerRepository;
import com.example.iam.clientregistry.service.IamResourceService;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

@Service
public class IamResourceServiceImpl implements IamResourceService {

    private final IamResourceServerRepository resourceRepository;
    private final IamAuditService auditService;

    public IamResourceServiceImpl(IamResourceServerRepository resourceRepository) {
        this(resourceRepository, null);
    }

    @Autowired
    public IamResourceServiceImpl(IamResourceServerRepository resourceRepository, IamAuditService auditService) {
        this.resourceRepository = resourceRepository;
        this.auditService = auditService;
    }

    @Override
    @Transactional
    public ResourceResponse create(CreateResourceRequest request) {
        if (request.resourceCode() == null || request.resourceCode().isBlank()) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "resource_code is required");
        }
        if (request.audience() == null || request.audience().isBlank()) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "audience is required");
        }
        if (resourceRepository.existsByResourceCode(request.resourceCode())) {
            throw new IamException(IamErrorCode.DUPLICATE_RESOURCE, "resource_code already exists");
        }
        if (resourceRepository.existsByAudience(request.audience())) {
            throw new IamException(IamErrorCode.DUPLICATE_AUDIENCE, "audience already exists");
        }
        IamResourceServerEntity saved = resourceRepository.save(IamResourceServerEntity.builder()
                .resourceCode(request.resourceCode())
                .resourceName(requireName(request.resourceName()))
                .audience(request.audience())
                .status(RegistryStatus.normalize(request.status()))
                .owner(request.owner())
                .createdAt(Instant.now())
                .build());
        audit(AuditEvent.RESOURCE_CREATED, saved.getResourceCode());
        return toResponse(saved);
    }

    @Override
    @Transactional
    public ResourceResponse update(String resourceCode, UpdateResourceRequest request) {
        IamResourceServerEntity entity = requireByCode(resourceCode);
        if (request.resourceName() != null) {
            entity.setResourceName(requireName(request.resourceName()));
        }
        if (request.audience() != null && !request.audience().equals(entity.getAudience())) {
            if (resourceRepository.existsByAudience(request.audience())) {
                throw new IamException(IamErrorCode.DUPLICATE_AUDIENCE, "audience already exists");
            }
            entity.setAudience(request.audience());
        }
        if (request.status() != null) {
            entity.setStatus(RegistryStatus.normalize(request.status()));
        }
        if (request.owner() != null) {
            entity.setOwner(request.owner());
        }
        IamResourceServerEntity saved = resourceRepository.save(entity);
        audit(AuditEvent.RESOURCE_UPDATED, saved.getResourceCode());
        return toResponse(saved);
    }

    @Override
    @Transactional(readOnly = true)
    public ResourceResponse get(String resourceCode) {
        return toResponse(requireByCode(resourceCode));
    }

    @Override
    @Transactional(readOnly = true)
    public ResourceResponse getById(UUID id) {
        IamResourceServerEntity entity = resourceRepository
                .findById(id)
                .orElseThrow(() -> new IamException(IamErrorCode.RESOURCE_NOT_FOUND, "resource not found: " + id));
        return toResponse(entity);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<ResourceResponse> search(String query, String status, Pageable pageable) {
        Specification<IamResourceServerEntity> spec = (root, q, cb) -> {
            List<jakarta.persistence.criteria.Predicate> predicates = new ArrayList<>();
            if (StringUtils.hasText(status)) {
                predicates.add(cb.equal(root.get("status"), RegistryStatus.normalize(status)));
            }
            if (StringUtils.hasText(query)) {
                String like = "%" + query.trim().toLowerCase(Locale.ROOT) + "%";
                predicates.add(cb.or(
                        cb.like(cb.lower(root.get("resourceCode")), like),
                        cb.like(cb.lower(root.get("resourceName")), like),
                        cb.like(cb.lower(root.get("audience")), like)));
            }
            return cb.and(predicates.toArray(jakarta.persistence.criteria.Predicate[]::new));
        };
        return resourceRepository.findAll(spec, pageable).map(IamResourceServiceImpl::toResponse);
    }

    @Override
    @Transactional
    public ResourceResponse disable(String resourceCode) {
        IamResourceServerEntity entity = requireByCode(resourceCode);
        entity.setStatus(RegistryStatus.INACTIVE);
        IamResourceServerEntity saved = resourceRepository.save(entity);
        audit(AuditEvent.RESOURCE_DISABLED, saved.getResourceCode());
        return toResponse(saved);
    }

    @Override
    @Transactional
    public ResourceResponse enable(String resourceCode) {
        IamResourceServerEntity entity = requireByCode(resourceCode);
        entity.setStatus(RegistryStatus.ACTIVE);
        IamResourceServerEntity saved = resourceRepository.save(entity);
        audit(AuditEvent.RESOURCE_ENABLED, saved.getResourceCode());
        return toResponse(saved);
    }

    @Override
    @Transactional(readOnly = true)
    public IamResourceServerEntity requireActiveByCode(String resourceCode) {
        IamResourceServerEntity entity = requireByCode(resourceCode);
        requireActive(entity);
        return entity;
    }

    @Override
    @Transactional(readOnly = true)
    public IamResourceServerEntity requireActiveByAudience(String audience) {
        IamResourceServerEntity entity = resourceRepository.findByAudience(audience)
                .orElseThrow(() -> new IamException(IamErrorCode.AUDIENCE_NOT_FOUND, "audience not found: " + audience));
        requireActive(entity);
        return entity;
    }

    private IamResourceServerEntity requireByCode(String resourceCode) {
        return resourceRepository.findByResourceCode(resourceCode)
                .orElseThrow(() -> new IamException(
                        IamErrorCode.RESOURCE_NOT_FOUND, "resource_code not found: " + resourceCode));
    }

    private void audit(AuditEvent event, String resourceCode) {
        if (auditService == null) {
            return;
        }
        auditService.success(event, null, null, "resource_code=" + resourceCode);
    }

    private static void requireActive(IamResourceServerEntity entity) {
        if (!RegistryStatus.isActive(entity.getStatus())) {
            throw new IamException(IamErrorCode.FORBIDDEN, "resource is disabled: " + entity.getResourceCode());
        }
    }

    private static String requireName(String name) {
        if (name == null || name.isBlank()) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "resource_name is required");
        }
        return name;
    }

    private static ResourceResponse toResponse(IamResourceServerEntity entity) {
        return new ResourceResponse(
                entity.getId(),
                entity.getResourceCode(),
                entity.getResourceName(),
                entity.getAudience(),
                entity.getStatus(),
                entity.getOwner(),
                entity.getCreatedAt());
    }
}
