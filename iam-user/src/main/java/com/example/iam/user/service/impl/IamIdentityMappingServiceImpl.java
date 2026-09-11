package com.example.iam.user.service.impl;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.user.domain.UserStatus;
import com.example.iam.user.dto.IdentityMappingRequest;
import com.example.iam.user.dto.IdentityMappingResponse;
import com.example.iam.user.entity.IamUserEntity;
import com.example.iam.user.entity.IamUserIdentityMappingEntity;
import com.example.iam.user.repository.IamUserIdentityMappingRepository;
import com.example.iam.user.service.IamIdentityMappingService;
import com.example.iam.user.service.IamUserService;
import jakarta.persistence.criteria.Predicate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

@Service
public class IamIdentityMappingServiceImpl implements IamIdentityMappingService {

    private final IamUserIdentityMappingRepository mappingRepository;
    private final IamUserService userService;

    public IamIdentityMappingServiceImpl(
            IamUserIdentityMappingRepository mappingRepository, IamUserService userService) {
        this.mappingRepository = mappingRepository;
        this.userService = userService;
    }

    @Override
    @Transactional
    public IdentityMappingResponse create(UUID subjectId, IdentityMappingRequest request) {
        IamUserEntity user = userService.requireUser(subjectId);
        String systemCode = requireText(request.systemCode(), "system_code");
        String externalUserId = requireText(request.externalUserId(), "external_user_id");
        if (mappingRepository.existsBySystemCodeAndExternalUserId(systemCode, externalUserId)) {
            throw new IamException(
                    IamErrorCode.DUPLICATE_IDENTITY_MAPPING, "system_code + external_user_id already mapped");
        }
        IamUserIdentityMappingEntity saved = mappingRepository.save(IamUserIdentityMappingEntity.builder()
                .subjectId(user.getSubjectId())
                .systemCode(systemCode)
                .externalUserId(externalUserId)
                .externalUsername(request.externalUsername())
                .mappingStatus(UserStatus.normalize(request.mappingStatus()))
                .createdAt(Instant.now())
                .build());
        return toResponse(saved);
    }

    @Override
    @Transactional
    public IdentityMappingResponse update(UUID mappingId, IdentityMappingRequest request) {
        IamUserIdentityMappingEntity entity = requireById(mappingId);
        if (request.systemCode() != null || request.externalUserId() != null) {
            String systemCode = request.systemCode() == null ? entity.getSystemCode() : requireText(request.systemCode(), "system_code");
            String externalUserId = request.externalUserId() == null
                    ? entity.getExternalUserId()
                    : requireText(request.externalUserId(), "external_user_id");
            mappingRepository
                    .findBySystemCodeAndExternalUserId(systemCode, externalUserId)
                    .filter(existing -> !existing.getId().equals(entity.getId()))
                    .ifPresent(existing -> {
                        throw new IamException(
                                IamErrorCode.DUPLICATE_IDENTITY_MAPPING,
                                "system_code + external_user_id already mapped");
                    });
            entity.setSystemCode(systemCode);
            entity.setExternalUserId(externalUserId);
        }
        if (request.externalUsername() != null) {
            entity.setExternalUsername(request.externalUsername());
        }
        if (request.mappingStatus() != null) {
            entity.setMappingStatus(UserStatus.normalize(request.mappingStatus()));
        }
        return toResponse(mappingRepository.save(entity));
    }

    @Override
    @Transactional
    public void delete(UUID mappingId) {
        mappingRepository.delete(requireById(mappingId));
    }

    @Override
    @Transactional(readOnly = true)
    public IdentityMappingResponse get(UUID mappingId) {
        return toResponse(requireById(mappingId));
    }

    @Override
    @Transactional(readOnly = true)
    public List<IdentityMappingResponse> list(UUID subjectId) {
        userService.requireUser(subjectId);
        return mappingRepository.findBySubjectId(subjectId).stream()
                .map(IamIdentityMappingServiceImpl::toResponse)
                .toList();
    }

    @Override
    @Transactional(readOnly = true)
    public IdentityMappingResponse requireMapping(String systemCode, String externalUserId) {
        String system = requireText(systemCode, "system_code");
        String external = requireText(externalUserId, "external_user_id");
        IamUserIdentityMappingEntity mapping = mappingRepository.findBySystemCodeAndExternalUserId(system, external)
                .orElseThrow(() -> new IamException(
                        IamErrorCode.MAPPING_NOT_FOUND, "identity mapping not found"));
        return toResponse(mapping);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<IdentityMappingResponse> search(
            String systemCode, String externalUserId, UUID subjectId, Pageable pageable) {
        Specification<IamUserIdentityMappingEntity> spec = (root, q, cb) -> {
            List<Predicate> predicates = new ArrayList<>();
            if (StringUtils.hasText(systemCode)) {
                predicates.add(cb.equal(root.get("systemCode"), systemCode.trim()));
            }
            if (StringUtils.hasText(externalUserId)) {
                predicates.add(cb.equal(root.get("externalUserId"), externalUserId.trim()));
            }
            if (subjectId != null) {
                predicates.add(cb.equal(root.get("subjectId"), subjectId));
            }
            return cb.and(predicates.toArray(Predicate[]::new));
        };
        return mappingRepository.findAll(spec, pageable).map(IamIdentityMappingServiceImpl::toResponse);
    }

    private IamUserIdentityMappingEntity requireById(UUID mappingId) {
        if (mappingId == null) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "mapping id is required");
        }
        return mappingRepository
                .findById(mappingId)
                .orElseThrow(() -> new IamException(IamErrorCode.MAPPING_NOT_FOUND, "identity mapping not found"));
    }

    private static String requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, field + " is required");
        }
        return value.trim();
    }

    private static IdentityMappingResponse toResponse(IamUserIdentityMappingEntity entity) {
        return new IdentityMappingResponse(
                entity.getId(),
                entity.getSubjectId().toString(),
                entity.getSystemCode(),
                entity.getExternalUserId(),
                entity.getExternalUsername(),
                entity.getMappingStatus(),
                entity.getCreatedAt());
    }
}
