package com.example.iam.user.service.impl;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.user.context.UserContext;
import com.example.iam.user.context.UserContextFactory;
import com.example.iam.user.domain.UserStatus;
import com.example.iam.user.dto.CreateUserRequest;
import com.example.iam.user.dto.UpdateUserRequest;
import com.example.iam.user.dto.UserResponse;
import com.example.iam.user.entity.IamUserEntity;
import com.example.iam.user.password.IamPasswordHasher;
import com.example.iam.user.repository.IamUserRepository;
import com.example.iam.user.service.IamUserService;
import com.example.iam.user.subject.UserSubjectGenerator;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import jakarta.persistence.criteria.Predicate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

@Service
public class IamUserServiceImpl implements IamUserService {

    private static final Logger log = LoggerFactory.getLogger(IamUserServiceImpl.class);

    private static final int MIN_PASSWORD_LENGTH = 8;

    private final IamUserRepository userRepository;
    private final UserSubjectGenerator subjectGenerator;
    private final UserContextFactory userContextFactory;
    private final IamPasswordHasher passwordHasher;

    public IamUserServiceImpl(
            IamUserRepository userRepository,
            UserSubjectGenerator subjectGenerator,
            UserContextFactory userContextFactory,
            IamPasswordHasher passwordHasher) {
        this.userRepository = userRepository;
        this.subjectGenerator = subjectGenerator;
        this.userContextFactory = userContextFactory;
        this.passwordHasher = passwordHasher;
    }

    @Override
    @Transactional
    public UserResponse create(CreateUserRequest request) {
        String tenantId = requireText(request.tenantId(), "tenant_id");
        String username = requireText(request.username(), "username");
        if (userRepository.existsByUsernameAndTenantId(username, tenantId)) {
            throw new IamException(IamErrorCode.DUPLICATE_USERNAME, "username already exists in tenant");
        }
        Instant now = Instant.now();
        UUID subjectId = subjectGenerator.next();
        IamUserEntity saved = userRepository.save(IamUserEntity.builder()
                .subjectId(subjectId)
                .username(username)
                .displayName(request.displayName())
                .email(normalizeEmail(request.email()))
                .status(UserStatus.normalize(request.status()))
                .tenantId(tenantId)
                .orgId(request.orgId())
                .passwordHash(encodePasswordIfPresent(request.password()))
                .createdAt(now)
                .updatedAt(now)
                .build());
        log.info("Created user subjectId={}", saved.getSubjectId());
        return toResponse(saved);
    }

    @Override
    @Transactional
    public UserResponse update(UUID subjectId, UpdateUserRequest request) {
        IamUserEntity entity = requireUser(subjectId);
        UUID originalSubject = entity.getSubjectId();
        if (request.username() != null) {
            String username = requireText(request.username(), "username");
            userRepository.findByUsernameAndTenantId(username, entity.getTenantId())
                    .filter(existing -> !existing.getSubjectId().equals(originalSubject))
                    .ifPresent(existing -> {
                        throw new IamException(IamErrorCode.DUPLICATE_USERNAME, "username already exists in tenant");
                    });
            entity.setUsername(username);
        }
        if (request.displayName() != null) {
            entity.setDisplayName(request.displayName());
        }
        if (request.email() != null) {
            entity.setEmail(normalizeEmail(request.email()));
        }
        if (request.orgId() != null) {
            entity.setOrgId(request.orgId());
        }
        if (request.status() != null) {
            entity.setStatus(UserStatus.normalize(request.status()));
        }
        if (request.password() != null) {
            entity.setPasswordHash(encodePasswordIfPresent(request.password()));
        }
        entity.setUpdatedAt(Instant.now());
        IamUserEntity saved = userRepository.save(entity);
        if (!originalSubject.equals(saved.getSubjectId())) {
            throw new IamException(IamErrorCode.INTERNAL_ERROR, "subject_id is immutable");
        }
        return toResponse(saved);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<UserResponse> search(String query, String status, String tenantId, Pageable pageable) {
        Specification<IamUserEntity> spec = (root, q, cb) -> {
            List<Predicate> predicates = new ArrayList<>();
            if (StringUtils.hasText(status)) {
                predicates.add(cb.equal(root.get("status"), UserStatus.normalize(status)));
            }
            if (StringUtils.hasText(tenantId)) {
                predicates.add(cb.equal(root.get("tenantId"), tenantId.trim()));
            }
            if (StringUtils.hasText(query)) {
                String raw = query.trim();
                String like = "%" + raw.toLowerCase(Locale.ROOT) + "%";
                Predicate text = cb.or(
                        cb.like(cb.lower(root.get("username")), like),
                        cb.like(cb.lower(root.get("email")), like),
                        cb.like(cb.lower(root.get("tenantId")), like));
                try {
                    UUID subject = UUID.fromString(raw);
                    predicates.add(cb.or(text, cb.equal(root.get("subjectId"), subject)));
                } catch (IllegalArgumentException ex) {
                    predicates.add(text);
                }
            }
            return cb.and(predicates.toArray(Predicate[]::new));
        };
        return userRepository.findAll(spec, pageable).map(IamUserServiceImpl::toResponse);
    }

    @Override
    @Transactional
    public UserResponse disable(UUID subjectId) {
        IamUserEntity entity = requireUser(subjectId);
        entity.setStatus(UserStatus.INACTIVE);
        entity.setUpdatedAt(Instant.now());
        return toResponse(userRepository.save(entity));
    }

    @Override
    @Transactional
    public UserResponse enable(UUID subjectId) {
        IamUserEntity entity = requireUser(subjectId);
        entity.setStatus(UserStatus.ACTIVE);
        entity.setUpdatedAt(Instant.now());
        return toResponse(userRepository.save(entity));
    }

    @Override
    @Transactional(readOnly = true)
    public UserResponse get(UUID subjectId) {
        return toResponse(requireUser(subjectId));
    }

    @Override
    @Transactional(readOnly = true)
    public IamUserEntity requireUser(UUID subjectId) {
        if (subjectId == null) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "subject_id is required");
        }
        return userRepository.findBySubjectId(subjectId)
                .orElseThrow(() -> new IamException(IamErrorCode.USER_NOT_FOUND, "user not found"));
    }

    @Override
    @Transactional(readOnly = true)
    public IamUserEntity requireActiveByUsernameAndTenantId(String username, String tenantId) {
        String normalizedUsername = requireText(username, "username");
        String normalizedTenant = requireText(tenantId, "tenant_id");
        IamUserEntity entity = userRepository.findByUsernameAndTenantId(normalizedUsername, normalizedTenant)
                .orElseThrow(() -> new IamException(IamErrorCode.USER_NOT_FOUND, "user not found"));
        if (!UserStatus.isActive(entity.getStatus())) {
            throw new IamException(IamErrorCode.USER_INACTIVE, "user is inactive");
        }
        return entity;
    }

    @Override
    @Transactional(readOnly = true)
    public IamUserEntity authenticatePassword(String username, String tenantId, String rawPassword) {
        String normalizedUsername = requireText(username, "username");
        String normalizedTenant = requireText(tenantId, "tenant_id");
        String password = requireText(rawPassword, "password");
        IamUserEntity entity = userRepository.findByUsernameAndTenantId(normalizedUsername, normalizedTenant)
                .orElse(null);
        boolean passwordOk = passwordHasher.matches(password, entity == null ? null : entity.getPasswordHash());
        if (entity == null || !passwordOk) {
            throw new IamException(IamErrorCode.INVALID_CREDENTIALS, "username or password is incorrect");
        }
        if (!UserStatus.isActive(entity.getStatus())) {
            throw new IamException(IamErrorCode.USER_INACTIVE, "user is inactive");
        }
        return entity;
    }

    @Override
    @Transactional(readOnly = true)
    public UserContext requireActiveForToken(UUID subjectId) {
        return userContextFactory.forToken(requireUser(subjectId));
    }

    private String encodePasswordIfPresent(String rawPassword) {
        if (rawPassword == null) {
            return null;
        }
        if (rawPassword.isBlank() || rawPassword.length() < MIN_PASSWORD_LENGTH) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "password must be at least 8 characters");
        }
        return passwordHasher.hash(rawPassword);
    }

    private static String requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, field + " is required");
        }
        return value.trim();
    }

    private static String normalizeEmail(String email) {
        if (email == null || email.isBlank()) {
            return null;
        }
        String normalized = email.trim().toLowerCase(Locale.ROOT);
        if (!normalized.contains("@") || normalized.startsWith("@") || normalized.endsWith("@")) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "email is invalid");
        }
        return normalized;
    }

    private static UserResponse toResponse(IamUserEntity entity) {
        return new UserResponse(
                entity.getId(),
                entity.getSubjectId().toString(),
                entity.getUsername(),
                entity.getDisplayName(),
                entity.getEmail(),
                entity.getStatus(),
                entity.getTenantId(),
                entity.getOrgId(),
                entity.getCreatedAt(),
                entity.getUpdatedAt());
    }
}
