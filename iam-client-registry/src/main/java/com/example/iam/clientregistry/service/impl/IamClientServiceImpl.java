package com.example.iam.clientregistry.service.impl;

import com.example.iam.clientregistry.domain.ClientType;
import com.example.iam.clientregistry.domain.RedirectUriType;
import com.example.iam.clientregistry.domain.RegistryStatus;
import com.example.iam.clientregistry.dto.ClientResponse;
import com.example.iam.clientregistry.dto.CreateClientRequest;
import com.example.iam.clientregistry.dto.RedirectUriInput;
import com.example.iam.clientregistry.dto.RotatedSecretResponse;
import com.example.iam.clientregistry.dto.UpdateClientRequest;
import com.example.iam.clientregistry.entity.IamClientEntity;
import com.example.iam.clientregistry.entity.IamClientRedirectUriEntity;
import com.example.iam.clientregistry.repository.IamClientRedirectUriRepository;
import com.example.iam.clientregistry.repository.IamClientRepository;
import com.example.iam.clientregistry.service.IamClientService;
import com.example.iam.clientregistry.validation.IamClientValidator;
import com.example.iam.clientregistry.validation.IamRedirectUriValidator;
import com.example.iam.audit.AuditEvent;
import com.example.iam.audit.IamAuditService;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.common.util.HashUtils;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

@Service
public class IamClientServiceImpl implements IamClientService {

    private static final Logger log = LoggerFactory.getLogger(IamClientServiceImpl.class);
    private static final SecureRandom RANDOM = new SecureRandom();

    private final IamClientRepository clientRepository;
    private final IamClientRedirectUriRepository redirectUriRepository;
    private final IamClientValidator clientValidator;
    private final IamRedirectUriValidator redirectUriValidator;
    private final IamAuditService auditService;

    public IamClientServiceImpl(
            IamClientRepository clientRepository,
            IamClientRedirectUriRepository redirectUriRepository,
            IamClientValidator clientValidator,
            IamRedirectUriValidator redirectUriValidator) {
        this(clientRepository, redirectUriRepository, clientValidator, redirectUriValidator, null);
    }

    @Autowired
    public IamClientServiceImpl(
            IamClientRepository clientRepository,
            IamClientRedirectUriRepository redirectUriRepository,
            IamClientValidator clientValidator,
            IamRedirectUriValidator redirectUriValidator,
            IamAuditService auditService) {
        this.clientRepository = clientRepository;
        this.redirectUriRepository = redirectUriRepository;
        this.clientValidator = clientValidator;
        this.redirectUriValidator = redirectUriValidator;
        this.auditService = auditService;
    }

    @Override
    @Transactional
    public ClientResponse create(CreateClientRequest request) {
        Objects.requireNonNull(request, "request");
        clientValidator.assertSecretNotLogged(request.toString());
        if (request.clientId() == null || request.clientId().isBlank()) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "client_id is required");
        }
        if (clientRepository.existsByClientId(request.clientId())) {
            throw new IamException(IamErrorCode.DUPLICATE_CLIENT_ID, "client_id already exists");
        }
        Instant now = Instant.now();
        IamClientEntity entity = IamClientEntity.builder()
                .clientId(request.clientId())
                .clientName(requireName(request.clientName()))
                .clientType(clientValidator.validateClientType(request.clientType()))
                .status(RegistryStatus.normalize(request.status()))
                .tokenEndpointAuthMethod(defaultAuthMethod(request.tokenEndpointAuthMethod(), request.clientType()))
                .accessTokenTtl(requirePositive(request.accessTokenTtl(), "access_token_ttl"))
                .refreshTokenTtl(requirePositive(request.refreshTokenTtl(), "refresh_token_ttl"))
                .pkceRequired(request.pkceRequired() == null || request.pkceRequired())
                .clientSecretHash(hashSecret(request.clientSecret(), request.clientType()))
                .owner(request.owner())
                .createdAt(now)
                .updatedAt(now)
                .build();
        IamClientEntity saved = clientRepository.save(entity);
        saveRedirectUris(saved, request.redirectUris());
        log.info("Created client {}", saved.getClientId());
        audit(AuditEvent.CLIENT_CREATED, saved.getClientId());
        return toResponse(saved);
    }

    @Override
    @Transactional
    public ClientResponse update(String clientId, UpdateClientRequest request) {
        IamClientEntity entity = clientRepository.findByClientId(clientId)
                .orElseThrow(() -> new IamException(IamErrorCode.CLIENT_NOT_FOUND, "client_id not found: " + clientId));
        if (request.clientName() != null) {
            entity.setClientName(requireName(request.clientName()));
        }
        if (request.status() != null) {
            entity.setStatus(RegistryStatus.normalize(request.status()));
        }
        if (request.tokenEndpointAuthMethod() != null) {
            entity.setTokenEndpointAuthMethod(request.tokenEndpointAuthMethod());
        }
        if (request.accessTokenTtl() != null) {
            entity.setAccessTokenTtl(requirePositive(request.accessTokenTtl(), "access_token_ttl"));
        }
        if (request.refreshTokenTtl() != null) {
            entity.setRefreshTokenTtl(requirePositive(request.refreshTokenTtl(), "refresh_token_ttl"));
        }
        if (request.pkceRequired() != null) {
            entity.setPkceRequired(request.pkceRequired());
        }
        if (request.owner() != null) {
            entity.setOwner(request.owner());
        }
        entity.setUpdatedAt(Instant.now());
        IamClientEntity saved = clientRepository.save(entity);
        if (request.redirectUris() != null) {
            redirectUriRepository.deleteAll(redirectUriRepository.findByClientId(saved.getId()));
            saveRedirectUris(saved, request.redirectUris());
        }
        audit(AuditEvent.CLIENT_UPDATED, saved.getClientId());
        return toResponse(saved);
    }

    @Override
    @Transactional(readOnly = true)
    public ClientResponse get(String clientId) {
        IamClientEntity entity = clientRepository.findByClientId(clientId)
                .orElseThrow(() -> new IamException(IamErrorCode.CLIENT_NOT_FOUND, "client_id not found: " + clientId));
        return toResponse(entity);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<ClientResponse> search(String query, String status, Pageable pageable) {
        Specification<IamClientEntity> spec = (root, q, cb) -> {
            List<jakarta.persistence.criteria.Predicate> predicates = new ArrayList<>();
            if (StringUtils.hasText(status)) {
                predicates.add(cb.equal(root.get("status"), RegistryStatus.normalize(status)));
            }
            if (StringUtils.hasText(query)) {
                String like = "%" + query.trim().toLowerCase(Locale.ROOT) + "%";
                predicates.add(cb.or(
                        cb.like(cb.lower(root.get("clientId")), like),
                        cb.like(cb.lower(root.get("clientName")), like)));
            }
            return cb.and(predicates.toArray(jakarta.persistence.criteria.Predicate[]::new));
        };
        return clientRepository.findAll(spec, pageable).map(this::toResponse);
    }

    @Override
    @Transactional
    public ClientResponse disable(String clientId) {
        IamClientEntity entity = requireExisting(clientId);
        entity.setStatus(RegistryStatus.INACTIVE);
        entity.setUpdatedAt(Instant.now());
        IamClientEntity saved = clientRepository.save(entity);
        audit(AuditEvent.CLIENT_DISABLED, saved.getClientId());
        log.info("Disabled client {}", saved.getClientId());
        return toResponse(saved);
    }

    @Override
    @Transactional
    public ClientResponse enable(String clientId) {
        IamClientEntity entity = requireExisting(clientId);
        entity.setStatus(RegistryStatus.ACTIVE);
        entity.setUpdatedAt(Instant.now());
        IamClientEntity saved = clientRepository.save(entity);
        audit(AuditEvent.CLIENT_ENABLED, saved.getClientId());
        log.info("Enabled client {}", saved.getClientId());
        return toResponse(saved);
    }

    @Override
    @Transactional
    public RotatedSecretResponse rotateSecret(String clientId) {
        IamClientEntity entity = requireExisting(clientId);
        if (ClientType.PUBLIC.equalsIgnoreCase(entity.getClientType())) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "public clients do not have a client_secret");
        }
        String secret = generateSecret();
        entity.setClientSecretHash(HashUtils.sha256Hex(secret));
        entity.setUpdatedAt(Instant.now());
        IamClientEntity saved = clientRepository.save(entity);
        audit(AuditEvent.SECRET_ROTATED, saved.getClientId());
        log.info("Rotated client secret for {}", saved.getClientId());
        return new RotatedSecretResponse(toResponse(saved), secret);
    }

    @Override
    @Transactional
    public ClientResponse replaceRedirectUris(String clientId, List<RedirectUriInput> redirectUris) {
        IamClientEntity entity = requireExisting(clientId);
        redirectUriRepository.deleteAll(redirectUriRepository.findByClientId(entity.getId()));
        saveRedirectUris(entity, redirectUris == null ? List.of() : redirectUris);
        entity.setUpdatedAt(Instant.now());
        IamClientEntity saved = clientRepository.save(entity);
        audit(AuditEvent.CLIENT_UPDATED, saved.getClientId());
        return toResponse(saved);
    }

    @Override
    @Transactional(readOnly = true)
    public IamClientEntity requireActiveClient(String clientId) {
        return clientValidator.validateClient(clientRepository.findByClientId(clientId), clientId);
    }

    @Override
    public ClientResponse dynamicRegister(CreateClientRequest request) {
        clientValidator.rejectDynamicRegistration();
        return create(request);
    }

    private void saveRedirectUris(IamClientEntity client, List<RedirectUriInput> redirectUris) {
        if (redirectUris == null) {
            return;
        }
        for (RedirectUriInput input : redirectUris) {
            redirectUriValidator.validateSyntax(input.redirectUri());
            String uriType = RedirectUriType.normalize(input.uriType());
            redirectUriRepository.save(IamClientRedirectUriEntity.builder()
                    .clientId(client.getId())
                    .redirectUri(input.redirectUri())
                    .uriType(uriType)
                    .status(RegistryStatus.ACTIVE)
                    .build());
        }
    }

    private ClientResponse toResponse(IamClientEntity entity) {
        List<RedirectUriInput> uris = entity.getId() == null
                ? List.of()
                : redirectUriRepository.findByClientId(entity.getId()).stream()
                        .map(uri -> new RedirectUriInput(uri.getRedirectUri(), uri.getUriType()))
                        .toList();
        return new ClientResponse(
                entity.getId(),
                entity.getClientId(),
                entity.getClientName(),
                entity.getClientType(),
                entity.getStatus(),
                entity.getTokenEndpointAuthMethod(),
                entity.getAccessTokenTtl(),
                entity.getRefreshTokenTtl(),
                entity.getPkceRequired(),
                entity.getOwner(),
                uris,
                entity.getCreatedAt(),
                entity.getUpdatedAt());
    }

    private static String hashSecret(String secret, String clientType) {
        String type = ClientType.normalize(clientType);
        if (ClientType.PUBLIC.equals(type)) {
            return null;
        }
        if (secret == null || secret.isBlank()) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "client_secret is required for confidential clients");
        }
        return HashUtils.sha256Hex(secret);
    }

    private static String requireName(String name) {
        if (name == null || name.isBlank()) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "client_name is required");
        }
        return name;
    }

    private static Integer requirePositive(Integer value, String field) {
        if (value == null || value <= 0) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, field + " must be positive");
        }
        return value;
    }

    private IamClientEntity requireExisting(String clientId) {
        return clientRepository.findByClientId(clientId)
                .orElseThrow(() -> new IamException(IamErrorCode.CLIENT_NOT_FOUND, "client_id not found: " + clientId));
    }

    public static String generateSecret() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private void audit(AuditEvent event, String clientId) {
        if (auditService == null) {
            return;
        }
        auditService.success(event, null, clientId, null);
    }

    private static String defaultAuthMethod(String method, String clientType) {
        if (method != null && !method.isBlank()) {
            return method;
        }
        return "public".equalsIgnoreCase(clientType) ? "none" : "client_secret_basic";
    }
}
