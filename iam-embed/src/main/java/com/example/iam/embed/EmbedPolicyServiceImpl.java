package com.example.iam.embed;

import com.example.iam.clientregistry.domain.RegistryStatus;
import com.example.iam.clientregistry.dto.ClientResponse;
import com.example.iam.clientregistry.entity.IamClientEntity;
import com.example.iam.clientregistry.repository.IamClientRepository;
import com.example.iam.clientregistry.service.IamClientService;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.embed.entity.IamEmbedPolicyEntity;
import com.example.iam.embed.repository.IamEmbedPolicyRepository;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;

@Service
public class EmbedPolicyServiceImpl implements EmbedPolicyService {

    private final IamEmbedPolicyRepository policyRepository;
    private final IamClientService clientService;
    private final IamClientRepository clientRepository;
    private final OriginValidator originValidator;

    public EmbedPolicyServiceImpl(
            IamEmbedPolicyRepository policyRepository,
            IamClientService clientService,
            IamClientRepository clientRepository,
            OriginValidator originValidator) {
        this.policyRepository = policyRepository;
        this.clientService = clientService;
        this.clientRepository = clientRepository;
        this.originValidator = originValidator;
    }

    @Override
    public IamEmbedPolicyEntity requireActive(String parentClientId, String childClientId, String origin, String path) {
        IamClientEntity parent = clientService.requireActiveClient(parentClientId);
        IamClientEntity child = clientService.requireActiveClient(childClientId);
        originValidator.requireExplicitOrigin(origin);
        String normalizedPath = normalizePath(path);
        List<IamEmbedPolicyEntity> policies =
                policyRepository.findByChildClientIdAndParentClientId(child.getId(), parent.getId());
        IamEmbedPolicyEntity matched = null;
        boolean disabledMatch = false;
        for (IamEmbedPolicyEntity policy : policies) {
            if (!origin.equals(policy.getParentOrigin())) {
                continue;
            }
            if (!pathAllowed(normalizedPath, policy.getAllowedPath())) {
                continue;
            }
            if (!RegistryStatus.isActive(policy.getStatus())) {
                disabledMatch = true;
                continue;
            }
            matched = policy;
            break;
        }
        if (matched != null) {
            return matched;
        }
        if (disabledMatch) {
            throw new IamException(IamErrorCode.EMBED_POLICY_DISABLED, "embed policy is disabled");
        }
        if (policies.stream().anyMatch(policy -> origin.equals(policy.getParentOrigin()))) {
            throw new IamException(IamErrorCode.EMBED_PATH_NOT_ALLOWED, "embed path is not allowed");
        }
        throw new IamException(IamErrorCode.FORBIDDEN, "no iframe embed policy for this parent/child/origin");
    }

    @Override
    public EmbedPolicyView create(String parentClientId, String childClientId, String origin, String path) {
        ClientResponse parent = clientService.get(parentClientId);
        ClientResponse child = clientService.get(childClientId);
        if (parent.id().equals(child.id())) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "parent and child clients must differ");
        }
        originValidator.requireExplicitOrigin(origin);
        String allowedPath = validateAllowedPath(path);
        if (policyRepository.existsByChildClientIdAndParentClientIdAndParentOriginAndAllowedPath(
                child.id(), parent.id(), origin, allowedPath)) {
            throw new IamException(IamErrorCode.CONFLICT, "embed policy already exists");
        }
        IamEmbedPolicyEntity saved = policyRepository.save(IamEmbedPolicyEntity.builder()
                .parentClientId(parent.id())
                .childClientId(child.id())
                .parentOrigin(origin)
                .allowedPath(allowedPath)
                .status(RegistryStatus.INACTIVE)
                .createdAt(Instant.now())
                .build());
        return toView(saved, parent.clientId(), child.clientId());
    }

    @Override
    public EmbedPolicyView update(UUID id, String origin, String path) {
        IamEmbedPolicyEntity entity = require(id);
        originValidator.requireExplicitOrigin(origin);
        String allowedPath = validateAllowedPath(path);
        if (policyRepository.existsByChildClientIdAndParentClientIdAndParentOriginAndAllowedPath(
                        entity.getChildClientId(), entity.getParentClientId(), origin, allowedPath)
                && !(origin.equals(entity.getParentOrigin()) && allowedPath.equals(entity.getAllowedPath()))) {
            throw new IamException(IamErrorCode.CONFLICT, "embed policy already exists");
        }
        entity.setParentOrigin(origin);
        entity.setAllowedPath(allowedPath);
        return toView(policyRepository.save(entity));
    }

    @Override
    public EmbedPolicyView get(UUID id) {
        return toView(require(id));
    }

    @Override
    public List<EmbedPolicyView> list(String parentClientId, String childClientId) {
        UUID parentPk = parentClientId == null || parentClientId.isBlank() ? null : clientService.get(parentClientId).id();
        UUID childPk = childClientId == null || childClientId.isBlank() ? null : clientService.get(childClientId).id();
        List<IamEmbedPolicyEntity> rows;
        if (parentPk != null && childPk != null) {
            rows = policyRepository.findByChildClientIdAndParentClientId(childPk, parentPk);
        } else if (parentPk != null) {
            rows = policyRepository.findByParentClientId(parentPk);
        } else if (childPk != null) {
            rows = policyRepository.findByChildClientId(childPk);
        } else {
            rows = policyRepository.findAll();
        }
        return rows.stream().map(this::toView).toList();
    }

    @Override
    public EmbedPolicyView enable(UUID id) {
        IamEmbedPolicyEntity entity = require(id);
        entity.setStatus(RegistryStatus.ACTIVE);
        return toView(policyRepository.save(entity));
    }

    @Override
    public EmbedPolicyView disable(UUID id) {
        IamEmbedPolicyEntity entity = require(id);
        entity.setStatus(RegistryStatus.INACTIVE);
        return toView(policyRepository.save(entity));
    }

    static String validateAllowedPath(String path) {
        if (path == null || path.isBlank()) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "path is required");
        }
        String trimmed = path.trim();
        if ("*".equals(trimmed) || "/*".equals(trimmed)) {
            throw new IamException(IamErrorCode.EMBED_PATH_NOT_ALLOWED, "wildcard path is not allowed");
        }
        if (trimmed.contains("*") && !trimmed.endsWith("/*")) {
            throw new IamException(IamErrorCode.EMBED_PATH_NOT_ALLOWED, "wildcard path is not allowed");
        }
        if (trimmed.endsWith("/*")) {
            String base = trimmed.substring(0, trimmed.length() - 2);
            normalizePath(base);
            return trimmed;
        }
        return normalizePath(trimmed);
    }

    static String normalizePath(String path) {
        if (path == null || path.isBlank()) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "path is required");
        }
        String trimmed = path.trim();
        if (!trimmed.startsWith("/") || trimmed.contains("..") || trimmed.contains("//")) {
            throw new IamException(IamErrorCode.EMBED_PATH_NOT_ALLOWED, "embed path is not allowed");
        }
        return trimmed;
    }

    static boolean pathAllowed(String requested, String allowed) {
        if (allowed == null || allowed.isBlank()) {
            return false;
        }
        if (allowed.endsWith("/*")) {
            String prefix = allowed.substring(0, allowed.length() - 1);
            String base = allowed.substring(0, allowed.length() - 2);
            return requested.equals(base) || requested.startsWith(prefix);
        }
        return requested.equals(allowed);
    }

    private IamEmbedPolicyEntity require(UUID id) {
        if (id == null) {
            throw new IamException(IamErrorCode.NOT_FOUND, "embed policy not found");
        }
        return policyRepository
                .findById(id)
                .orElseThrow(() -> new IamException(IamErrorCode.NOT_FOUND, "embed policy not found"));
    }

    private EmbedPolicyView toView(IamEmbedPolicyEntity entity) {
        String parent = clientRepository
                .findById(entity.getParentClientId())
                .map(IamClientEntity::getClientId)
                .orElse(entity.getParentClientId().toString());
        String child = clientRepository
                .findById(entity.getChildClientId())
                .map(IamClientEntity::getClientId)
                .orElse(entity.getChildClientId().toString());
        return toView(entity, parent, child);
    }

    private static EmbedPolicyView toView(IamEmbedPolicyEntity entity, String parentClientId, String childClientId) {
        return new EmbedPolicyView(
                entity.getId(),
                parentClientId,
                childClientId,
                entity.getParentOrigin(),
                entity.getAllowedPath(),
                entity.getStatus(),
                entity.getCreatedAt());
    }
}
