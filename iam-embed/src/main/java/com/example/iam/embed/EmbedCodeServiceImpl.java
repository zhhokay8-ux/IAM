package com.example.iam.embed;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.core.redis.IamRedisProperties;
import com.example.iam.embed.repository.EmbedCodeRepository;
import com.example.iam.user.service.IamUserService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class EmbedCodeServiceImpl implements EmbedCodeService, EmbedCodeExchangeService {

    private final EmbedPolicyService policyService;
    private final OriginValidator originValidator;
    private final EmbedCodeGenerator generator;
    private final EmbedCodeValidator validator;
    private final EmbedCodeRepository repository;
    private final IamUserService userService;
    private final IamRedisProperties redisProperties;
    private final ObjectMapper objectMapper;
    private final Clock clock;

    @Autowired
    public EmbedCodeServiceImpl(
            EmbedPolicyService policyService,
            OriginValidator originValidator,
            EmbedCodeGenerator generator,
            EmbedCodeValidator validator,
            EmbedCodeRepository repository,
            IamUserService userService,
            IamRedisProperties redisProperties,
            ObjectMapper objectMapper) {
        this(
                policyService,
                originValidator,
                generator,
                validator,
                repository,
                userService,
                redisProperties,
                objectMapper,
                Clock.systemUTC());
    }

    EmbedCodeServiceImpl(
            EmbedPolicyService policyService,
            OriginValidator originValidator,
            EmbedCodeGenerator generator,
            EmbedCodeValidator validator,
            EmbedCodeRepository repository,
            IamUserService userService,
            IamRedisProperties redisProperties,
            ObjectMapper objectMapper,
            Clock clock) {
        this.policyService = policyService;
        this.originValidator = originValidator;
        this.generator = generator;
        this.validator = validator;
        this.repository = repository;
        this.userService = userService;
        this.redisProperties = redisProperties;
        this.objectMapper = objectMapper;
        this.clock = clock;
    }

    @Override
    public CreateEmbedCodeResponse issue(
            CreateEmbedCodeRequest request, String parentClientId, String subjectId, String sessionId) {
        if (request == null) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "embed request is required");
        }
        if (parentClientId == null || parentClientId.isBlank()) {
            throw new IamException(IamErrorCode.INVALID_CLIENT, "parent client is required");
        }
        if (sessionId == null || sessionId.isBlank()) {
            throw new IamException(IamErrorCode.SESSION_NOT_FOUND, "SSO session is required");
        }
        requireUser(subjectId);
        originValidator.requireExplicitOrigin(request.origin());
        if (request.nonce() == null || request.nonce().isBlank()) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "nonce is required");
        }
        var policy = policyService.requireActive(
                parentClientId, request.childClientId(), request.origin(), request.path());
        Instant now = clock.instant();
        Duration ttl = redisProperties.getEmbedCodeTtl();
        Instant expiresAt = now.plus(ttl);
        String code = generator.next();
        EmbedContext context = new EmbedContext(
                code,
                parentClientId,
                request.childClientId(),
                subjectId,
                sessionId,
                request.nonce(),
                request.origin(),
                policy.getAllowedPath(),
                now,
                expiresAt);
        repository.save(code, write(context), ttl);
        return new CreateEmbedCodeResponse(code, expiresAt, request.childClientId(), request.path(), request.nonce());
    }

    @Override
    public EmbedContext exchange(ExchangeEmbedCodeRequest request, String childClientId) {
        if (request == null || request.code() == null || request.code().isBlank()) {
            throw new IamException(IamErrorCode.EMBED_CODE_NOT_FOUND, "embed code is required");
        }
        String raw = repository.get(request.code())
                .orElseThrow(() -> new IamException(IamErrorCode.EMBED_CODE_REPLAY, "embed code not found or already used"));
        EmbedContext stored = read(raw);
        EmbedContext validated = validator.validateForExchange(stored, request, childClientId);
        if (repository.consume(request.code()).isEmpty()) {
            throw new IamException(IamErrorCode.EMBED_CODE_REPLAY, "embed code already used");
        }
        return validated;
    }

    private void requireUser(String subjectId) {
        if (subjectId == null || subjectId.isBlank()) {
            throw new IamException(IamErrorCode.USER_NOT_FOUND, "subject is required");
        }
        try {
            userService.requireUser(UUID.fromString(subjectId));
        } catch (IllegalArgumentException ex) {
            throw new IamException(IamErrorCode.USER_NOT_FOUND, "subject_id is invalid", ex);
        }
    }

    private String write(EmbedContext context) {
        try {
            return objectMapper.writeValueAsString(context);
        } catch (JsonProcessingException ex) {
            throw new IamException(IamErrorCode.INTERNAL_ERROR, "failed to serialize embed code", ex);
        }
    }

    private EmbedContext read(String json) {
        try {
            return objectMapper.readValue(json, EmbedContext.class);
        } catch (JsonProcessingException ex) {
            throw new IamException(IamErrorCode.EMBED_CODE_NOT_FOUND, "embed code payload is corrupt", ex);
        }
    }
}
