package com.example.iam.token.oauth;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.token.redis.AuthorizationCodeRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;
import java.util.Optional;
import org.springframework.stereotype.Service;

@Service
public class AuthorizationCodeServiceImpl implements AuthorizationCodeService {

    private static final int CODE_BYTES = 32;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final AuthorizationCodeRepository repository;
    private final ObjectMapper objectMapper;

    public AuthorizationCodeServiceImpl(AuthorizationCodeRepository repository, ObjectMapper objectMapper) {
        this.repository = repository;
        this.objectMapper = objectMapper;
    }

    @Override
    public String issue(AuthorizationCodePayload payload) {
        Objects.requireNonNull(payload, "payload");
        if (payload.clientId() == null || payload.redirectUri() == null || payload.subject() == null) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "authorization code payload is incomplete");
        }
        String code = randomCode();
        repository.save(code, write(payload));
        return code;
    }

    @Override
    public Optional<AuthorizationCodePayload> find(String code) {
        if (code == null || code.isBlank()) {
            return Optional.empty();
        }
        return repository.get(code).map(this::read);
    }

    @Override
    public AuthorizationCodePayload consume(String code, String clientId, String redirectUri) {
        if (code == null || code.isBlank()) {
            throw new IamException(IamErrorCode.INVALID_GRANT, "authorization code is required");
        }
        var stored = repository.consume(code);
        if (stored.isEmpty()) {
            throw new IamException(IamErrorCode.INVALID_GRANT, "authorization code is invalid, expired, or already used");
        }
        AuthorizationCodePayload payload = read(stored.get());
        if (!payload.clientId().equals(clientId) || !payload.redirectUri().equals(redirectUri)) {
            throw new IamException(IamErrorCode.INVALID_GRANT, "authorization code is bound to a different client or redirect_uri");
        }
        return payload;
    }

    static String randomCode() {
        byte[] bytes = new byte[CODE_BYTES];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String write(AuthorizationCodePayload payload) {
        try {
            return objectMapper.writeValueAsString(payload);
        } catch (JsonProcessingException ex) {
            throw new IamException(IamErrorCode.INTERNAL_ERROR, "failed to serialize authorization code", ex);
        }
    }

    private AuthorizationCodePayload read(String json) {
        try {
            return objectMapper.readValue(json, AuthorizationCodePayload.class);
        } catch (JsonProcessingException ex) {
            throw new IamException(IamErrorCode.INVALID_GRANT, "authorization code payload is corrupt");
        }
    }
}
