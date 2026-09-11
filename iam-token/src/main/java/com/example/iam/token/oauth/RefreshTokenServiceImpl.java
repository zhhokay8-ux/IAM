package com.example.iam.token.oauth;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.common.util.HashUtils;
import com.example.iam.token.entity.IamRefreshTokenEntity;
import com.example.iam.token.redis.RefreshTokenStatusRepository;
import com.example.iam.token.repository.IamRefreshTokenRepository;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class RefreshTokenServiceImpl implements RefreshTokenService {

    public static final String STATUS_ACTIVE = "ACTIVE";
    public static final String STATUS_REVOKED = "REVOKED";

    private static final SecureRandom RANDOM = new SecureRandom();

    private final IamRefreshTokenRepository repository;
    private final RefreshTokenStatusRepository statusRepository;
    private final RefreshTokenFamilyService familyService;

    public RefreshTokenServiceImpl(
            IamRefreshTokenRepository repository,
            RefreshTokenStatusRepository statusRepository,
            RefreshTokenFamilyService familyService) {
        this.repository = repository;
        this.statusRepository = statusRepository;
        this.familyService = familyService;
    }

    @Override
    @Transactional
    public IssuedRefreshToken issue(
            UUID userPk, UUID clientPk, UUID familyId, String scope, String audience, Duration ttl) {
        return persist(userPk, clientPk, familyId, scope, audience, ttl, null);
    }

    @Override
    @Transactional
    public IssuedRefreshToken rotate(String presentedToken, UUID clientPk) {
        if (presentedToken == null || presentedToken.isBlank()) {
            throw new IamException(IamErrorCode.INVALID_GRANT, "refresh_token is required");
        }
        String hash = HashUtils.sha256Hex(presentedToken);
        IamRefreshTokenEntity current = repository.findByTokenHash(hash).orElseThrow(
                () -> new IamException(IamErrorCode.INVALID_GRANT, "refresh_token is invalid"));
        if (!current.getClientId().equals(clientPk)) {
            throw new IamException(IamErrorCode.INVALID_GRANT, "refresh_token is bound to a different client");
        }
        if (STATUS_REVOKED.equals(current.getStatus()) || statusRepository.isRevoked(hash)) {
            familyService.revokeFamily(current.getSessionId());
            throw new IamException(IamErrorCode.INVALID_GRANT, "refresh_token reuse detected");
        }
        if (current.getExpiresAt().isBefore(Instant.now())) {
            throw new IamException(IamErrorCode.INVALID_GRANT, "refresh_token expired");
        }
        Duration remaining = Duration.between(Instant.now(), current.getExpiresAt());
        if (remaining.isZero() || remaining.isNegative()) {
            throw new IamException(IamErrorCode.INVALID_GRANT, "refresh_token expired");
        }
        revoke(current);
        return persist(
                current.getSubjectId(),
                current.getClientId(),
                current.getSessionId(),
                current.getScope(),
                current.getAudience(),
                remaining,
                current.getId());
    }

    private IssuedRefreshToken persist(
            UUID userPk,
            UUID clientPk,
            UUID familyId,
            String scope,
            String audience,
            Duration ttl,
            UUID parentId) {
        Instant now = Instant.now();
        String token = randomToken();
        String hash = HashUtils.sha256Hex(token);
        IamRefreshTokenEntity saved = repository.save(IamRefreshTokenEntity.builder()
                .tokenHash(hash)
                .subjectId(userPk)
                .clientId(clientPk)
                .sessionId(familyId)
                .issuedAt(now)
                .expiresAt(now.plus(ttl))
                .rotationParentId(parentId)
                .status(STATUS_ACTIVE)
                .scope(scope)
                .audience(audience)
                .build());
        statusRepository.save(hash, STATUS_ACTIVE);
        return new IssuedRefreshToken(token, saved);
    }

    private void revoke(IamRefreshTokenEntity entity) {
        entity.setStatus(STATUS_REVOKED);
        entity.setRevokedAt(Instant.now());
        repository.save(entity);
        statusRepository.revoke(entity.getTokenHash());
    }

    private static String randomToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
