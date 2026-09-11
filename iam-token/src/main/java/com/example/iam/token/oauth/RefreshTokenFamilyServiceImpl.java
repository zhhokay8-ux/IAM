package com.example.iam.token.oauth;

import com.example.iam.common.util.HashUtils;
import com.example.iam.token.entity.IamRefreshTokenEntity;
import com.example.iam.token.redis.RefreshTokenStatusRepository;
import com.example.iam.token.repository.IamRefreshTokenRepository;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class RefreshTokenFamilyServiceImpl implements RefreshTokenFamilyService {

    private final IamRefreshTokenRepository repository;
    private final RefreshTokenStatusRepository statusRepository;

    public RefreshTokenFamilyServiceImpl(
            IamRefreshTokenRepository repository, RefreshTokenStatusRepository statusRepository) {
        this.repository = repository;
        this.statusRepository = statusRepository;
    }

    @Override
    @Transactional
    public void revokeFamily(UUID familyId) {
        if (familyId == null) {
            return;
        }
        revokeAll(repository.findBySessionId(familyId));
    }

    @Override
    @Transactional
    public void revokeAllForSubject(UUID subjectId) {
        if (subjectId == null) {
            return;
        }
        revokeAll(repository.findBySubjectId(subjectId));
    }

    @Override
    @Transactional
    public boolean revokePresentedToken(String presentedToken) {
        Optional<IamRefreshTokenEntity> found = findByPresentedToken(presentedToken);
        if (found.isEmpty()) {
            return false;
        }
        revokeFamily(found.get().getSessionId());
        return true;
    }

    @Override
    public Optional<IamRefreshTokenEntity> findByPresentedToken(String presentedToken) {
        if (presentedToken == null || presentedToken.isBlank()) {
            return Optional.empty();
        }
        return repository.findByTokenHash(HashUtils.sha256Hex(presentedToken));
    }

    void revoke(IamRefreshTokenEntity entity) {
        entity.setStatus(RefreshTokenServiceImpl.STATUS_REVOKED);
        entity.setRevokedAt(Instant.now());
        repository.save(entity);
        statusRepository.revoke(entity.getTokenHash());
    }

    private void revokeAll(List<IamRefreshTokenEntity> tokens) {
        for (IamRefreshTokenEntity entity : tokens) {
            if (!"REVOKED".equals(entity.getStatus())) {
                revoke(entity);
            } else {
                statusRepository.revoke(entity.getTokenHash());
            }
        }
    }
}
