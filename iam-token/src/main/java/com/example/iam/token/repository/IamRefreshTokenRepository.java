package com.example.iam.token.repository;

import com.example.iam.token.entity.IamRefreshTokenEntity;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface IamRefreshTokenRepository extends JpaRepository<IamRefreshTokenEntity, UUID> {
    Optional<IamRefreshTokenEntity> findByTokenHash(String tokenHash);
    List<IamRefreshTokenEntity> findBySubjectIdAndClientId(UUID subjectId, UUID clientId);
    List<IamRefreshTokenEntity> findBySessionId(UUID sessionId);
    List<IamRefreshTokenEntity> findBySubjectId(UUID subjectId);
    long countByStatusAndExpiresAtAfter(String status, Instant expiresAt);
}
