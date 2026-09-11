package com.example.iam.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.iam.clientregistry.entity.IamClientEntity;
import com.example.iam.clientregistry.repository.IamClientRepository;
import com.example.iam.common.util.HashUtils;
import com.example.iam.token.entity.IamRefreshTokenEntity;
import com.example.iam.token.repository.IamRefreshTokenRepository;
import com.example.iam.user.entity.IamUserEntity;
import com.example.iam.user.repository.IamUserRepository;
import java.time.Instant;
import java.util.UUID;
import com.example.iam.authorizationserver.AbstractIamIntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import com.example.iam.authorizationserver.IamAuthorizationServerApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;

@SpringBootTest(classes = IamAuthorizationServerApplication.class)
class IamRefreshTokenRepositoryTest extends AbstractIamIntegrationTest {

    @Autowired
    private IamRefreshTokenRepository repository;
    @Autowired
    private IamUserRepository userRepository;
    @Autowired
    private IamClientRepository clientRepository;

    @Test
    void savesOnlyHashAndQueriesByHash() {
        UUID subjectId = UUID.randomUUID();
        UUID clientId = UUID.randomUUID();
        UUID sessionId = UUID.randomUUID();
        String rawToken = "raw-refresh-token-" + UUID.randomUUID();
        String tokenHash = HashUtils.sha256Hex(rawToken);
        UUID userId = createUser(subjectId, "user-" + UUID.randomUUID());
        UUID clientDbId = createClient("client-" + UUID.randomUUID());

        IamRefreshTokenEntity entity = IamRefreshTokenEntity.builder()
                .tokenHash(tokenHash)
                .subjectId(userId)
                .clientId(clientDbId)
                .sessionId(sessionId)
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .status("ACTIVE")
                .build();
        IamRefreshTokenEntity saved = repository.saveAndFlush(entity);

        assertThat(saved.getTokenHash())
                .hasSize(64)
                .isEqualTo(tokenHash)
                .isNotEqualTo(rawToken);
        assertThat(repository.findByTokenHash(tokenHash)).isPresent();
        assertThat(repository.findBySessionId(sessionId)).hasSize(1);
    }

    @Test
    void rejectsDuplicateTokenHash() {
        String tokenHash = HashUtils.sha256Hex("refresh-token-" + UUID.randomUUID());
        UUID userId = createUser(UUID.randomUUID(), "user-" + UUID.randomUUID());
        UUID clientDbId = createClient("client-" + UUID.randomUUID());
        repository.saveAndFlush(refreshToken(tokenHash, userId, clientDbId, UUID.randomUUID()));
        assertThatThrownBy(() -> repository.saveAndFlush(refreshToken(
                tokenHash, userId, clientDbId, UUID.randomUUID())))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    private UUID createUser(UUID subjectId, String username) {
        return userRepository.saveAndFlush(IamUserEntity.builder()
                        .subjectId(subjectId)
                        .username(username)
                        .status("ACTIVE")
                        .tenantId("tenant-1")
                        .createdAt(Instant.now())
                        .updatedAt(Instant.now())
                        .build())
                .getId();
    }

    private UUID createClient(String clientId) {
        return clientRepository.saveAndFlush(IamClientEntity.builder()
                        .clientId(clientId)
                        .clientName("Client")
                        .clientType("CONFIDENTIAL")
                        .status("ACTIVE")
                        .tokenEndpointAuthMethod("client_secret_basic")
                        .accessTokenTtl(900)
                        .refreshTokenTtl(86400)
                        .pkceRequired(true)
                        .createdAt(Instant.now())
                        .updatedAt(Instant.now())
                        .build())
                .getId();
    }

    private IamRefreshTokenEntity refreshToken(
            String tokenHash, UUID subjectId, UUID clientId, UUID sessionId) {
        return IamRefreshTokenEntity.builder()
                .tokenHash(tokenHash)
                .subjectId(subjectId)
                .clientId(clientId)
                .sessionId(sessionId)
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .status("ACTIVE")
                .build();
    }
}
