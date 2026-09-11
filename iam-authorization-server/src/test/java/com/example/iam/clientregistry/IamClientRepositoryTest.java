package com.example.iam.clientregistry;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.iam.clientregistry.entity.IamClientEntity;
import com.example.iam.clientregistry.repository.IamClientRepository;
import java.time.Instant;
import java.util.UUID;
import com.example.iam.authorizationserver.AbstractIamIntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import com.example.iam.authorizationserver.IamAuthorizationServerApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;

@SpringBootTest(classes = IamAuthorizationServerApplication.class)
class IamClientRepositoryTest extends AbstractIamIntegrationTest {

    @Autowired
    private IamClientRepository repository;

    @Test
    void savesAndQueriesClient() {
        String clientId = "client-" + UUID.randomUUID();
        IamClientEntity entity = IamClientEntity.builder()
                .clientId(clientId)
                .clientName("Test Client")
                .clientType("CONFIDENTIAL")
                .status("ACTIVE")
                .tokenEndpointAuthMethod("client_secret_basic")
                .accessTokenTtl(900)
                .refreshTokenTtl(86400)
                .pkceRequired(true)
                .owner("iam")
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .build();

        IamClientEntity saved = repository.saveAndFlush(entity);

        assertThat(saved.getId()).isNotNull();
        assertThat(repository.findByClientId(clientId))
                .hasValueSatisfying(found -> {
                    assertThat(found.getClientName()).isEqualTo("Test Client");
                    assertThat(found.getPkceRequired()).isTrue();
                });
    }

    @Test
    void rejectsDuplicateClientId() {
        String clientId = "client-" + UUID.randomUUID();
        repository.saveAndFlush(client(clientId));
        assertThatThrownBy(() -> repository.saveAndFlush(client(clientId)))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    private IamClientEntity client(String clientId) {
        return IamClientEntity.builder()
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
                .build();
    }
}
