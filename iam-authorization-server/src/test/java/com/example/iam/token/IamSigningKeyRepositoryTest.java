package com.example.iam.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.iam.token.entity.IamSigningKeyEntity;
import com.example.iam.token.repository.IamSigningKeyRepository;
import java.time.Instant;
import java.util.UUID;
import com.example.iam.authorizationserver.AbstractIamIntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import com.example.iam.authorizationserver.IamAuthorizationServerApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;

@SpringBootTest(classes = IamAuthorizationServerApplication.class)
class IamSigningKeyRepositoryTest extends AbstractIamIntegrationTest {

    @Autowired
    private IamSigningKeyRepository repository;

    @Test
    void savesAndQueriesSigningKeyByKid() {
        String kid = "key-" + UUID.randomUUID();
        IamSigningKeyEntity entity = IamSigningKeyEntity.builder()
                .kid(kid)
                .algorithm("RS256")
                .kmsKeyId("kms-key-id")
                .status("ACTIVE")
                .activatedAt(Instant.now())
                .createdAt(Instant.now())
                .build();

        IamSigningKeyEntity saved = repository.saveAndFlush(entity);

        assertThat(saved.getId()).isNotNull();
        assertThat(repository.findByKid(kid)).isPresent();
        assertThat(repository.findByStatus("ACTIVE")).extracting(IamSigningKeyEntity::getKid).contains(kid);
    }

    @Test
    void rejectsDuplicateKid() {
        String kid = "key-" + UUID.randomUUID();
        repository.saveAndFlush(key(kid));
        assertThatThrownBy(() -> repository.saveAndFlush(key(kid)))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    private IamSigningKeyEntity key(String kid) {
        return IamSigningKeyEntity.builder()
                .kid(kid)
                .algorithm("RS256")
                .kmsKeyId("kms-key-id")
                .status("ACTIVE")
                .createdAt(Instant.now())
                .build();
    }
}
