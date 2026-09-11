package com.example.iam.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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
class IamUserRepositoryTest extends AbstractIamIntegrationTest {

    @Autowired
    private IamUserRepository repository;

    @Test
    void savesAndQueriesUser() {
        UUID subjectId = UUID.randomUUID();
        String username = "user-" + UUID.randomUUID();
        IamUserEntity entity = IamUserEntity.builder()
                .subjectId(subjectId)
                .username(username)
                .displayName("Test User")
                .status("ACTIVE")
                .tenantId("tenant-1")
                .orgId("org-1")
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .build();

        IamUserEntity saved = repository.saveAndFlush(entity);

        assertThat(saved.getId()).isNotNull();
        assertThat(repository.findBySubjectId(subjectId)).hasValueSatisfying(found ->
                assertThat(found.getUsername()).isEqualTo(username));
        assertThat(repository.findByUsernameAndTenantId(username, "tenant-1")).isPresent();
    }

    @Test
    void rejectsDuplicateSubjectId() {
        UUID subjectId = UUID.randomUUID();
        repository.saveAndFlush(user(subjectId, "user-" + UUID.randomUUID()));
        assertThatThrownBy(() -> repository.saveAndFlush(user(subjectId, "user-" + UUID.randomUUID())))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    private IamUserEntity user(UUID subjectId, String username) {
        return IamUserEntity.builder()
                .subjectId(subjectId)
                .username(username)
                .status("ACTIVE")
                .tenantId("tenant-1")
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .build();
    }
}
