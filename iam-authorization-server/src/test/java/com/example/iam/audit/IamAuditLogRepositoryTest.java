package com.example.iam.audit;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.iam.audit.entity.IamAuditLogEntity;
import com.example.iam.audit.repository.IamAuditLogRepository;
import java.time.Instant;
import java.util.UUID;
import com.example.iam.authorizationserver.AbstractIamIntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import com.example.iam.authorizationserver.IamAuthorizationServerApplication;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(classes = IamAuthorizationServerApplication.class)
class IamAuditLogRepositoryTest extends AbstractIamIntegrationTest {

    @Autowired
    private IamAuditLogRepository repository;

    @Test
    void savesAndQueriesAuditLog() {
        String traceId = UUID.randomUUID().toString();
        UUID subjectId = UUID.randomUUID();
        UUID clientId = UUID.randomUUID();
        IamAuditLogEntity entity = IamAuditLogEntity.builder()
                .traceId(traceId)
                .eventType("TOKEN_ISSUED")
                .subjectId(subjectId)
                .clientId(clientId)
                .sourceIp("127.0.0.1")
                .userAgent("JUnit")
                .result("SUCCESS")
                .createdAt(Instant.now())
                .build();

        IamAuditLogEntity saved = repository.saveAndFlush(entity);

        assertThat(saved.getId()).isNotNull();
        assertThat(repository.findByTraceId(traceId)).hasSize(1);
        assertThat(repository.findBySubjectId(subjectId)).hasSize(1);
        assertThat(repository.findByClientId(clientId)).hasSize(1);
    }
}
