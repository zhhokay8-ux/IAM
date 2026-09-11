package com.example.iam.migration.redis;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.iam.authorizationserver.AbstractIamIntegrationTest;
import com.example.iam.migration.repository.MigrationTicketRepository;
import java.time.Duration;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import com.example.iam.authorizationserver.IamAuthorizationServerApplication;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(classes = IamAuthorizationServerApplication.class)
class MigrationTicketRepositoryTest extends AbstractIamIntegrationTest {

    @Autowired
    private MigrationTicketRepository repository;

    @Test
    void savesQueriesAndConsumesMigrationTicketOnce() {
        String ticket = UUID.randomUUID().toString();
        String value = "migration-ticket-value";

        repository.save(ticket, value);

        assertThat(repository.get(ticket)).contains(value);
        assertThat(repository.getTtl(ticket))
                .isGreaterThan(Duration.ofSeconds(30))
                .isLessThanOrEqualTo(Duration.ofSeconds(60));
        assertThat(repository.consume(ticket)).contains(value);
        assertThat(repository.consume(ticket)).isEmpty();
        assertThat(repository.get(ticket)).isEmpty();
    }
}
