package com.example.iam.embed.redis;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.iam.authorizationserver.AbstractIamIntegrationTest;
import com.example.iam.embed.repository.EmbedCodeRepository;
import java.time.Duration;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import com.example.iam.authorizationserver.IamAuthorizationServerApplication;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(classes = IamAuthorizationServerApplication.class)
class EmbedCodeRepositoryTest extends AbstractIamIntegrationTest {

    @Autowired
    private EmbedCodeRepository repository;

    @Test
    void savesQueriesAndConsumesEmbedCodeOnce() {
        String code = UUID.randomUUID().toString();
        String value = "embed-code-value";

        repository.save(code, value);

        assertThat(repository.get(code)).contains(value);
        assertThat(repository.getTtl(code))
                .isGreaterThan(Duration.ofSeconds(29))
                .isLessThanOrEqualTo(Duration.ofSeconds(30));
        assertThat(repository.consume(code)).contains(value);
        assertThat(repository.consume(code)).isEmpty();
        assertThat(repository.get(code)).isEmpty();
    }
}
