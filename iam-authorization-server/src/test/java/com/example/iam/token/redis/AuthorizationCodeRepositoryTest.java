package com.example.iam.token.redis;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.iam.authorizationserver.AbstractIamIntegrationTest;
import java.time.Duration;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import com.example.iam.authorizationserver.IamAuthorizationServerApplication;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(classes = IamAuthorizationServerApplication.class)
class AuthorizationCodeRepositoryTest extends AbstractIamIntegrationTest {

    @Autowired
    private AuthorizationCodeRepository repository;

    @Test
    void savesQueriesAndConsumesCodeOnce() {
        String code = UUID.randomUUID().toString();
        String value = "authorization-code-value";

        repository.save(code, value);

        assertThat(repository.get(code)).contains(value);
        assertThat(repository.getTtl(code))
                .isGreaterThan(Duration.ofSeconds(59))
                .isLessThanOrEqualTo(Duration.ofSeconds(60));
        assertThat(repository.consume(code)).contains(value);
        assertThat(repository.consume(code)).isEmpty();
        assertThat(repository.get(code)).isEmpty();
    }
}
