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
class RevokedJtiRepositoryTest extends AbstractIamIntegrationTest {

    @Autowired
    private RevokedJtiRepository repository;

    @Test
    void revokesJtiWithConfiguredTtl() {
        String jti = UUID.randomUUID().toString();

        assertThat(repository.isRevoked(jti)).isFalse();
        repository.revoke(jti);

        assertThat(repository.isRevoked(jti)).isTrue();
        assertThat(repository.getTtl(jti))
                .isGreaterThan(Duration.ofSeconds(890))
                .isLessThanOrEqualTo(Duration.ofMinutes(15));
    }
}
