package com.example.iam.admin.web.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.iam.admin.config.IamAdminProperties;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.common.security.CorsProperties;
import com.example.iam.core.redis.IamRedisProperties;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

class AdminConfigServiceTest {

    @Test
    void snapshotIsReadOnlyRedactsSecretsAndMarksDangerousKeys() {
        MockEnvironment environment = new MockEnvironment();
        environment.setProperty("iam.issuer", "https://auth.example.com");
        environment.setProperty("iam.jwt.algorithm", "RS256");
        environment.setProperty("iam.jwt.access-token-ttl", "10m");
        IamAdminProperties admin = new IamAdminProperties();
        admin.setAccessToken("break-glass-token");
        admin.getOauth().setClientSecret("oauth-secret");
        admin.getLegacyToken().setEnabled(true);
        IamRedisProperties redis = new IamRedisProperties();
        redis.setPkceStateTtl(Duration.ofMinutes(5));
        redis.setSessionTtl(Duration.ofHours(8));
        CorsProperties cors = new CorsProperties();
        cors.getAllowedOrigins().add("https://portal.example.com");
        AdminConfigService service = new AdminConfigService(environment, admin, redis, cors);

        AdminConfigResponse snapshot = service.snapshot();

        assertThat(snapshot.readOnly()).isTrue();
        assertThat(snapshot.restartRequired()).isTrue();
        assertThat(snapshot.sections()).anySatisfy(section -> {
            if ("issuer".equals(section.name())) {
                assertThat(section.dangerous()).isTrue();
                assertThat(section.items()).anyMatch(item -> "iam.issuer".equals(item.key())
                        && "https://auth.example.com".equals(item.value()));
            }
        });
        assertThat(snapshot.sections().stream().flatMap(section -> section.items().stream()).toList())
                .anySatisfy(item -> {
                    if ("iam.admin.access-token".equals(item.key())) {
                        assertThat(item.redacted()).isTrue();
                        assertThat(item.value()).isEqualTo("***");
                        assertThat(item.dangerous()).isTrue();
                    }
                })
                .anySatisfy(item -> {
                    if ("iam.admin.oauth.client-secret".equals(item.key())) {
                        assertThat(item.value()).isEqualTo("***");
                    }
                })
                .anySatisfy(item -> {
                    if ("iam.jwt.access-token-ttl".equals(item.key())) {
                        assertThat(item.redacted()).isFalse();
                    }
                })
                .anySatisfy(item -> {
                    if ("iam.redis.pkce-state-ttl".equals(item.key())) {
                        assertThat(item.value()).isEqualTo("PT5M");
                    }
                });
        assertThatThrownBy(service::rejectMutation)
                .isInstanceOf(IamException.class)
                .extracting(ex -> ((IamException) ex).getErrorCode())
                .isEqualTo(IamErrorCode.FORBIDDEN);
    }
}
