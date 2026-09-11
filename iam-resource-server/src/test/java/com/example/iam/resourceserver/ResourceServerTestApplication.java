package com.example.iam.resourceserver;

import com.example.iam.common.web.GlobalExceptionHandler;
import com.example.iam.resourceserver.jwt.TestJwtSupport;
import com.example.iam.token.signing.JwtKeyResolver;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration;
import org.springframework.boot.autoconfigure.flyway.FlywayAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;

@SpringBootApplication(
        scanBasePackages = "com.example.iam.resourceserver",
        exclude = {
            DataSourceAutoConfiguration.class,
            HibernateJpaAutoConfiguration.class,
            RedisAutoConfiguration.class,
            FlywayAutoConfiguration.class
        })
@Import(GlobalExceptionHandler.class)
public class ResourceServerTestApplication {

    @Bean
    TestJwtSupport testJwtSupport() {
        return new TestJwtSupport();
    }

    @Bean
    JwtKeyResolver jwtKeyResolver(TestJwtSupport testJwtSupport) {
        return testJwtSupport.resolver();
    }
}
