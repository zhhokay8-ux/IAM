package com.example.iam.gateway;

import com.example.iam.sdk.IamJwksClient;
import com.example.iam.sdk.IamProperties;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
@EnableConfigurationProperties({IamGatewayProperties.class, IamProperties.class})
public class IamGatewayApplication {

    public static void main(String[] args) {
        org.springframework.boot.SpringApplication.run(IamGatewayApplication.class, args);
    }

    @Bean
    IamJwksClient iamJwksClient(IamGatewayProperties properties) {
        return new IamJwksClient(properties.getIssuer(), java.time.Duration.ofHours(1));
    }

    @Bean
    FilterRegistrationBean<RequestIdFilter> requestIdFilter() {
        return register(new RequestIdFilter());
    }

    @Bean
    FilterRegistrationBean<CorsGatewayFilter> corsGatewayFilter(IamGatewayProperties properties) {
        return register(new CorsGatewayFilter(properties.getCorsAllowedOrigins()));
    }

    @Bean
    FilterRegistrationBean<RateLimitFilter> rateLimitFilter(IamGatewayProperties properties) {
        return register(new RateLimitFilter(properties.getRateLimit(), properties.getRateLimitWindow()));
    }

    @Bean
    FilterRegistrationBean<JwtGatewayFilter> jwtGatewayFilter(IamJwksClient jwksClient, IamGatewayProperties properties) {
        return register(new JwtGatewayFilter(
                jwksClient, properties.getIssuer(), properties.getClockSkew(), properties.getPermitAll()));
    }

    @Bean
    FilterRegistrationBean<AuditGatewayFilter> auditGatewayFilter() {
        return register(new AuditGatewayFilter());
    }

    private static <T extends IamGatewayFilter> FilterRegistrationBean<T> register(T filter) {
        FilterRegistrationBean<T> registration = new FilterRegistrationBean<>(filter);
        registration.setOrder(filter.getOrder());
        registration.addUrlPatterns("/*");
        return registration;
    }
}
