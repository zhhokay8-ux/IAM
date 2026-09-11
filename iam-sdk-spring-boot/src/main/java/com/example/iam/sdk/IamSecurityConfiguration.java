package com.example.iam.sdk;

import com.example.iam.resourceserver.jwt.AudienceValidator;
import com.example.iam.resourceserver.jwt.IssuerValidator;
import com.example.iam.resourceserver.jwt.JtiValidator;
import com.example.iam.resourceserver.jwt.JwtTokenValidator;
import com.example.iam.resourceserver.jwt.RoleValidator;
import com.example.iam.resourceserver.jwt.ScopeValidator;
import java.time.Clock;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

@Configuration
public class IamSecurityConfiguration {

    @Bean
    public JwtTokenValidator jwtTokenValidator(IamProperties properties, IamJwksClient jwksClient) {
        return new JwtTokenValidator(
                jwksClient,
                new IssuerValidator(properties.getIssuer()),
                new AudienceValidator(properties.getResourceServer().getAudience()),
                new ScopeValidator(),
                new RoleValidator(),
                new JtiValidator(false, jti -> false),
                Clock.systemUTC(),
                properties.getToken().getClockSkew());
    }

    @Bean
    public IamJwtAuthenticationFilter iamJwtAuthenticationFilter(
            JwtTokenValidator jwtTokenValidator, IamProperties properties) {
        return new IamJwtAuthenticationFilter(jwtTokenValidator, properties.getResourceServer().getPermitAll());
    }

    @Bean
    public FilterRegistrationBean<IamJwtAuthenticationFilter> iamJwtAuthenticationFilterRegistration(
            IamJwtAuthenticationFilter filter) {
        FilterRegistrationBean<IamJwtAuthenticationFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE + 20);
        registration.addUrlPatterns("/*");
        return registration;
    }

    @Bean
    public RequireScopeAspect requireScopeAspect() {
        return new RequireScopeAspect();
    }

    @Bean
    public RequireRoleAspect requireRoleAspect() {
        return new RequireRoleAspect();
    }
}
