package com.example.iam.admin.config;

import com.example.iam.admin.security.AdminAuthenticationFilter;
import com.example.iam.admin.security.AdminAuthenticationService;
import com.example.iam.admin.security.AdminAuthorizationInterceptor;
import com.example.iam.audit.IamAuditService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@EnableConfigurationProperties(IamAdminProperties.class)
public class AdminWebConfiguration implements WebMvcConfigurer {

    private static final Logger log = LoggerFactory.getLogger(AdminWebConfiguration.class);

    private final IamAdminProperties properties;
    private final AdminAuthorizationInterceptor authorizationInterceptor;

    public AdminWebConfiguration(IamAdminProperties properties, IamAuditService auditService) {
        this.properties = properties;
        this.authorizationInterceptor = new AdminAuthorizationInterceptor(auditService);
    }

    @PostConstruct
    void warnLegacy() {
        if (properties.getLegacyToken() != null && properties.getLegacyToken().isEnabled()) {
            if (!StringUtils.hasText(properties.getAccessToken())) {
                log.warn("iam.admin.legacy-token.enabled=true but iam.admin.access-token is empty; header auth stays denied");
            } else {
                log.warn(
                        "Legacy admin token is ENABLED. Restrict to break-glass use, rotate the secret, and migrate /api/admin clients to SSO cookie or Bearer JWT. The token value is never logged.");
            }
        }
    }

    @Bean
    FilterRegistrationBean<AdminAuthenticationFilter> adminAuthenticationFilter(
            AdminAuthenticationService authenticationService, ObjectMapper objectMapper) {
        AdminAuthenticationFilter filter = new AdminAuthenticationFilter(authenticationService, objectMapper);
        FilterRegistrationBean<AdminAuthenticationFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setOrder(filter.getOrder());
        registration.addUrlPatterns("/api/admin/*");
        return registration;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(authorizationInterceptor).addPathPatterns("/api/admin", "/api/admin/**");
    }
}
