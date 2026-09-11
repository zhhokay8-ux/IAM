package com.example.iam.authorizationserver.security;

import com.example.iam.authorizationserver.sso.IamSsoProperties;
import com.example.iam.authorizationserver.sso.SsoCookieService;
import com.example.iam.common.security.CorsOriginValidator;
import com.example.iam.common.security.CorsProperties;
import com.example.iam.common.security.CsrfTokenService;
import com.example.iam.common.security.CsrfValidationFilter;
import com.example.iam.common.security.IamCorsFilter;
import com.example.iam.common.security.SecurityHeadersFilter;
import com.example.iam.common.security.TokenLoggingFilter;
import com.example.iam.common.security.TraceIdFilter;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(CorsProperties.class)
public class IamWebSecurityConfiguration {

    @Bean
    CorsOriginValidator corsOriginValidator() {
        return new CorsOriginValidator();
    }

    @Bean
    FilterRegistrationBean<TraceIdFilter> traceIdFilter() {
        return register(new TraceIdFilter(), new TraceIdFilter().getOrder());
    }

    @Bean
    FilterRegistrationBean<SecurityHeadersFilter> securityHeadersFilter(CorsProperties corsProperties) {
        SecurityHeadersFilter filter = new SecurityHeadersFilter(corsProperties.getEmbedParentOrigins());
        return register(filter, filter.getOrder());
    }

    @Bean
    FilterRegistrationBean<IamCorsFilter> iamCorsFilter(CorsProperties corsProperties, CorsOriginValidator validator) {
        IamCorsFilter filter = new IamCorsFilter(corsProperties, validator);
        return register(filter, filter.getOrder());
    }

    @Bean
    FilterRegistrationBean<CsrfValidationFilter> csrfValidationFilter(
            CsrfTokenService csrfTokenService,
            CorsOriginValidator originValidator,
            CorsProperties corsProperties,
            IamSsoProperties ssoProperties) {
        String cookieName = ssoProperties.getCookieName() == null || ssoProperties.getCookieName().isBlank()
                ? SsoCookieService.COOKIE_NAME
                : ssoProperties.getCookieName();
        CsrfValidationFilter filter =
                new CsrfValidationFilter(csrfTokenService, originValidator, corsProperties, cookieName);
        return register(filter, filter.getOrder());
    }

    @Bean
    FilterRegistrationBean<TokenLoggingFilter> tokenLoggingFilter() {
        TokenLoggingFilter filter = new TokenLoggingFilter();
        return register(filter, filter.getOrder());
    }

    private static <T extends jakarta.servlet.Filter> FilterRegistrationBean<T> register(T filter, int order) {
        FilterRegistrationBean<T> registration = new FilterRegistrationBean<>(filter);
        registration.setOrder(order);
        registration.addUrlPatterns("/*");
        return registration;
    }
}
