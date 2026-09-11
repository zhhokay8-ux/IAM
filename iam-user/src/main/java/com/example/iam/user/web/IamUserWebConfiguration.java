package com.example.iam.user.web;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class IamUserWebConfiguration implements WebMvcConfigurer {

    private final String adminAccessToken;

    public IamUserWebConfiguration(@Value("${iam.admin.access-token:}") String adminAccessToken) {
        this.adminAccessToken = adminAccessToken;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new IamAdminAccessInterceptor(adminAccessToken))
                .addPathPatterns("/api/users", "/api/users/**");
    }
}
