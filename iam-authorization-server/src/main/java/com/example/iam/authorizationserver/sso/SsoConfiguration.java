package com.example.iam.authorizationserver.sso;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(IamSsoProperties.class)
public class SsoConfiguration {
}
