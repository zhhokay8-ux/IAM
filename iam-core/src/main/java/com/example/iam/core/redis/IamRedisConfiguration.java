package com.example.iam.core.redis;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(IamRedisProperties.class)
public class IamRedisConfiguration {
}
