package com.example.iam.migration;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(MigrationProperties.class)
public class MigrationConfiguration {
}
