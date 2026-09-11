package com.example.iam.sdk;

import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

/**
 * Resource-server authentication is owned by {@link IamJwtAuthenticationFilter}. Spring Security
 * servlet / OAuth2 resource-server auto-configuration would otherwise return 401 before the starter
 * filter runs.
 */
public class IamSecurityAutoConfigurationExcluder implements EnvironmentPostProcessor {

    static final String PROPERTY = "spring.autoconfigure.exclude";

    private static final String[] EXCLUDES = {
        "org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration",
        "org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration",
        "org.springframework.boot.autoconfigure.security.oauth2.resource.servlet.OAuth2ResourceServerAutoConfiguration"
    };

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        Set<String> merged = new LinkedHashSet<>();
        String existing = environment.getProperty(PROPERTY);
        if (existing != null && !existing.isBlank()) {
            for (String item : existing.split(",")) {
                String trimmed = item.trim();
                if (!trimmed.isEmpty()) {
                    merged.add(trimmed);
                }
            }
        }
        for (String exclude : EXCLUDES) {
            merged.add(exclude);
        }
        environment
                .getPropertySources()
                .addFirst(new MapPropertySource("iamSdkSecurityAutoConfigExclude", Map.of(PROPERTY, String.join(",", merged))));
    }
}
