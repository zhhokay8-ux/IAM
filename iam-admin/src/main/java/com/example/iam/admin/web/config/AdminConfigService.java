package com.example.iam.admin.web.config;

import com.example.iam.admin.config.IamAdminProperties;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.common.security.CorsProperties;
import com.example.iam.core.redis.IamRedisProperties;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.springframework.core.env.AbstractEnvironment;
import org.springframework.core.env.EnumerablePropertySource;
import org.springframework.core.env.Environment;
import org.springframework.core.env.PropertySource;
import org.springframework.stereotype.Service;

@Service
public class AdminConfigService {

    private final Environment environment;
    private final IamAdminProperties adminProperties;
    private final IamRedisProperties redisProperties;
    private final CorsProperties corsProperties;

    public AdminConfigService(
            Environment environment,
            IamAdminProperties adminProperties,
            IamRedisProperties redisProperties,
            CorsProperties corsProperties) {
        this.environment = environment;
        this.adminProperties = adminProperties;
        this.redisProperties = redisProperties;
        this.corsProperties = corsProperties;
    }

    public AdminConfigResponse snapshot() {
        Map<String, String> values = new LinkedHashMap<>();
        put(values, "iam.issuer", environment.getProperty("iam.issuer"));
        put(values, "iam.enabled", environment.getProperty("iam.enabled"));
        put(values, "iam.jwt.algorithm", environment.getProperty("iam.jwt.algorithm"));
        put(values, "iam.jwt.rsa-key-size", environment.getProperty("iam.jwt.rsa-key-size"));
        put(values, "iam.jwt.access-token-ttl", environment.getProperty("iam.jwt.access-token-ttl"));
        put(values, "iam.sso.cookie-name", environment.getProperty("iam.sso.cookie-name"));
        put(values, "iam.sso.cookie-secure", environment.getProperty("iam.sso.cookie-secure"));
        put(values, "iam.sso.cookie-same-site", environment.getProperty("iam.sso.cookie-same-site"));
        put(values, "iam.sso.cookie-path", environment.getProperty("iam.sso.cookie-path"));
        put(values, "iam.admin.cookie-name", adminProperties.getCookieName());
        put(values, "iam.admin.legacy-token.enabled", Boolean.toString(adminProperties.getLegacyToken().isEnabled()));
        put(values, "iam.admin.access-token", adminProperties.getAccessToken());
        put(values, "iam.admin.oauth.client-id", adminProperties.getOauth().getClientId());
        put(values, "iam.admin.oauth.client-secret", adminProperties.getOauth().getClientSecret());
        put(values, "iam.admin.oauth.redirect-uri", adminProperties.getOauth().getRedirectUri());
        put(values, "iam.admin.oauth.post-login-uri", adminProperties.getOauth().getPostLoginUri());
        put(values, "iam.admin.oauth.resource-code", adminProperties.getOauth().getResourceCode());
        put(values, "iam.admin.oauth.audience", adminProperties.getOauth().getAudience());
        put(values, "iam.admin.oauth.scope", adminProperties.getOauth().getScope());
        put(values, "iam.redis.authorization-code-ttl", duration(redisProperties.getAuthorizationCodeTtl()));
        put(values, "iam.redis.embed-code-ttl", duration(redisProperties.getEmbedCodeTtl()));
        put(values, "iam.redis.oauth-state-ttl", duration(redisProperties.getOauthStateTtl()));
        put(values, "iam.redis.pkce-state-ttl", duration(redisProperties.getPkceStateTtl()));
        put(values, "iam.redis.nonce-ttl", duration(redisProperties.getNonceTtl()));
        put(values, "iam.redis.session-ttl", duration(redisProperties.getSessionTtl()));
        put(values, "iam.redis.migration-ticket-ttl", duration(redisProperties.getMigrationTicketTtl()));
        put(values, "iam.redis.refresh-token-status-ttl", duration(redisProperties.getRefreshTokenStatusTtl()));
        put(values, "iam.redis.revoked-jti-ttl", duration(redisProperties.getRevokedJtiTtl()));
        put(values, "iam.redis.rate-limit-ttl", duration(redisProperties.getRateLimitTtl()));
        put(values, "iam.cors.allow-credentials", Boolean.toString(corsProperties.isAllowCredentials()));
        put(values, "iam.cors.allowed-origins", String.join(",", corsProperties.getAllowedOrigins()));
        put(values, "iam.cors.embed-parent-origins", String.join(",", corsProperties.getEmbedParentOrigins()));
        collectEnvironment(values);

        Map<String, List<AdminConfigResponse.AdminConfigItem>> grouped = new LinkedHashMap<>();
        grouped.put("issuer", new ArrayList<>());
        grouped.put("jwt", new ArrayList<>());
        grouped.put("cors", new ArrayList<>());
        grouped.put("pkce", new ArrayList<>());
        grouped.put("session", new ArrayList<>());
        grouped.put("redis", new ArrayList<>());
        grouped.put("admin", new ArrayList<>());
        grouped.put("other", new ArrayList<>());
        for (Map.Entry<String, String> entry : values.entrySet()) {
            grouped.get(sectionOf(entry.getKey())).add(item(entry.getKey(), entry.getValue()));
        }
        List<AdminConfigResponse.AdminConfigSection> sections = new ArrayList<>();
        grouped.forEach((name, items) -> {
            if (!items.isEmpty()) {
                sections.add(new AdminConfigResponse.AdminConfigSection(name, dangerousSection(name), List.copyOf(items)));
            }
        });
        return new AdminConfigResponse(true, true, sections);
    }

    public void rejectMutation() {
        throw new IamException(
                IamErrorCode.FORBIDDEN, "IAM configuration is READ_ONLY; changes require restart (RESTART_REQUIRED)");
    }

    private void collectEnvironment(Map<String, String> values) {
        if (!(environment instanceof AbstractEnvironment abstractEnvironment)) {
            return;
        }
        for (PropertySource<?> source : abstractEnvironment.getPropertySources()) {
            if (!(source instanceof EnumerablePropertySource<?> enumerable)) {
                continue;
            }
            for (String name : enumerable.getPropertyNames()) {
                if (name != null && name.startsWith("iam.") && !values.containsKey(name)) {
                    put(values, name, environment.getProperty(name));
                }
            }
        }
    }

    private static void put(Map<String, String> values, String key, String value) {
        if (value != null) {
            values.putIfAbsent(key, value);
        }
    }

    private static String duration(Duration duration) {
        return duration == null ? null : duration.toString();
    }

    static AdminConfigResponse.AdminConfigItem item(String key, String value) {
        boolean redacted = shouldRedact(key);
        boolean dangerous = isDangerous(key);
        return new AdminConfigResponse.AdminConfigItem(
                key, redacted ? "***" : value, redacted, dangerous, true);
    }

    static boolean shouldRedact(String key) {
        String normalized = key.toLowerCase(Locale.ROOT);
        if (normalized.contains("password") || normalized.contains("credential") || normalized.endsWith("secret")) {
            return true;
        }
        return normalized.contains("access-token") && !normalized.contains("ttl");
    }

    static boolean isDangerous(String key) {
        String normalized = key.toLowerCase(Locale.ROOT);
        return normalized.equals("iam.issuer")
                || normalized.startsWith("iam.jwt.algorithm")
                || normalized.startsWith("iam.cors.")
                || normalized.startsWith("iam.admin.");
    }

    static String sectionOf(String key) {
        if (key.equals("iam.issuer") || key.equals("iam.enabled")) {
            return "issuer";
        }
        if (key.startsWith("iam.jwt.")) {
            return "jwt";
        }
        if (key.startsWith("iam.cors.")) {
            return "cors";
        }
        if (key.contains("pkce")) {
            return "pkce";
        }
        if (key.startsWith("iam.sso.") || key.contains("session-ttl")) {
            return "session";
        }
        if (key.startsWith("iam.redis.")) {
            return "redis";
        }
        if (key.startsWith("iam.admin.")) {
            return "admin";
        }
        return "other";
    }

    static boolean dangerousSection(String name) {
        return "issuer".equals(name) || "jwt".equals(name) || "cors".equals(name) || "admin".equals(name);
    }
}
