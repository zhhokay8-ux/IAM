package com.example.iam.common.security;

/** Factory for page vs embed Content-Security-Policy headers. Does not emit X-Frame-Options ALLOW-FROM. */
public final class SecurityHeadersConfig {

    private SecurityHeadersConfig() {
    }

    public static SecurityHeadersFilter forPages() {
        return new SecurityHeadersFilter(java.util.List.of());
    }

    public static SecurityHeadersFilter forEmbed(java.util.List<String> parentOrigins) {
        return new SecurityHeadersFilter(parentOrigins);
    }
}
