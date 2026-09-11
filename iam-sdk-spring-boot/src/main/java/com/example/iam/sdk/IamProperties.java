package com.example.iam.sdk;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "iam")
public class IamProperties {

    private String issuer;
    private final ResourceServer resourceServer = new ResourceServer();
    private final Jwks jwks = new Jwks();
    private final Token token = new Token();

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public ResourceServer getResourceServer() {
        return resourceServer;
    }

    public Jwks getJwks() {
        return jwks;
    }

    public Token getToken() {
        return token;
    }

    public static class ResourceServer {
        private String audience;
        private boolean enabled = true;
        private String[] permitAll = new String[0];

        public String getAudience() {
            return audience;
        }

        public void setAudience(String audience) {
            this.audience = audience;
        }

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String[] getPermitAll() {
            return permitAll;
        }

        public void setPermitAll(String[] permitAll) {
            this.permitAll = permitAll == null ? new String[0] : permitAll;
        }
    }

    public static class Jwks {
        private Duration cacheTtl = Duration.ofHours(1);
        private Duration refresh = Duration.ofMinutes(10);

        public Duration getCacheTtl() {
            return cacheTtl;
        }

        public void setCacheTtl(Duration cacheTtl) {
            this.cacheTtl = cacheTtl;
        }

        public Duration getRefresh() {
            return refresh;
        }

        public void setRefresh(Duration refresh) {
            this.refresh = refresh;
        }
    }

    public static class Token {
        private Duration clockSkew = Duration.ofSeconds(30);

        public Duration getClockSkew() {
            return clockSkew;
        }

        public void setClockSkew(Duration clockSkew) {
            this.clockSkew = clockSkew;
        }
    }
}
