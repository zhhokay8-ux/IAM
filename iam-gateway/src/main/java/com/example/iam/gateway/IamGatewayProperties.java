package com.example.iam.gateway;

import java.time.Duration;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "iam.gateway")
public class IamGatewayProperties {

    private String issuer = "https://auth.example.com";
    private Duration clockSkew = Duration.ofSeconds(30);
    private List<String> corsAllowedOrigins = List.of();
    private int rateLimit = 100;
    private Duration rateLimitWindow = Duration.ofMinutes(1);
    private String[] permitAll = new String[] {"/health", "/actuator/health"};

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public Duration getClockSkew() {
        return clockSkew;
    }

    public void setClockSkew(Duration clockSkew) {
        this.clockSkew = clockSkew;
    }

    public List<String> getCorsAllowedOrigins() {
        return corsAllowedOrigins;
    }

    public void setCorsAllowedOrigins(List<String> corsAllowedOrigins) {
        this.corsAllowedOrigins = corsAllowedOrigins == null ? List.of() : corsAllowedOrigins;
    }

    public int getRateLimit() {
        return rateLimit;
    }

    public void setRateLimit(int rateLimit) {
        this.rateLimit = rateLimit;
    }

    public Duration getRateLimitWindow() {
        return rateLimitWindow;
    }

    public void setRateLimitWindow(Duration rateLimitWindow) {
        this.rateLimitWindow = rateLimitWindow;
    }

    public String[] getPermitAll() {
        return permitAll;
    }

    public void setPermitAll(String[] permitAll) {
        this.permitAll = permitAll == null ? new String[0] : permitAll;
    }
}
