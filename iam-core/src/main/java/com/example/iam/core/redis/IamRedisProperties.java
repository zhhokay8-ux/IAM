package com.example.iam.core.redis;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "iam.redis")
public class IamRedisProperties {

    private Duration authorizationCodeTtl = Duration.ofSeconds(60);
    private Duration embedCodeTtl = Duration.ofSeconds(30);
    private Duration oauthStateTtl = Duration.ofMinutes(5);
    private Duration pkceStateTtl = Duration.ofMinutes(5);
    private Duration nonceTtl = Duration.ofMinutes(5);
    private Duration sessionTtl = Duration.ofHours(8);
    private Duration migrationTicketTtl = Duration.ofSeconds(45);
    private Duration refreshTokenStatusTtl = Duration.ofDays(30);
    private Duration revokedJtiTtl = Duration.ofMinutes(15);
    private Duration rateLimitTtl = Duration.ofMinutes(1);

    public Duration getAuthorizationCodeTtl() {
        return authorizationCodeTtl;
    }

    public void setAuthorizationCodeTtl(Duration authorizationCodeTtl) {
        this.authorizationCodeTtl = authorizationCodeTtl;
    }

    public Duration getEmbedCodeTtl() {
        return embedCodeTtl;
    }

    public void setEmbedCodeTtl(Duration embedCodeTtl) {
        this.embedCodeTtl = embedCodeTtl;
    }

    public Duration getOauthStateTtl() {
        return oauthStateTtl;
    }

    public void setOauthStateTtl(Duration oauthStateTtl) {
        this.oauthStateTtl = oauthStateTtl;
    }

    public Duration getPkceStateTtl() {
        return pkceStateTtl;
    }

    public void setPkceStateTtl(Duration pkceStateTtl) {
        this.pkceStateTtl = pkceStateTtl;
    }

    public Duration getNonceTtl() {
        return nonceTtl;
    }

    public void setNonceTtl(Duration nonceTtl) {
        this.nonceTtl = nonceTtl;
    }

    public Duration getSessionTtl() {
        return sessionTtl;
    }

    public void setSessionTtl(Duration sessionTtl) {
        this.sessionTtl = sessionTtl;
    }

    public Duration getMigrationTicketTtl() {
        return migrationTicketTtl;
    }

    public void setMigrationTicketTtl(Duration migrationTicketTtl) {
        this.migrationTicketTtl = migrationTicketTtl;
    }

    public Duration getRefreshTokenStatusTtl() {
        return refreshTokenStatusTtl;
    }

    public void setRefreshTokenStatusTtl(Duration refreshTokenStatusTtl) {
        this.refreshTokenStatusTtl = refreshTokenStatusTtl;
    }

    public Duration getRevokedJtiTtl() {
        return revokedJtiTtl;
    }

    public void setRevokedJtiTtl(Duration revokedJtiTtl) {
        this.revokedJtiTtl = revokedJtiTtl;
    }

    public Duration getRateLimitTtl() {
        return rateLimitTtl;
    }

    public void setRateLimitTtl(Duration rateLimitTtl) {
        this.rateLimitTtl = rateLimitTtl;
    }
}
