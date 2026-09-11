package com.example.iam.authorizationserver.sso;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "iam.sso")
public class IamSsoProperties {

    /**
     * HttpOnly SSO session cookie name. Access tokens must never be stored here.
     */
    private String cookieName = "IAM_SSO_SESSION";

    /**
     * Secure flag. Production HTTPS should keep this true; local HTTP tests may disable it.
     */
    private boolean cookieSecure = true;

    private String cookieSameSite = "Lax";

    private String cookiePath = "/";

    public String getCookieName() {
        return cookieName;
    }

    public void setCookieName(String cookieName) {
        this.cookieName = cookieName;
    }

    public boolean isCookieSecure() {
        return cookieSecure;
    }

    public void setCookieSecure(boolean cookieSecure) {
        this.cookieSecure = cookieSecure;
    }

    public String getCookieSameSite() {
        return cookieSameSite;
    }

    public void setCookieSameSite(String cookieSameSite) {
        this.cookieSameSite = cookieSameSite;
    }

    public String getCookiePath() {
        return cookiePath;
    }

    public void setCookiePath(String cookiePath) {
        this.cookiePath = cookiePath;
    }
}
