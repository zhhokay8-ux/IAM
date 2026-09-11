package com.example.iam.admin.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "iam.admin")
public class IamAdminProperties {

    /**
     * Shared secret for legacy {@code X-IAM-Admin-Token}. Empty disables the header even when
     * {@link LegacyToken#enabled} is true.
     */
    private String accessToken = "";

    /**
     * SSO session cookie used for cookie-based admin authentication. Defaults to IAM_SSO_SESSION.
     */
    private String cookieName = "IAM_SSO_SESSION";

    private LegacyToken legacyToken = new LegacyToken();

    private OAuth oauth = new OAuth();

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken == null ? "" : accessToken;
    }

    public String getCookieName() {
        return cookieName;
    }

    public void setCookieName(String cookieName) {
        this.cookieName = cookieName;
    }

    public LegacyToken getLegacyToken() {
        return legacyToken;
    }

    public void setLegacyToken(LegacyToken legacyToken) {
        this.legacyToken = legacyToken == null ? new LegacyToken() : legacyToken;
    }

    public OAuth getOauth() {
        return oauth;
    }

    public void setOauth(OAuth oauth) {
        this.oauth = oauth == null ? new OAuth() : oauth;
    }

    public static class LegacyToken {
        private boolean enabled = false;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }
    }

    public static class OAuth {
        private String clientId = "iam-admin";
        private String clientSecret = "";
        private String redirectUri = "http://localhost:5173/admin/callback";
        private String postLoginUri = "http://localhost:5173/admin/";
        private String resourceCode = "IAM-ADMIN";
        private String audience = "iam-admin";
        private String scope = "openid";

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getClientSecret() {
            return clientSecret;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret == null ? "" : clientSecret;
        }

        public String getRedirectUri() {
            return redirectUri;
        }

        public void setRedirectUri(String redirectUri) {
            this.redirectUri = redirectUri;
        }

        public String getPostLoginUri() {
            return postLoginUri;
        }

        public void setPostLoginUri(String postLoginUri) {
            this.postLoginUri = postLoginUri;
        }

        public String getResourceCode() {
            return resourceCode;
        }

        public void setResourceCode(String resourceCode) {
            this.resourceCode = resourceCode;
        }

        public String getAudience() {
            return audience;
        }

        public void setAudience(String audience) {
            this.audience = audience;
        }

        public String getScope() {
            return scope;
        }

        public void setScope(String scope) {
            this.scope = scope;
        }
    }
}
