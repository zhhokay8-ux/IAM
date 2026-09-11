package com.example.iam.authorizationserver.oidc;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import java.net.URI;
import java.util.List;
import java.util.Locale;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class OidcDiscoveryService {

    static final String GRANT_AUTHORIZATION_CODE = "authorization_code";
    static final String GRANT_REFRESH_TOKEN = "refresh_token";
    static final String GRANT_CLIENT_CREDENTIALS = "client_credentials";
    static final String GRANT_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
    static final String RESPONSE_TYPE_CODE = "code";
    static final String PKCE_S256 = "S256";

    private final String issuer;

    public OidcDiscoveryService(@Value("${iam.issuer}") String issuer) {
        this.issuer = normalizeIssuer(issuer);
    }

    public OidcDiscoveryResponse discovery() {
        return new OidcDiscoveryResponse(
                issuer,
                endpoint("/oauth2/authorize"),
                endpoint("/oauth2/token"),
                endpoint("/.well-known/jwks.json"),
                endpoint("/oidc/userinfo"),
                endpoint("/oauth2/revoke"),
                endpoint("/oauth2/introspect"),
                endpoint("/oidc/logout"),
                endpoint("/oidc/backchannel-logout"),
                List.of(
                        GRANT_AUTHORIZATION_CODE,
                        GRANT_REFRESH_TOKEN,
                        GRANT_CLIENT_CREDENTIALS,
                        GRANT_TOKEN_EXCHANGE),
                List.of(RESPONSE_TYPE_CODE),
                List.of("openid", "profile", "offline_access"),
                List.of("sub", "iss", "aud", "exp", "iat", "nbf", "jti", "client_id", "scope", "roles", "tenant_id", "org_id"),
                List.of(PKCE_S256));
    }

    String issuer() {
        return issuer;
    }

    private String endpoint(String path) {
        return issuer + path;
    }

    static String normalizeIssuer(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "iam.issuer is required");
        }
        String value = raw.trim();
        if (value.endsWith("/")) {
            value = value.substring(0, value.length() - 1);
        }
        URI uri;
        try {
            uri = URI.create(value);
        } catch (IllegalArgumentException ex) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "iam.issuer is not a valid URI");
        }
        if (!uri.isAbsolute() || uri.getScheme() == null || uri.getHost() == null) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "iam.issuer must be an absolute URI");
        }
        String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
        if (!"https".equals(scheme) && !isLocalHttp(scheme, uri.getHost())) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "iam.issuer must use https");
        }
        if (uri.getQuery() != null || uri.getFragment() != null || uri.getRawUserInfo() != null) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "iam.issuer must not contain userinfo, query, or fragment");
        }
        return value;
    }

    private static boolean isLocalHttp(String scheme, String host) {
        if (!"http".equals(scheme) || host == null) {
            return false;
        }
        String normalized = host.toLowerCase(Locale.ROOT);
        return "localhost".equals(normalized) || "127.0.0.1".equals(normalized);
    }
}
