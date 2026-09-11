package com.example.iam.core.redis;

public final class RedisKeyConstants {

    public static final String AUTHORIZATION_CODE = "auth:code:";
    public static final String EMBED_CODE = "embed:code:";
    public static final String OAUTH_STATE = "oauth:state:";
    public static final String PKCE_STATE = "pkce:state:";
    public static final String NONCE = "oidc:nonce:";
    public static final String SESSION = "session:";
    public static final String SESSION_SUBJECT = "session:subject:";
    public static final String MIGRATION_TICKET = "migration:ticket:";
    public static final String REFRESH_TOKEN_STATUS = "refresh:status:";
    public static final String REVOKED_JTI = "revoked:jti:";
    public static final String RATE_LIMIT = "rate:limit:";
    public static final String ADMIN_OAUTH = "admin:oauth:";
    /** Short-TTL cache of dashboard SCAN; not a second statistics store. */
    public static final String ADMIN_SESSION_COUNT_CACHE = "admin:cache:session-count";

    private RedisKeyConstants() {
    }

    public static String authorizationCode(String code) {
        return AUTHORIZATION_CODE + code;
    }

    public static String embedCode(String code) {
        return EMBED_CODE + code;
    }

    public static String oauthState(String state) {
        return OAUTH_STATE + state;
    }

    public static String pkceState(String state) {
        return PKCE_STATE + state;
    }

    public static String nonce(String nonce) {
        return NONCE + nonce;
    }

    public static String session(String sessionId) {
        return SESSION + sessionId;
    }

    public static String sessionSubject(String subjectId) {
        return SESSION_SUBJECT + subjectId;
    }

    public static String migrationTicket(String ticket) {
        return MIGRATION_TICKET + ticket;
    }

    public static String refreshTokenStatus(String tokenHash) {
        return REFRESH_TOKEN_STATUS + tokenHash;
    }

    public static String revokedJti(String jti) {
        return REVOKED_JTI + jti;
    }

    public static String rateLimit(String key) {
        return RATE_LIMIT + key;
    }

    public static String adminOauth(String state) {
        return ADMIN_OAUTH + state;
    }

    public static boolean isSessionPayloadKey(String redisKey) {
        return redisKey != null
                && redisKey.startsWith(SESSION)
                && !redisKey.startsWith(SESSION_SUBJECT);
    }
}
