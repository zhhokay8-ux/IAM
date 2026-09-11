package com.example.iam.sdk;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.token.signing.JwtKeyResolver;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.client.RestClient;

public class IamJwksClient implements JwtKeyResolver {

    private static final Logger log = LoggerFactory.getLogger(IamJwksClient.class);

    private final String jwksUri;
    private final Duration cacheTtl;
    private final RestClient restClient;
    private final Clock clock;
    private final JwksCache cache;

    public IamJwksClient(String issuer, Duration cacheTtl) {
        this(issuer, cacheTtl, RestClient.create(), Clock.systemUTC(), new JwksCache());
    }

    IamJwksClient(String issuer, Duration cacheTtl, RestClient restClient, Clock clock, JwksCache cache) {
        if (issuer == null || issuer.isBlank()) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "issuer is required");
        }
        this.jwksUri = trimSlash(issuer) + "/.well-known/jwks.json";
        this.cacheTtl = cacheTtl == null ? Duration.ofHours(1) : cacheTtl;
        this.restClient = Objects.requireNonNull(restClient);
        this.clock = clock == null ? Clock.systemUTC() : clock;
        this.cache = cache == null ? new JwksCache() : cache;
    }

    static IamJwksClient staticSet(JWKSet jwkSet) {
        JwksCache cache = new JwksCache();
        cache.put(jwkSet, Instant.MAX);
        return new IamJwksClient("https://auth.example.com", Duration.ofHours(1), RestClient.create(), Clock.systemUTC(), cache);
    }

    public String jwksUri() {
        return jwksUri;
    }

    JwksCache cache() {
        return cache;
    }

    @Override
    public RSAPublicKey resolvePublicKey(String kid) {
        if (kid == null || kid.isBlank()) {
            throw new IamException(IamErrorCode.SIGNING_KEY_NOT_FOUND, "kid is required");
        }
        JWKSet set = current();
        JWK jwk = set.getKeyByKeyId(kid);
        if (jwk == null) {
            set = fetch(false);
            jwk = set.getKeyByKeyId(kid);
        }
        if (!(jwk instanceof RSAKey rsa)) {
            throw new IamException(IamErrorCode.SIGNING_KEY_NOT_FOUND, "unknown kid: " + kid);
        }
        try {
            return rsa.toRSAPublicKey();
        } catch (Exception ex) {
            throw new IamException(IamErrorCode.SIGNING_KEY_NOT_FOUND, "failed to load JWKS key", ex);
        }
    }

    JWKSet current() {
        return cache.getIfFresh(clock.instant()).orElseGet(() -> fetch(true));
    }

    void refreshQuietly() {
        try {
            fetch(true);
        } catch (RuntimeException ex) {
            log.warn("JWKS refresh failed; continuing with cached keys uri={}", jwksUri);
        }
    }

    JWKSet fetch(boolean allowStale) {
        try {
            String body = restClient.get().uri(jwksUri).retrieve().body(String.class);
            JWKSet set = JWKSet.parse(body);
            cache.put(set, clock.instant().plus(cacheTtl));
            return set;
        } catch (IamException ex) {
            throw ex;
        } catch (Exception ex) {
            if (allowStale) {
                return cache.getStale()
                        .orElseThrow(() -> new IamException(IamErrorCode.SIGNING_KEY_NOT_FOUND, "failed to fetch JWKS", ex));
            }
            throw new IamException(IamErrorCode.SIGNING_KEY_NOT_FOUND, "failed to fetch JWKS", ex);
        }
    }

    private static String trimSlash(String issuer) {
        if (issuer.endsWith("/")) {
            return issuer.substring(0, issuer.length() - 1);
        }
        return issuer;
    }
}
