package com.example.iam.authorizationserver.oauth.revoke;

import com.example.iam.audit.AuditEvent;
import com.example.iam.audit.IamAuditService;
import com.example.iam.token.oauth.JtiRevocationService;
import com.example.iam.token.oauth.RefreshTokenFamilyService;
import com.example.iam.token.signing.JwtSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class TokenRevocationServiceImpl implements TokenRevocationService {

    private final JwtSigner jwtSigner;
    private final JtiRevocationService jtiRevocationService;
    private final RefreshTokenFamilyService refreshTokenFamilyService;
    private final IamAuditService auditService;
    private final Clock clock;

    @Autowired
    public TokenRevocationServiceImpl(
            JwtSigner jwtSigner,
            JtiRevocationService jtiRevocationService,
            RefreshTokenFamilyService refreshTokenFamilyService,
            IamAuditService auditService) {
        this(jwtSigner, jtiRevocationService, refreshTokenFamilyService, auditService, Clock.systemUTC());
    }

    TokenRevocationServiceImpl(
            JwtSigner jwtSigner,
            JtiRevocationService jtiRevocationService,
            RefreshTokenFamilyService refreshTokenFamilyService,
            IamAuditService auditService,
            Clock clock) {
        this.jwtSigner = jwtSigner;
        this.jtiRevocationService = jtiRevocationService;
        this.refreshTokenFamilyService = refreshTokenFamilyService;
        this.auditService = auditService;
        this.clock = clock;
    }

    @Override
    public boolean revoke(String token, String tokenTypeHint) {
        if (token == null || token.isBlank()) {
            return false;
        }
        String hint = tokenTypeHint == null ? "" : tokenTypeHint.trim().toLowerCase();
        boolean revoked;
        if ("refresh_token".equals(hint)) {
            revoked = refreshTokenFamilyService.revokePresentedToken(token);
            if (!revoked) {
                revoked = revokeAccessTokenQuietly(token);
            }
        } else if ("access_token".equals(hint)) {
            revoked = revokeAccessTokenQuietly(token);
            if (!revoked) {
                revoked = refreshTokenFamilyService.revokePresentedToken(token);
            }
        } else {
            revoked = revokeAccessTokenQuietly(token);
            if (!revoked) {
                revoked = refreshTokenFamilyService.revokePresentedToken(token);
            }
        }
        if (revoked) {
            auditService.success(AuditEvent.TOKEN_REVOKED, null, null, "token_type_hint=" + hint);
        }
        return revoked;
    }

    private boolean revokeAccessTokenQuietly(String token) {
        try {
            SignedJWT jwt = jwtSigner.verify(token);
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            String jti = claims.getJWTID();
            if (jti == null || jti.isBlank()) {
                return false;
            }
            Duration ttl = remainingTtl(claims.getExpirationTime());
            jtiRevocationService.revoke(jti, ttl);
            return true;
        } catch (RuntimeException | ParseException ex) {
            return false;
        }
    }

    private Duration remainingTtl(Date exp) {
        if (exp == null) {
            return Duration.ofMinutes(15);
        }
        Duration remaining = Duration.between(clock.instant(), exp.toInstant());
        if (remaining.isZero() || remaining.isNegative()) {
            return Duration.ofSeconds(1);
        }
        return remaining;
    }
}
