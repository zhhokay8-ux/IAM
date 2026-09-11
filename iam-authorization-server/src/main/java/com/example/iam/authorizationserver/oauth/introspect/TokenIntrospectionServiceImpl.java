package com.example.iam.authorizationserver.oauth.introspect;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.token.entity.IamRefreshTokenEntity;
import com.example.iam.token.oauth.JtiRevocationService;
import com.example.iam.token.oauth.RefreshTokenFamilyService;
import com.example.iam.token.oauth.RefreshTokenServiceImpl;
import com.example.iam.token.signing.JwtSigner;
import com.example.iam.user.service.IamUserService;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class TokenIntrospectionServiceImpl implements TokenIntrospectionService {

    private final JwtSigner jwtSigner;
    private final JtiRevocationService jtiRevocationService;
    private final RefreshTokenFamilyService refreshTokenFamilyService;
    private final IamUserService userService;
    private final Clock clock;

    @Autowired
    public TokenIntrospectionServiceImpl(
            JwtSigner jwtSigner,
            JtiRevocationService jtiRevocationService,
            RefreshTokenFamilyService refreshTokenFamilyService,
            IamUserService userService) {
        this(jwtSigner, jtiRevocationService, refreshTokenFamilyService, userService, Clock.systemUTC());
    }

    TokenIntrospectionServiceImpl(
            JwtSigner jwtSigner,
            JtiRevocationService jtiRevocationService,
            RefreshTokenFamilyService refreshTokenFamilyService,
            Clock clock) {
        this(jwtSigner, jtiRevocationService, refreshTokenFamilyService, null, clock);
    }

    TokenIntrospectionServiceImpl(
            JwtSigner jwtSigner,
            JtiRevocationService jtiRevocationService,
            RefreshTokenFamilyService refreshTokenFamilyService,
            IamUserService userService,
            Clock clock) {
        this.jwtSigner = jwtSigner;
        this.jtiRevocationService = jtiRevocationService;
        this.refreshTokenFamilyService = refreshTokenFamilyService;
        this.userService = userService;
        this.clock = clock;
    }

    @Override
    public TokenIntrospectionResponse introspect(String token) {
        if (token == null || token.isBlank()) {
            return TokenIntrospectionResponse.inactive();
        }
        Optional<TokenIntrospectionResponse> jwt = introspectJwt(token);
        if (jwt.isPresent()) {
            return jwt.get();
        }
        return introspectRefresh(token);
    }

    private Optional<TokenIntrospectionResponse> introspectJwt(String token) {
        SignedJWT jwt;
        try {
            jwt = jwtSigner.verify(token);
        } catch (IamException ex) {
            if (ex.getErrorCode() == IamErrorCode.INTROSPECTION_UNAVAILABLE) {
                throw ex;
            }
            return Optional.empty();
        }
        JWTClaimsSet claims;
        try {
            claims = jwt.getJWTClaimsSet();
        } catch (ParseException ex) {
            return Optional.empty();
        }
        Date exp = claims.getExpirationTime();
        Instant now = clock.instant();
        if (exp == null || !exp.toInstant().isAfter(now)) {
            return Optional.of(TokenIntrospectionResponse.inactive());
        }
        String jti = claims.getJWTID();
        if (jtiRevocationService.isRevoked(jti)) {
            return Optional.of(TokenIntrospectionResponse.inactive());
        }
        if (userService != null && claims.getSubject() != null) {
            try {
                userService.requireActiveForToken(UUID.fromString(claims.getSubject()));
            } catch (IllegalArgumentException ignored) {
                // non-UUID subjects are not IAM users
            } catch (IamException ex) {
                if (ex.getErrorCode() == IamErrorCode.USER_INACTIVE || ex.getErrorCode() == IamErrorCode.USER_NOT_FOUND) {
                    return Optional.of(TokenIntrospectionResponse.inactive());
                }
                throw ex;
            }
        }
        Date iat = claims.getIssueTime();
        return Optional.of(new TokenIntrospectionResponse(
                true,
                claims.getSubject(),
                claims.getAudience() == null ? List.of() : List.copyOf(claims.getAudience()),
                stringClaim(claims, "client_id"),
                stringClaim(claims, "scope"),
                "Bearer",
                exp.getTime() / 1000,
                iat == null ? null : iat.getTime() / 1000,
                jti));
    }

    private TokenIntrospectionResponse introspectRefresh(String token) {
        Optional<IamRefreshTokenEntity> found = refreshTokenFamilyService.findByPresentedToken(token);
        if (found.isEmpty()) {
            return TokenIntrospectionResponse.inactive();
        }
        IamRefreshTokenEntity entity = found.get();
        Instant now = clock.instant();
        if (RefreshTokenServiceImpl.STATUS_REVOKED.equals(entity.getStatus())
                || entity.getExpiresAt() == null
                || !entity.getExpiresAt().isAfter(now)) {
            return TokenIntrospectionResponse.inactive();
        }
        return new TokenIntrospectionResponse(
                true,
                entity.getSubjectId().toString(),
                entity.getAudience() == null ? List.of() : List.of(entity.getAudience().split("\\s+")),
                null,
                entity.getScope(),
                "refresh_token",
                entity.getExpiresAt().getEpochSecond(),
                entity.getIssuedAt() == null ? null : entity.getIssuedAt().getEpochSecond(),
                null);
    }

    private static String stringClaim(JWTClaimsSet claims, String name) {
        Object value = claims.getClaim(name);
        return value == null ? null : value.toString();
    }
}
