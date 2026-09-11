package com.example.iam.authorizationserver.oauth.token.exchange;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.policy.IamPolicyEvaluator;
import com.example.iam.token.signing.JwtSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class SubjectTokenValidator {

    static final String ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

    private final JwtSigner jwtSigner;
    private final IamPolicyEvaluator policyEvaluator;
    private final String issuer;
    private final Clock clock;
    private final Duration clockSkew;

    @Autowired
    public SubjectTokenValidator(
            JwtSigner jwtSigner,
            IamPolicyEvaluator policyEvaluator,
            @Value("${iam.issuer}") String issuer) {
        this(jwtSigner, policyEvaluator, issuer, Clock.systemUTC(), Duration.ofSeconds(30));
    }

    SubjectTokenValidator(
            JwtSigner jwtSigner,
            IamPolicyEvaluator policyEvaluator,
            String issuer,
            Clock clock,
            Duration clockSkew) {
        this.jwtSigner = jwtSigner;
        this.policyEvaluator = policyEvaluator;
        this.issuer = issuer;
        this.clock = clock;
        this.clockSkew = clockSkew;
    }

    public DelegationContext validate(String token, String tokenType) {
        assertAccessTokenType(tokenType);
        if (token == null || token.isBlank()) {
            throw new IamException(IamErrorCode.INVALID_GRANT, "subject_token is required");
        }
        JWTClaimsSet claims = verifiedClaims(token);
        requireIssuer(claims);
        requireTimeWindow(claims);
        List<String> audiences = claims.getAudience() == null ? List.of() : List.copyOf(claims.getAudience());
        if (audiences.isEmpty()) {
            throw new IamException(IamErrorCode.INVALID_JWT_AUDIENCE, "subject token audience is required");
        }
        for (String audience : audiences) {
            policyEvaluator.validateAudience(audience);
        }
        if (claims.getSubject() == null || claims.getSubject().isBlank()) {
            throw new IamException(IamErrorCode.INVALID_JWT, "subject token sub is required");
        }
        return new DelegationContext(
                claims.getSubject(),
                audiences,
                scopes(claims),
                stringClaim(claims, "client_id"),
                stringClaim(claims, "tenant_id"),
                stringClaim(claims, "org_id"),
                roles(claims),
                claims.getJWTID());
    }

    JWTClaimsSet verifiedClaims(String token) {
        SignedJWT jwt = jwtSigner.verify(token);
        try {
            return jwt.getJWTClaimsSet();
        } catch (ParseException ex) {
            throw new IamException(IamErrorCode.INVALID_JWT, "JWT claims are malformed", ex);
        }
    }

    void requireIssuer(JWTClaimsSet claims) {
        if (issuer == null || !issuer.equals(claims.getIssuer())) {
            throw new IamException(IamErrorCode.INVALID_JWT_ISSUER, "invalid JWT issuer");
        }
    }

    void requireTimeWindow(JWTClaimsSet claims) {
        Instant now = clock.instant();
        Date exp = claims.getExpirationTime();
        if (exp == null || now.minus(clockSkew).isAfter(exp.toInstant())) {
            throw new IamException(IamErrorCode.JWT_EXPIRED, "JWT expired");
        }
        Date nbf = claims.getNotBeforeTime();
        if (nbf != null && now.plus(clockSkew).isBefore(nbf.toInstant())) {
            throw new IamException(IamErrorCode.JWT_NOT_BEFORE, "JWT is not yet valid");
        }
    }

    static void assertAccessTokenType(String tokenType) {
        if (tokenType == null || tokenType.isBlank()) {
            throw new IamException(IamErrorCode.INVALID_ARGUMENT, "token type is required");
        }
        String normalized = tokenType.trim();
        if (!ACCESS_TOKEN_TYPE.equals(normalized) && !"urn:ietf:params:oauth:token-type:jwt".equals(normalized)) {
            throw new IamException(IamErrorCode.INVALID_GRANT, "unsupported token type: " + tokenType);
        }
    }

    static List<String> scopes(JWTClaimsSet claims) {
        Object scope = claims.getClaim("scope");
        if (scope == null) {
            return List.of();
        }
        String value = scope.toString().trim();
        if (value.isEmpty()) {
            return List.of();
        }
        return List.of(value.split("\\s+"));
    }

    @SuppressWarnings("unchecked")
    static List<String> roles(JWTClaimsSet claims) {
        List<String> roles = new ArrayList<>();
        Object rolesClaim = claims.getClaim("roles");
        if (rolesClaim instanceof List<?> list) {
            for (Object item : list) {
                if (item != null) {
                    roles.add(item.toString());
                }
            }
        }
        return List.copyOf(roles);
    }

    static String stringClaim(JWTClaimsSet claims, String name) {
        Object value = claims.getClaim(name);
        return value == null ? null : value.toString();
    }
}
