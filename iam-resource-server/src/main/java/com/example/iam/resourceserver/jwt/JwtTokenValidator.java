package com.example.iam.resourceserver.jwt;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.token.signing.JwtKeyResolver;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class JwtTokenValidator {

    private final JwtKeyResolver keyResolver;
    private final IssuerValidator issuerValidator;
    private final AudienceValidator audienceValidator;
    private final ScopeValidator scopeValidator;
    private final RoleValidator roleValidator;
    private final JtiValidator jtiValidator;
    private final Clock clock;
    private final Duration clockSkew;

    public JwtTokenValidator(
            JwtKeyResolver keyResolver,
            IssuerValidator issuerValidator,
            AudienceValidator audienceValidator,
            ScopeValidator scopeValidator,
            RoleValidator roleValidator,
            JtiValidator jtiValidator,
            Clock clock,
            Duration clockSkew) {
        this.keyResolver = keyResolver;
        this.issuerValidator = issuerValidator;
        this.audienceValidator = audienceValidator;
        this.scopeValidator = scopeValidator;
        this.roleValidator = roleValidator;
        this.jtiValidator = jtiValidator;
        this.clock = clock == null ? Clock.systemUTC() : clock;
        this.clockSkew = clockSkew == null ? Duration.ofSeconds(30) : clockSkew;
    }

    public ValidatedAccessToken validate(String token) {
        SignedJWT jwt = parse(token);
        assertRs256(jwt);
        String kid = jwt.getHeader().getKeyID();
        if (kid == null || kid.isBlank()) {
            throw new IamException(IamErrorCode.SIGNING_KEY_NOT_FOUND, "kid is required");
        }
        RSAPublicKey publicKey = keyResolver.resolvePublicKey(kid);
        verifySignature(jwt, publicKey);
        JWTClaimsSet claims = claims(jwt);
        issuerValidator.validate(claims.getIssuer());
        audienceValidator.validate(claims.getAudience());
        assertTimeWindow(claims);
        jtiValidator.validate(claims.getJWTID());
        return toValidated(claims);
    }

    public ValidatedAccessToken requireScope(String token, String scope) {
        ValidatedAccessToken validated = validate(token);
        scopeValidator.validate(validated.scopes(), scope);
        return validated;
    }

    public ValidatedAccessToken requireRole(String token, String role) {
        ValidatedAccessToken validated = validate(token);
        roleValidator.validate(validated.roles(), role);
        return validated;
    }

    private static SignedJWT parse(String token) {
        if (token == null || token.isBlank()) {
            throw new IamException(IamErrorCode.UNAUTHORIZED, "access token is required");
        }
        try {
            return SignedJWT.parse(token);
        } catch (ParseException ex) {
            throw new IamException(IamErrorCode.INVALID_JWT, "JWT is malformed", ex);
        }
    }

    private static void assertRs256(SignedJWT jwt) {
        if (!JWSAlgorithm.RS256.equals(jwt.getHeader().getAlgorithm())) {
            throw new IamException(IamErrorCode.INVALID_JWT, "JWT alg must be RS256");
        }
    }

    private static void verifySignature(SignedJWT jwt, RSAPublicKey publicKey) {
        try {
            if (!jwt.verify(new RSASSAVerifier(publicKey))) {
                throw new IamException(IamErrorCode.INVALID_JWT_SIGNATURE, "JWT signature is invalid");
            }
        } catch (JOSEException ex) {
            throw new IamException(IamErrorCode.INVALID_JWT_SIGNATURE, "JWT signature is invalid", ex);
        }
    }

    private static JWTClaimsSet claims(SignedJWT jwt) {
        try {
            return jwt.getJWTClaimsSet();
        } catch (ParseException ex) {
            throw new IamException(IamErrorCode.INVALID_JWT, "JWT claims are malformed", ex);
        }
    }

    private void assertTimeWindow(JWTClaimsSet claims) {
        Instant now = clock.instant();
        Date exp = claims.getExpirationTime();
        if (exp == null) {
            throw new IamException(IamErrorCode.JWT_EXPIRED, "exp is required");
        }
        if (now.minus(clockSkew).isAfter(exp.toInstant())) {
            throw new IamException(IamErrorCode.JWT_EXPIRED, "JWT expired");
        }
        Date nbf = claims.getNotBeforeTime();
        if (nbf != null && now.plus(clockSkew).isBefore(nbf.toInstant())) {
            throw new IamException(IamErrorCode.JWT_NOT_BEFORE, "JWT is not yet valid");
        }
    }

    @SuppressWarnings("unchecked")
    private static ValidatedAccessToken toValidated(JWTClaimsSet claims) {
        List<String> scopes = split(claims.getClaim("scope"));
        List<String> roles = new ArrayList<>();
        Object rolesClaim = claims.getClaim("roles");
        if (rolesClaim instanceof List<?> list) {
            for (Object item : list) {
                if (item != null) {
                    roles.add(item.toString());
                }
            }
        } else if (rolesClaim instanceof String value) {
            roles.addAll(split(value));
        }
        String clientId = stringClaim(claims, "client_id");
        return new ValidatedAccessToken(
                claims.getSubject(),
                claims.getIssuer(),
                claims.getAudience() == null ? List.of() : List.copyOf(claims.getAudience()),
                clientId,
                List.copyOf(scopes),
                List.copyOf(roles),
                stringClaim(claims, "tenant_id"),
                stringClaim(claims, "org_id"),
                claims.getJWTID());
    }

    private static String stringClaim(JWTClaimsSet claims, String name) {
        Object value = claims.getClaim(name);
        return value == null ? null : value.toString();
    }

    private static List<String> split(Object scope) {
        if (scope == null) {
            return List.of();
        }
        String value = scope.toString().trim();
        if (value.isEmpty()) {
            return List.of();
        }
        return List.of(value.split("\\s+"));
    }
}
