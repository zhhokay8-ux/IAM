package com.example.iam.resourceserver.jwt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.nimbusds.jwt.JWTClaimsSet;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class JwtTokenValidatorTest {

    private TestJwtSupport jwtSupport;
    private Set<String> revoked;
    private JwtTokenValidator validator;

    @BeforeEach
    void setUp() {
        jwtSupport = new TestJwtSupport();
        revoked = ConcurrentHashMap.newKeySet();
        validator = new JwtTokenValidator(
                jwtSupport.resolver(),
                new IssuerValidator(TestJwtSupport.ISSUER),
                new AudienceValidator(TestJwtSupport.AUDIENCE),
                new ScopeValidator(),
                new RoleValidator(),
                new JtiValidator(true, revoked::contains),
                Clock.systemUTC(),
                Duration.ofSeconds(30));
    }

    @Test
    void validToken() {
        ValidatedAccessToken token = validator.validate(jwtSupport.token(jwtSupport.validClaims().build()));
        assertEquals("u-100086", token.subject());
        assertTrue(token.audiences().contains(TestJwtSupport.AUDIENCE));
        assertTrue(token.scopes().contains("order.read"));
        assertTrue(token.roles().contains("order_viewer"));
    }

    @Test
    void invalidSignature() {
        String jwt = jwtSupport.token(jwtSupport.validClaims().build());
        String[] parts = jwt.split("\\.");
        String tampered = parts[0] + "." + parts[1] + "." + (parts[2].charAt(0) == 'A' ? "B" : "A") + parts[2].substring(1);
        IamException ex = assertThrows(IamException.class, () -> validator.validate(tampered));
        assertEquals(IamErrorCode.INVALID_JWT_SIGNATURE, ex.getErrorCode());
    }

    @Test
    void unknownKid() {
        String jwt = jwtSupport.token(jwtSupport.validClaims().build(), "unknown-kid");
        IamException ex = assertThrows(IamException.class, () -> validator.validate(jwt));
        assertEquals(IamErrorCode.SIGNING_KEY_NOT_FOUND, ex.getErrorCode());
    }

    @Test
    void wrongIssuer() {
        JWTClaimsSet claims = jwtSupport.validClaims().issuer("https://evil.example.com").build();
        IamException ex = assertThrows(IamException.class, () -> validator.validate(jwtSupport.token(claims)));
        assertEquals(IamErrorCode.INVALID_JWT_ISSUER, ex.getErrorCode());
    }

    @Test
    void wrongAudience() {
        JWTClaimsSet claims = jwtSupport.validClaims().audience("system-1-api").build();
        IamException ex = assertThrows(IamException.class, () -> validator.validate(jwtSupport.token(claims)));
        assertEquals(IamErrorCode.INVALID_JWT_AUDIENCE, ex.getErrorCode());
    }

    @Test
    void expiredToken() {
        Instant now = Instant.now();
        JWTClaimsSet claims = jwtSupport.validClaims()
                .expirationTime(Date.from(now.minusSeconds(120)))
                .notBeforeTime(Date.from(now.minusSeconds(180)))
                .issueTime(Date.from(now.minusSeconds(180)))
                .build();
        IamException ex = assertThrows(IamException.class, () -> validator.validate(jwtSupport.token(claims)));
        assertEquals(IamErrorCode.JWT_EXPIRED, ex.getErrorCode());
    }

    @Test
    void notBeforeFailure() {
        Instant now = Instant.now();
        JWTClaimsSet claims = jwtSupport.validClaims()
                .notBeforeTime(Date.from(now.plusSeconds(120)))
                .expirationTime(Date.from(now.plusSeconds(600)))
                .build();
        IamException ex = assertThrows(IamException.class, () -> validator.validate(jwtSupport.token(claims)));
        assertEquals(IamErrorCode.JWT_NOT_BEFORE, ex.getErrorCode());
    }

    @Test
    void missingScope() {
        IamException ex = assertThrows(
                IamException.class,
                () -> validator.requireScope(jwtSupport.token(jwtSupport.validClaims().build()), "order.admin"));
        assertEquals(IamErrorCode.INSUFFICIENT_SCOPE, ex.getErrorCode());
    }

    @Test
    void missingRole() {
        IamException ex = assertThrows(
                IamException.class,
                () -> validator.requireRole(jwtSupport.token(jwtSupport.validClaims().build()), "order_admin"));
        assertEquals(IamErrorCode.INSUFFICIENT_ROLE, ex.getErrorCode());
    }

    @Test
    void revokedJti() {
        JWTClaimsSet claims = jwtSupport.validClaims().jwtID("revoked-jti").build();
        revoked.add("revoked-jti");
        IamException ex = assertThrows(IamException.class, () -> validator.validate(jwtSupport.token(claims)));
        assertEquals(IamErrorCode.TOKEN_REVOKED, ex.getErrorCode());
    }
}
