package com.example.iam.authorizationserver.oauth.introspect;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.token.entity.IamRefreshTokenEntity;
import com.example.iam.token.oauth.JtiRevocationService;
import com.example.iam.token.oauth.RefreshTokenFamilyService;
import com.example.iam.token.oauth.RefreshTokenServiceImpl;
import com.example.iam.token.signing.JwtSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class TokenIntrospectionServiceTest {

    private static final Instant NOW = Instant.parse("2026-09-10T06:00:00Z");

    @Mock
    private JwtSigner jwtSigner;

    @Mock
    private JtiRevocationService jtiRevocationService;

    @Mock
    private RefreshTokenFamilyService refreshTokenFamilyService;

    private TokenIntrospectionServiceImpl service;

    @BeforeEach
    void setUp() {
        service = new TokenIntrospectionServiceImpl(
                jwtSigner, jtiRevocationService, refreshTokenFamilyService, Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    void introspectionActive() throws Exception {
        SignedJWT jwt = signed(activeClaims().build());
        when(jwtSigner.verify("at")).thenReturn(jwt);
        when(jtiRevocationService.isRevoked("jti-active")).thenReturn(false);
        TokenIntrospectionResponse response = service.introspect("at");
        assertTrue(response.active());
        assertEquals("user-1", response.sub());
        assertEquals(List.of("system-1"), response.aud());
        assertEquals("jti-active", response.jti());
    }

    @Test
    void introspectionRevoked() throws Exception {
        SignedJWT jwt = signed(activeClaims().build());
        when(jwtSigner.verify("at")).thenReturn(jwt);
        when(jtiRevocationService.isRevoked("jti-active")).thenReturn(true);
        assertFalse(service.introspect("at").active());
    }

    @Test
    void introspectionExpired() throws Exception {
        JWTClaimsSet claims = activeClaims().expirationTime(Date.from(NOW.minusSeconds(1))).build();
        SignedJWT jwt = signed(claims);
        when(jwtSigner.verify("at")).thenReturn(jwt);
        assertFalse(service.introspect("at").active());
    }

    @Test
    void introspectionServiceUnavailableFailsClosed() throws Exception {
        SignedJWT jwt = signed(activeClaims().build());
        when(jwtSigner.verify("at")).thenReturn(jwt);
        when(jtiRevocationService.isRevoked("jti-active"))
                .thenThrow(new IamException(IamErrorCode.INTROSPECTION_UNAVAILABLE, "redis down"));
        IamException ex = assertThrows(IamException.class, () -> service.introspect("at"));
        assertEquals(IamErrorCode.INTROSPECTION_UNAVAILABLE, ex.getErrorCode());
    }

    @Test
    void revokedRefreshTokenIsInactive() {
        when(jwtSigner.verify("rt")).thenThrow(new IamException(IamErrorCode.INVALID_JWT, "not jwt"));
        IamRefreshTokenEntity entity = IamRefreshTokenEntity.builder()
                .subjectId(UUID.randomUUID())
                .status(RefreshTokenServiceImpl.STATUS_REVOKED)
                .expiresAt(NOW.plusSeconds(60))
                .issuedAt(NOW)
                .scope("openid")
                .audience("system-1")
                .build();
        when(refreshTokenFamilyService.findByPresentedToken("rt")).thenReturn(Optional.of(entity));
        assertFalse(service.introspect("rt").active());
    }

    private static SignedJWT signed(JWTClaimsSet claims) throws Exception {
        SignedJWT jwt = mock(SignedJWT.class);
        when(jwt.getJWTClaimsSet()).thenReturn(claims);
        return jwt;
    }

    private static JWTClaimsSet.Builder activeClaims() {
        return new JWTClaimsSet.Builder()
                .subject("user-1")
                .audience("system-1")
                .jwtID("jti-active")
                .issueTime(Date.from(NOW.minusSeconds(10)))
                .expirationTime(Date.from(NOW.plusSeconds(600)))
                .claim("client_id", "portal")
                .claim("scope", "openid");
    }
}
