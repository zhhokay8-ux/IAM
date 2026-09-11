package com.example.iam.authorizationserver.oauth.revoke;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.token.oauth.JtiRevocationService;
import com.example.iam.token.oauth.RefreshTokenFamilyService;
import com.example.iam.token.signing.JwtSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class TokenRevocationServiceTest {

    private static final Instant NOW = Instant.parse("2026-09-10T06:00:00Z");

    @Mock
    private JwtSigner jwtSigner;

    @Mock
    private JtiRevocationService jtiRevocationService;

    @Mock
    private RefreshTokenFamilyService refreshTokenFamilyService;

    private TokenRevocationServiceImpl service;

    @BeforeEach
    void setUp() {
        service = new TokenRevocationServiceImpl(
                jwtSigner,
                jtiRevocationService,
                refreshTokenFamilyService,
                org.mockito.Mockito.mock(com.example.iam.audit.IamAuditService.class),
                Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    void refreshRevokeRevokesFamily() {
        when(refreshTokenFamilyService.revokePresentedToken("rt-1")).thenReturn(true);
        service.revoke("rt-1", "refresh_token");
        verify(refreshTokenFamilyService).revokePresentedToken("rt-1");
        verify(jtiRevocationService, never()).revoke(any(), any());
    }

    @Test
    void jtiRevokeRevokesAccessToken() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .jwtID("jti-1")
                .expirationTime(Date.from(NOW.plusSeconds(600)))
                .build();
        SignedJWT jwt = mock(SignedJWT.class);
        when(jwt.getJWTClaimsSet()).thenReturn(claims);
        when(jwtSigner.verify("at-1")).thenReturn(jwt);
        service.revoke("at-1", "access_token");
        verify(jtiRevocationService).revoke(eq("jti-1"), eq(Duration.ofSeconds(600)));
        verify(refreshTokenFamilyService, never()).revokePresentedToken(any());
    }

    @Test
    void unknownTokenIsIgnored() {
        when(jwtSigner.verify("unknown")).thenThrow(new IamException(IamErrorCode.INVALID_JWT, "bad"));
        when(refreshTokenFamilyService.revokePresentedToken("unknown")).thenReturn(false);
        assertDoesNotThrow(() -> service.revoke("unknown", null));
    }
}
