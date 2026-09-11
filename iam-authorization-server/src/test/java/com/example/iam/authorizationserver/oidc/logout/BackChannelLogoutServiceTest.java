package com.example.iam.authorizationserver.oidc.logout;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.iam.clientregistry.domain.RedirectUriType;
import com.example.iam.clientregistry.entity.IamClientEntity;
import com.example.iam.clientregistry.entity.IamClientRedirectUriEntity;
import com.example.iam.clientregistry.repository.IamClientRedirectUriRepository;
import com.example.iam.clientregistry.repository.IamClientRepository;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.session.IamSessionService;
import com.example.iam.token.oauth.JtiRevocationService;
import com.example.iam.token.oauth.RefreshTokenFamilyService;
import com.example.iam.token.signing.JwtSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class BackChannelLogoutServiceTest {

    private static final Instant NOW = Instant.parse("2026-09-10T06:00:00Z");
    private static final String ISSUER = "https://auth.example.com";
    private static final String SUBJECT = "01999a2e-7c3a-7000-8000-000000000001";
    private static final String SID = "sid-1";

    @Mock
    private JwtSigner jwtSigner;

    @Mock
    private IamClientRedirectUriRepository redirectUriRepository;

    @Mock
    private IamClientRepository clientRepository;

    @Mock
    private BackChannelLogoutClient backChannelLogoutClient;

    @Mock
    private JtiRevocationService jtiRevocationService;

    @Mock
    private IamSessionService sessionService;

    @Mock
    private RefreshTokenFamilyService refreshTokenFamilyService;

    private BackChannelLogoutServiceImpl service;

    @BeforeEach
    void setUp() {
        service = new BackChannelLogoutServiceImpl(
                jwtSigner,
                ISSUER,
                redirectUriRepository,
                clientRepository,
                backChannelLogoutClient,
                jtiRevocationService,
                sessionService,
                refreshTokenFamilyService,
                Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    void notifyClientsPostsLogoutToken() {
        UUID clientPk = UUID.randomUUID();
        IamClientRedirectUriEntity uri = IamClientRedirectUriEntity.builder()
                .clientId(clientPk)
                .redirectUri("https://system1.example.com/oidc/backchannel-logout")
                .uriType(RedirectUriType.LOGOUT_CALLBACK)
                .status("ACTIVE")
                .build();
        IamClientEntity client = new IamClientEntity();
        client.setId(clientPk);
        client.setClientId("system-1");
        when(redirectUriRepository.findByUriType(RedirectUriType.LOGOUT_CALLBACK)).thenReturn(List.of(uri));
        when(clientRepository.findById(clientPk)).thenReturn(Optional.of(client));
        SignedJWT signed = mock(SignedJWT.class);
        when(signed.serialize()).thenReturn("logout.jwt");
        when(jwtSigner.sign(any(), eq(BackChannelLogoutServiceImpl.LOGOUT_JWT))).thenReturn(signed);
        service.notifyClients(SUBJECT, SID);
        verify(backChannelLogoutClient)
                .postLogoutToken("https://system1.example.com/oidc/backchannel-logout", "logout.jwt");
    }

    @Test
    void backChannelCallbackAcceptsValidLogoutToken() throws Exception {
        SignedJWT jwt = signed(validClaims().build());
        when(jwtSigner.verify("valid")).thenReturn(jwt);
        when(jtiRevocationService.isRevoked("lt-1")).thenReturn(false);
        service.consumeLogoutToken("valid");
        verify(sessionService).delete(SID);
        verify(refreshTokenFamilyService).revokeAllForSubject(UUID.fromString(SUBJECT));
        verify(jtiRevocationService).revoke(eq("lt-1"), any());
    }

    @Test
    void invalidLogoutTokenIsRejected() {
        when(jwtSigner.verify("bad")).thenThrow(new IamException(IamErrorCode.INVALID_JWT_SIGNATURE, "bad sig"));
        IamException ex = assertThrows(IamException.class, () -> service.consumeLogoutToken("bad"));
        assertEquals(IamErrorCode.INVALID_LOGOUT_TOKEN, ex.getErrorCode());
    }

    @Test
    void logoutTokenMissingEventsIsRejected() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject(SUBJECT)
                .jwtID("lt-2")
                .expirationTime(Date.from(NOW.plusSeconds(60)))
                .build();
        SignedJWT jwt = signed(claims);
        when(jwtSigner.verify("no-events")).thenReturn(jwt);
        IamException ex = assertThrows(IamException.class, () -> service.consumeLogoutToken("no-events"));
        assertEquals(IamErrorCode.INVALID_LOGOUT_TOKEN, ex.getErrorCode());
    }

    private static SignedJWT signed(JWTClaimsSet claims) throws Exception {
        SignedJWT jwt = mock(SignedJWT.class);
        when(jwt.getJWTClaimsSet()).thenReturn(claims);
        return jwt;
    }

    private static JWTClaimsSet.Builder validClaims() {
        return new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject(SUBJECT)
                .audience("system-1")
                .jwtID("lt-1")
                .expirationTime(Date.from(NOW.plusSeconds(60)))
                .claim("sid", SID)
                .claim("events", Map.of(BackChannelLogoutServiceImpl.EVENT_TYPE, Map.of()));
    }
}
