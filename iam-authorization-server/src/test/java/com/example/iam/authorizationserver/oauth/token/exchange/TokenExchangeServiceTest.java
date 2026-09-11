package com.example.iam.authorizationserver.oauth.token.exchange;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.iam.authorizationserver.oauth.token.TokenResponse;
import com.example.iam.clientregistry.entity.IamClientEntity;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.policy.TokenExchangePolicyService;
import com.example.iam.token.oauth.AccessTokenClaims;
import com.example.iam.token.oauth.AccessTokenService;
import com.example.iam.user.service.IamUserService;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class TokenExchangeServiceTest {

    private static final String GRANT = TokenExchangeServiceImpl.GRANT;
    private static final String ACCESS = SubjectTokenValidator.ACCESS_TOKEN_TYPE;
    private static final String SUBJECT_TOKEN = "subject-token-a";
    private static final String ACTOR_TOKEN = "actor-token";

    @Mock
    private SubjectTokenValidator subjectTokenValidator;

    @Mock
    private ActorTokenValidator actorTokenValidator;

    @Mock
    private TokenExchangePolicyService policyService;

    @Mock
    private AccessTokenService accessTokenService;

    @Mock
    private IamUserService userService;

    private TokenExchangeServiceImpl service;
    private IamClientEntity client;
    private DelegationContext subject;

    @BeforeEach
    void setUp() {
        service = new TokenExchangeServiceImpl(
                subjectTokenValidator,
                actorTokenValidator,
                policyService,
                accessTokenService,
                userService,
                org.mockito.Mockito.mock(com.example.iam.audit.IamAuditService.class));
        client = IamClientEntity.builder().clientId("system-1").accessTokenTtl(600).build();
        subject = new DelegationContext(
                "u_100086",
                List.of("system-1-api"),
                List.of("openid"),
                "system-1",
                "tenant-1",
                "org-1",
                List.of(),
                "jti-original");
    }

    @Test
    void validExchangeIssuesNewTokenForRequestedAudience() {
        when(subjectTokenValidator.validate(SUBJECT_TOKEN, ACCESS)).thenReturn(subject);
        when(accessTokenService.issue(any())).thenReturn("token-b");
        TokenResponse response = service.exchange(request("system-n-api", "order.read", null, null), client);
        ArgumentCaptor<AccessTokenClaims> captor = ArgumentCaptor.forClass(AccessTokenClaims.class);
        verify(accessTokenService).issue(captor.capture());
        AccessTokenClaims claims = captor.getValue();
        assertEquals("u_100086", claims.subject());
        assertEquals(List.of("system-n-api"), claims.audiences());
        assertEquals("system-1", claims.clientId());
        assertEquals("order.read", claims.scope());
        assertNull(claims.jti());
        assertNull(claims.actSub());
        assertEquals("token-b", response.accessToken());
        assertEquals(ACCESS, response.issuedTokenType());
        assertNotEquals(SUBJECT_TOKEN, response.accessToken());
        assertNotEquals("jti-original", claims.jti());
    }

    @Test
    void newJtiAndNewSignatureAreForced() {
        when(subjectTokenValidator.validate(SUBJECT_TOKEN, ACCESS)).thenReturn(subject);
        when(accessTokenService.issue(any())).thenReturn("re-signed-token");
        TokenResponse response = service.exchange(request("system-n-api", "order.read", null, null), client);
        ArgumentCaptor<AccessTokenClaims> captor = ArgumentCaptor.forClass(AccessTokenClaims.class);
        verify(accessTokenService).issue(captor.capture());
        assertNull(captor.getValue().jti());
        assertNotEquals(SUBJECT_TOKEN, response.accessToken());
        assertNotEquals(List.of("system-1-api"), captor.getValue().audiences());
    }

    @Test
    void invalidSubjectToken() {
        when(subjectTokenValidator.validate(SUBJECT_TOKEN, ACCESS))
                .thenThrow(new IamException(IamErrorCode.INVALID_JWT, "malformed"));
        IamException ex = assertThrows(
                IamException.class, () -> service.exchange(request("system-n-api", "order.read", null, null), client));
        assertEquals(IamErrorCode.INVALID_JWT, ex.getErrorCode());
        verify(accessTokenService, never()).issue(any());
    }

    @Test
    void expiredSubjectToken() {
        when(subjectTokenValidator.validate(SUBJECT_TOKEN, ACCESS))
                .thenThrow(new IamException(IamErrorCode.JWT_EXPIRED, "expired"));
        IamException ex = assertThrows(
                IamException.class, () -> service.exchange(request("system-n-api", "order.read", null, null), client));
        assertEquals(IamErrorCode.JWT_EXPIRED, ex.getErrorCode());
    }

    @Test
    void wrongIssuer() {
        when(subjectTokenValidator.validate(SUBJECT_TOKEN, ACCESS))
                .thenThrow(new IamException(IamErrorCode.INVALID_JWT_ISSUER, "iss"));
        IamException ex = assertThrows(
                IamException.class, () -> service.exchange(request("system-n-api", "order.read", null, null), client));
        assertEquals(IamErrorCode.INVALID_JWT_ISSUER, ex.getErrorCode());
    }

    @Test
    void wrongAudience() {
        when(subjectTokenValidator.validate(SUBJECT_TOKEN, ACCESS))
                .thenThrow(new IamException(IamErrorCode.INVALID_JWT_AUDIENCE, "aud"));
        IamException ex = assertThrows(
                IamException.class, () -> service.exchange(request("system-n-api", "order.read", null, null), client));
        assertEquals(IamErrorCode.INVALID_JWT_AUDIENCE, ex.getErrorCode());
    }

    @Test
    void clientUnauthorized() {
        when(subjectTokenValidator.validate(SUBJECT_TOKEN, ACCESS)).thenReturn(subject);
        doThrow(new IamException(IamErrorCode.TOKEN_EXCHANGE_NOT_ALLOWED, "client"))
                .when(policyService)
                .requireExchangePermission("system-1", "system-n-api", List.of("order.read"));
        IamException ex = assertThrows(
                IamException.class, () -> service.exchange(request("system-n-api", "order.read", null, null), client));
        assertEquals(IamErrorCode.TOKEN_EXCHANGE_NOT_ALLOWED, ex.getErrorCode());
        verify(accessTokenService, never()).issue(any());
    }

    @Test
    void resourceUnauthorized() {
        when(subjectTokenValidator.validate(SUBJECT_TOKEN, ACCESS)).thenReturn(subject);
        doThrow(new IamException(IamErrorCode.PERMISSION_DENIED, "resource"))
                .when(policyService)
                .requireExchangePermission("system-1", "system-n-api", List.of("order.read"));
        IamException ex = assertThrows(
                IamException.class, () -> service.exchange(request("system-n-api", "order.read", null, null), client));
        assertEquals(IamErrorCode.PERMISSION_DENIED, ex.getErrorCode());
    }

    @Test
    void scopeUnauthorized() {
        when(subjectTokenValidator.validate(SUBJECT_TOKEN, ACCESS)).thenReturn(subject);
        doThrow(new IamException(IamErrorCode.TOKEN_EXCHANGE_NOT_ALLOWED, "scope"))
                .when(policyService)
                .requireExchangePermission("system-1", "system-n-api", List.of("order.write"));
        IamException ex = assertThrows(
                IamException.class, () -> service.exchange(request("system-n-api", "order.write", null, null), client));
        assertEquals(IamErrorCode.TOKEN_EXCHANGE_NOT_ALLOWED, ex.getErrorCode());
    }

    @Test
    void invalidActor() {
        when(subjectTokenValidator.validate(SUBJECT_TOKEN, ACCESS)).thenReturn(subject);
        when(actorTokenValidator.validate(ACTOR_TOKEN, ACCESS))
                .thenThrow(new IamException(IamErrorCode.INVALID_ACTOR, "bad actor"));
        IamException ex = assertThrows(
                IamException.class,
                () -> service.exchange(request("system-n-api", "order.read", ACTOR_TOKEN, ACCESS), client));
        assertEquals(IamErrorCode.INVALID_ACTOR, ex.getErrorCode());
        verify(accessTokenService, never()).issue(any());
    }

    @Test
    void actorUnauthorized() {
        when(subjectTokenValidator.validate(SUBJECT_TOKEN, ACCESS)).thenReturn(subject);
        when(actorTokenValidator.validate(ACTOR_TOKEN, ACCESS)).thenReturn(new ActorContext("actor-1", "other-client"));
        doThrow(new IamException(IamErrorCode.ACTOR_UNAUTHORIZED, "actor"))
                .when(policyService)
                .requireActorAuthorized("other-client", "system-1");
        IamException ex = assertThrows(
                IamException.class,
                () -> service.exchange(request("system-n-api", "order.read", ACTOR_TOKEN, ACCESS), client));
        assertEquals(IamErrorCode.ACTOR_UNAUTHORIZED, ex.getErrorCode());
    }

    @Test
    void requestedAudienceInvalid() {
        doThrow(new IamException(IamErrorCode.AUDIENCE_NOT_FOUND, "missing"))
                .when(policyService)
                .requireRequestedAudience("missing-api");
        IamException ex = assertThrows(
                IamException.class, () -> service.exchange(request("missing-api", "order.read", null, null), client));
        assertEquals(IamErrorCode.AUDIENCE_NOT_FOUND, ex.getErrorCode());
        verify(subjectTokenValidator, never()).validate(any(), any());
    }

    @Test
    void actorClaimIsCopiedOntoIssuedToken() {
        when(subjectTokenValidator.validate(SUBJECT_TOKEN, ACCESS)).thenReturn(subject);
        when(actorTokenValidator.validate(ACTOR_TOKEN, ACCESS)).thenReturn(new ActorContext("caller", "system-1"));
        when(accessTokenService.issue(any())).thenReturn("token-b");
        service.exchange(request("system-n-api", "order.read", ACTOR_TOKEN, ACCESS), client);
        ArgumentCaptor<AccessTokenClaims> captor = ArgumentCaptor.forClass(AccessTokenClaims.class);
        verify(accessTokenService).issue(captor.capture());
        assertEquals("caller", captor.getValue().actSub());
        verify(policyService).requireActorAuthorized(eq("system-1"), eq("system-1"));
    }

    private static TokenExchangeRequest request(
            String audience, String scope, String actorToken, String actorTokenType) {
        return new TokenExchangeRequest(
                GRANT, SUBJECT_TOKEN, ACCESS, ACCESS, audience, scope, actorToken, actorTokenType);
    }
}
