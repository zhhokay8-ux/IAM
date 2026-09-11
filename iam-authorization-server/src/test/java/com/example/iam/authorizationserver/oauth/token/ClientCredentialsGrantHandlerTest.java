package com.example.iam.authorizationserver.oauth.token;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.iam.clientregistry.domain.GrantType;
import com.example.iam.clientregistry.domain.RegistryStatus;
import com.example.iam.clientregistry.entity.IamClientEntity;
import com.example.iam.clientregistry.repository.IamClientRepository;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.common.util.HashUtils;
import com.example.iam.policy.IamPolicyEvaluator;
import com.example.iam.token.oauth.AccessTokenClaims;
import com.example.iam.token.oauth.AccessTokenService;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class ClientCredentialsGrantHandlerTest {

    @Nested
    class Authentication {
        @Mock
        private IamClientRepository clientRepository;

        private ClientAuthenticationProvider provider;
        private IamClientEntity active;

        @BeforeEach
        void setUp() {
            provider = new ClientAuthenticationProvider(clientRepository);
            active = client("system-1", RegistryStatus.ACTIVE, HashUtils.sha256Hex("secret"));
        }

        @Test
        void invalidSecret() {
            when(clientRepository.findByClientId("system-1")).thenReturn(Optional.of(active));
            IamException ex = assertThrows(IamException.class, () -> provider.authenticate("system-1", "wrong"));
            assertEquals(IamErrorCode.INVALID_CLIENT, ex.getErrorCode());
        }

        @Test
        void disabledClient() {
            when(clientRepository.findByClientId("system-1"))
                    .thenReturn(Optional.of(client("system-1", RegistryStatus.INACTIVE, HashUtils.sha256Hex("secret"))));
            IamException ex = assertThrows(IamException.class, () -> provider.authenticate("system-1", "secret"));
            assertEquals(IamErrorCode.CLIENT_INACTIVE, ex.getErrorCode());
        }

        @Test
        void validConfidentialClient() {
            when(clientRepository.findByClientId("system-1")).thenReturn(Optional.of(active));
            assertEquals("system-1", provider.authenticateConfidential("system-1", "secret").getClientId());
        }
    }

    @Nested
    class Grant {
        @Mock
        private IamPolicyEvaluator policyEvaluator;

        @Mock
        private ServiceTokenService serviceTokenService;

        private ClientCredentialsGrantHandler handler;
        private IamClientEntity client;

        @BeforeEach
        void setUp() {
            handler = new ClientCredentialsGrantHandler(policyEvaluator, serviceTokenService);
            client = client("system-1", RegistryStatus.ACTIVE, "hash");
        }

        @Test
        void valid() {
            when(serviceTokenService.issue(client, List.of("system-n-api"), "data.read")).thenReturn("service-jwt");
            TokenResponse response = handler.handle(request("data.read", "system-n-api"), client);
            assertEquals("service-jwt", response.accessToken());
            assertEquals("Bearer", response.tokenType());
            assertEquals("data.read", response.scope());
            assertNull(response.refreshToken());
            assertNull(response.idToken());
        }

        @Test
        void invalidScope() {
            org.mockito.Mockito.doThrow(new IamException(IamErrorCode.SCOPE_NOT_FOUND, "missing"))
                    .when(policyEvaluator)
                    .validateClientCredentialsPermission("system-1", "system-n-api", "nope");
            IamException ex = assertThrows(
                    IamException.class, () -> handler.handle(request("nope", "system-n-api"), client));
            assertEquals(IamErrorCode.PERMISSION_DENIED, ex.getErrorCode());
            verify(serviceTokenService, never()).issue(any(), any(), any());
        }

        @Test
        void unauthorizedAudience() {
            org.mockito.Mockito.doThrow(new IamException(IamErrorCode.PERMISSION_DENIED, "no access"))
                    .when(policyEvaluator)
                    .validateClientCredentialsPermission("system-1", "locked-api", "data.read");
            IamException ex = assertThrows(
                    IamException.class, () -> handler.handle(request("data.read", "locked-api"), client));
            assertEquals(IamErrorCode.PERMISSION_DENIED, ex.getErrorCode());
        }

        @Test
        void servicePrincipalIsNotAUserSubject() {
            when(serviceTokenService.issue(client, List.of("system-n-api"), "data.read")).thenReturn("service-jwt");
            handler.handle(request("data.read", "system-n-api"), client);
            assertEquals("client:system-1", ServiceTokenService.subjectFor("system-1"));
            assertTrue(ServiceTokenService.isServiceSubject("client:system-1"));
            assertFalse(ServiceTokenService.isServiceSubject("u_100086"));
        }

        @Test
        void publicClientIsRejected() {
            IamClientEntity pub = client("public-1", RegistryStatus.ACTIVE, null);
            pub.setClientType("public");
            IamException ex = assertThrows(
                    IamException.class, () -> handler.handle(request("data.read", "system-n-api"), pub));
            assertEquals(IamErrorCode.CLIENT_CREDENTIALS_NOT_ALLOWED, ex.getErrorCode());
        }

        @Test
        void audienceCanBeResolvedFromScope() {
            when(policyEvaluator.resolveAudiences("system-1", List.of("data.read"), GrantType.CLIENT_CREDENTIALS))
                    .thenReturn(List.of("system-n-api"));
            when(serviceTokenService.issue(client, List.of("system-n-api"), "data.read")).thenReturn("service-jwt");
            TokenResponse response = handler.handle(request("data.read", null), client);
            assertEquals("service-jwt", response.accessToken());
        }
    }

    @Nested
    class ServiceToken {
        @Mock
        private AccessTokenService accessTokenService;

        private ServiceTokenServiceImpl service;
        private IamClientEntity client;

        @BeforeEach
        void setUp() {
            service = new ServiceTokenServiceImpl(accessTokenService);
            client = client("system-1", RegistryStatus.ACTIVE, "hash");
            client.setAccessTokenTtl(600);
        }

        @Test
        void issuesServicePrincipalClaimsWithoutUserContext() {
            when(accessTokenService.issue(any())).thenReturn("jwt");
            service.issue(client, List.of("system-n-api"), "data.read");
            ArgumentCaptor<AccessTokenClaims> captor = ArgumentCaptor.forClass(AccessTokenClaims.class);
            verify(accessTokenService).issue(captor.capture());
            AccessTokenClaims claims = captor.getValue();
            assertEquals("client:system-1", claims.subject());
            assertEquals("system-1", claims.clientId());
            assertEquals(List.of("system-n-api"), claims.audiences());
            assertEquals("data.read", claims.scope());
            assertEquals(ServiceTokenService.TOKEN_USE, claims.tokenUse());
            assertTrue(claims.roles() == null || claims.roles().isEmpty());
            assertNull(claims.tenantId());
            assertNull(claims.orgId());
            assertNull(claims.actSub());
        }

        @Test
        void expiredTokenHasExpInThePastWhenIssuedInThePast() {
            Instant past = Instant.parse("2020-01-01T00:00:00Z");
            when(accessTokenService.issue(any())).thenReturn("jwt");
            service.issue(client, List.of("system-n-api"), "data.read", past);
            ArgumentCaptor<AccessTokenClaims> captor = ArgumentCaptor.forClass(AccessTokenClaims.class);
            verify(accessTokenService).issue(captor.capture());
            assertTrue(captor.getValue().expiresAt().isBefore(Instant.now()));
        }
    }

    private static TokenRequest request(String scope, String audience) {
        return new TokenRequest("client_credentials", null, null, null, null, scope, audience, "system-1", "secret");
    }

    private static IamClientEntity client(String clientId, String status, String secretHash) {
        return IamClientEntity.builder()
                .clientId(clientId)
                .clientName(clientId)
                .clientType("confidential")
                .status(status)
                .tokenEndpointAuthMethod("client_secret_basic")
                .accessTokenTtl(600)
                .refreshTokenTtl(86400)
                .clientSecretHash(secretHash)
                .build();
    }
}
