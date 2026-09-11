package com.example.iam.policy;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

import com.example.iam.clientregistry.domain.GrantType;
import com.example.iam.clientregistry.domain.RedirectUriType;
import com.example.iam.clientregistry.domain.RegistryStatus;
import com.example.iam.clientregistry.entity.IamClientEntity;
import com.example.iam.clientregistry.entity.IamClientRedirectUriEntity;
import com.example.iam.clientregistry.entity.IamClientResourcePermissionEntity;
import com.example.iam.clientregistry.entity.IamResourceServerEntity;
import com.example.iam.clientregistry.entity.IamScopeEntity;
import com.example.iam.clientregistry.repository.IamClientRedirectUriRepository;
import com.example.iam.clientregistry.repository.IamClientRepository;
import com.example.iam.clientregistry.repository.IamClientResourcePermissionRepository;
import com.example.iam.clientregistry.repository.IamResourceServerRepository;
import com.example.iam.clientregistry.repository.IamScopeRepository;
import com.example.iam.clientregistry.validation.IamClientValidator;
import com.example.iam.clientregistry.validation.IamOriginValidator;
import com.example.iam.clientregistry.validation.IamRedirectUriValidator;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class IamPolicyEvaluatorTest {

    private static final String CLIENT_ID = "system-1";
    private static final String AUDIENCE = "system-n-api";
    private static final String SCOPE = "order.read";
    private static final String REDIRECT = "https://system1.example.com/login/oauth2/code/iam";

    @Mock
    private IamClientRepository clientRepository;

    @Mock
    private IamClientRedirectUriRepository redirectUriRepository;

    @Mock
    private IamResourceServerRepository resourceRepository;

    @Mock
    private IamScopeRepository scopeRepository;

    @Mock
    private IamClientResourcePermissionRepository permissionRepository;

    private IamPolicyEvaluator evaluator;
    private IamClientEntity client;
    private IamResourceServerEntity resource;
    private IamScopeEntity scope;

    @BeforeEach
    void setUp() {
        evaluator = new IamPolicyEvaluator(
                clientRepository,
                redirectUriRepository,
                resourceRepository,
                scopeRepository,
                permissionRepository,
                new IamClientValidator(),
                new IamRedirectUriValidator(),
                new IamOriginValidator());
        client = IamClientEntity.builder()
                .id(UUID.randomUUID())
                .clientId(CLIENT_ID)
                .clientName("System 1")
                .clientType("confidential")
                .status(RegistryStatus.ACTIVE)
                .tokenEndpointAuthMethod("client_secret_basic")
                .accessTokenTtl(600)
                .refreshTokenTtl(86400)
                .pkceRequired(true)
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .build();
        resource = IamResourceServerEntity.builder()
                .id(UUID.randomUUID())
                .resourceCode("SYSTEM_N")
                .resourceName("System N")
                .audience(AUDIENCE)
                .status(RegistryStatus.ACTIVE)
                .createdAt(Instant.now())
                .build();
        scope = IamScopeEntity.builder()
                .id(UUID.randomUUID())
                .resourceId(resource.getId())
                .scopeCode(SCOPE)
                .scopeName("Order Read")
                .status(RegistryStatus.ACTIVE)
                .build();
    }

    @Test
    void clientIdDoesNotExist() {
        when(clientRepository.findByClientId(CLIENT_ID)).thenReturn(Optional.empty());
        IamException ex = assertThrows(IamException.class, () -> evaluator.validateClient(CLIENT_ID));
        assertEquals(IamErrorCode.CLIENT_NOT_FOUND, ex.getErrorCode());
    }

    @Test
    void clientDisabled() {
        client.setStatus(RegistryStatus.INACTIVE);
        when(clientRepository.findByClientId(CLIENT_ID)).thenReturn(Optional.of(client));
        IamException ex = assertThrows(IamException.class, () -> evaluator.validateClient(CLIENT_ID));
        assertEquals(IamErrorCode.CLIENT_INACTIVE, ex.getErrorCode());
    }

    @Test
    void redirectUriDoesNotMatch() {
        stubActiveClient();
        when(redirectUriRepository.findByClientId(client.getId())).thenReturn(List.of(loginUri(REDIRECT)));
        IamException ex = assertThrows(
                IamException.class,
                () -> evaluator.validateRedirectUri(CLIENT_ID, "https://evil.example.com/callback"));
        assertEquals(IamErrorCode.REDIRECT_URI_MISMATCH, ex.getErrorCode());
    }

    @Test
    void redirectUriExtraCharacterDoesNotMatch() {
        stubActiveClient();
        when(redirectUriRepository.findByClientId(client.getId())).thenReturn(List.of(loginUri(REDIRECT)));
        IamException ex = assertThrows(
                IamException.class, () -> evaluator.validateRedirectUri(CLIENT_ID, REDIRECT + "/"));
        assertEquals(IamErrorCode.REDIRECT_URI_MISMATCH, ex.getErrorCode());
    }

    @Test
    void scopeDoesNotExist() {
        stubAudience();
        when(scopeRepository.findByResourceIdAndScopeCode(resource.getId(), "missing")).thenReturn(Optional.empty());
        when(scopeRepository.findByScopeCode("missing")).thenReturn(List.of());
        IamException ex = assertThrows(IamException.class, () -> evaluator.validateScope(AUDIENCE, "missing"));
        assertEquals(IamErrorCode.SCOPE_NOT_FOUND, ex.getErrorCode());
    }

    @Test
    void scopeNotBoundToResource() {
        stubAudience();
        when(scopeRepository.findByResourceIdAndScopeCode(resource.getId(), SCOPE)).thenReturn(Optional.empty());
        IamScopeEntity other = IamScopeEntity.builder()
                .id(UUID.randomUUID())
                .resourceId(UUID.randomUUID())
                .scopeCode(SCOPE)
                .scopeName("Order Read")
                .status(RegistryStatus.ACTIVE)
                .build();
        when(scopeRepository.findByScopeCode(SCOPE)).thenReturn(List.of(other));
        IamException ex = assertThrows(IamException.class, () -> evaluator.validateScope(AUDIENCE, SCOPE));
        assertEquals(IamErrorCode.SCOPE_NOT_BOUND, ex.getErrorCode());
    }

    @Test
    void inactiveScopeIsRejected() {
        stubAudience();
        scope.setStatus(RegistryStatus.INACTIVE);
        when(scopeRepository.findByResourceIdAndScopeCode(resource.getId(), SCOPE)).thenReturn(Optional.of(scope));
        IamException ex = assertThrows(IamException.class, () -> evaluator.validateScope(AUDIENCE, SCOPE));
        assertEquals(IamErrorCode.SCOPE_INACTIVE, ex.getErrorCode());
    }

    @Test
    void wildcardOriginIsRejected() {
        IamException ex = assertThrows(
                IamException.class,
                () -> evaluator.validateOrigin("*", List.of("https://portal.example.com")));
        assertEquals(IamErrorCode.INVALID_ORIGIN, ex.getErrorCode());
    }

    @Test
    void clientHasNoResourcePermission() {
        stubClientAudienceAndScope();
        when(permissionRepository.findByClientIdAndResourceId(client.getId(), resource.getId())).thenReturn(List.of());
        IamException ex = assertThrows(
                IamException.class,
                () -> evaluator.validateTokenExchangePermission(CLIENT_ID, AUDIENCE, SCOPE));
        assertEquals(IamErrorCode.PERMISSION_DENIED, ex.getErrorCode());
    }

    @Test
    void tokenExchangeNotAuthorized() {
        stubClientAudienceAndScope();
        when(permissionRepository.findByClientIdAndResourceId(client.getId(), resource.getId()))
                .thenReturn(List.of(permission(GrantType.AUTHORIZATION_CODE)));
        IamException ex = assertThrows(
                IamException.class,
                () -> evaluator.validateTokenExchangePermission(CLIENT_ID, AUDIENCE, SCOPE));
        assertEquals(IamErrorCode.TOKEN_EXCHANGE_NOT_ALLOWED, ex.getErrorCode());
    }

    @Test
    void clientCredentialsNotAuthorized() {
        stubClientAudienceAndScope();
        when(permissionRepository.findByClientIdAndResourceId(client.getId(), resource.getId()))
                .thenReturn(List.of(permission(GrantType.TOKEN_EXCHANGE)));
        IamException ex = assertThrows(
                IamException.class,
                () -> evaluator.validateClientCredentialsPermission(CLIENT_ID, AUDIENCE, SCOPE));
        assertEquals(IamErrorCode.CLIENT_CREDENTIALS_NOT_ALLOWED, ex.getErrorCode());
    }

    @Test
    void happyPathAllowsExactRedirectAndTokenExchange() {
        stubActiveClient();
        when(redirectUriRepository.findByClientId(client.getId())).thenReturn(List.of(loginUri(REDIRECT)));
        stubAudience();
        when(scopeRepository.findByResourceIdAndScopeCode(resource.getId(), SCOPE)).thenReturn(Optional.of(scope));
        when(permissionRepository.findByClientIdAndResourceId(client.getId(), resource.getId()))
                .thenReturn(List.of(permission(GrantType.TOKEN_EXCHANGE), permission(GrantType.CLIENT_CREDENTIALS)));

        assertDoesNotThrow(() -> evaluator.validateRedirectUri(CLIENT_ID, REDIRECT));
        assertDoesNotThrow(() -> evaluator.validateTokenExchangePermission(CLIENT_ID, AUDIENCE, SCOPE));
        assertDoesNotThrow(() -> evaluator.validateClientCredentialsPermission(CLIENT_ID, AUDIENCE, SCOPE));
        assertEquals(client.getId(), evaluator.validateClient(CLIENT_ID).getId());
        assertEquals(resource.getId(), evaluator.validateAudience(AUDIENCE).getId());
        assertEquals(scope.getId(), evaluator.validateScope(AUDIENCE, SCOPE).getId());
    }

    @Test
    void authorizationCodeScopeRequiresMatchingGrant() {
        stubActiveClient();
        when(scopeRepository.findByScopeCode(SCOPE)).thenReturn(List.of(scope));
        when(resourceRepository.findById(resource.getId())).thenReturn(Optional.of(resource));
        when(permissionRepository.findByClientIdAndResourceId(client.getId(), resource.getId()))
                .thenReturn(List.of(permission(GrantType.TOKEN_EXCHANGE)));
        IamException ex = assertThrows(
                IamException.class,
                () -> evaluator.validateAuthorizationCodeScopes(CLIENT_ID, List.of(SCOPE)));
        assertEquals(IamErrorCode.PERMISSION_DENIED, ex.getErrorCode());
    }

    private void stubActiveClient() {
        when(clientRepository.findByClientId(CLIENT_ID)).thenReturn(Optional.of(client));
    }

    private void stubAudience() {
        when(resourceRepository.findByAudience(AUDIENCE)).thenReturn(Optional.of(resource));
    }

    private void stubClientAudienceAndScope() {
        stubActiveClient();
        stubAudience();
        when(scopeRepository.findByResourceIdAndScopeCode(resource.getId(), SCOPE)).thenReturn(Optional.of(scope));
    }

    private IamClientRedirectUriEntity loginUri(String uri) {
        return IamClientRedirectUriEntity.builder()
                .id(UUID.randomUUID())
                .clientId(client.getId())
                .redirectUri(uri)
                .uriType(RedirectUriType.LOGIN_CALLBACK)
                .status(RegistryStatus.ACTIVE)
                .build();
    }

    private IamClientResourcePermissionEntity permission(GrantType grantType) {
        return IamClientResourcePermissionEntity.builder()
                .id(UUID.randomUUID())
                .clientId(client.getId())
                .resourceId(resource.getId())
                .scopeId(scope.getId())
                .grantType(grantType.name())
                .status(RegistryStatus.ACTIVE)
                .createdAt(Instant.now())
                .build();
    }
}
